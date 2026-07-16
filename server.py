"""Tollbooth OAuth2 Collector — unauthenticated mailbox for OAuth2 authorization codes.

Receives authorization codes and holds them for retrieval by the
originating MCP server.  Solves Horizon's routing constraint: Horizon
only proxies ``/mcp/`` traffic (POST, MCP JSON-RPC) so browser GET
redirects from OAuth providers cannot reach custom_route endpoints.

Architecture
~~~~~~~~~~~~
* A lightweight **serverless HTTP function** (Val Town) receives the
  browser GET redirect from the OAuth provider and calls the collector's
  ``store_code`` MCP tool via JSON-RPC over ``/mcp/``.
* The originating MCP server calls ``retrieve_code`` (also an MCP tool)
  to pick up the encrypted code (one-time read, auto-deleted).

The serverless callback source lives in ``val/oauth_callback.js`` in
this repository.

Uses Neon's SQL-over-HTTP API via httpx — no asyncpg or C extensions.

DPYC Identity
~~~~~~~~~~~~~
This service is registered as an **Advocate** in the DPYC Honor Chain.
Peer MCP servers discover its URL via registry lookup
(``resolve_service_by_name("tollbooth-oauth2-collector")``).
The browser callback URL is registered separately as
``resolve_service_by_name("tollbooth-oauth2-callback")``.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

_TTL_SECONDS = 600  # 10 minutes

mcp = FastMCP(
    "Tollbooth OAuth2 Collector",
    instructions=(
        "Tollbooth OAuth2 Collector — unauthenticated mailbox for OAuth2 "
        "authorization codes. This is a community utility with no monetization.\n\n"
        "## How It Works\n\n"
        "1. An MCP server directs the user's browser to an OAuth provider, with "
        "`redirect_uri` pointing to the serverless callback function.\n"
        "2. After the user authorizes, the provider redirects the browser to the "
        "callback, which calls `store_code` on this collector via MCP.\n"
        "3. The originating MCP server calls `retrieve_code(state=...)` to pick "
        "up the encrypted code (one-time read, auto-deleted).\n\n"
        "## Tools\n\n"
        "- `store_code` — Store an encrypted authorization code (called by the "
        "serverless callback).\n"
        "- `retrieve_code` — Retrieve and delete a stored code (called by the "
        "originating MCP server).\n"
        "- `collector_status` — Health check showing pending code count and TTL.\n"
        "- `service_status` — Report the running build (incl. the deployed git "
        "sha) so a redeploy can be verified."
    ),
)

_SERVICE_NAME = "tollbooth-oauth2-collector"

# ---------------------------------------------------------------------------
# Neon SQL-over-HTTP helpers
# ---------------------------------------------------------------------------

_http_client: httpx.AsyncClient | None = None
_neon_endpoint: str | None = None
_schema_ensured = False


async def _get_client() -> httpx.AsyncClient:
    """Lazily create a persistent httpx client for Neon HTTP API."""
    global _http_client, _neon_endpoint, _schema_ensured

    if _http_client is None:
        database_url = os.environ.get("NEON_DATABASE_URL")
        if not database_url:
            raise RuntimeError("NEON_DATABASE_URL environment variable is required")

        parsed = urlparse(database_url)
        _neon_endpoint = f"https://{parsed.hostname}/sql"

        _http_client = httpx.AsyncClient(
            headers={
                "Neon-Connection-String": database_url,
                "Content-Type": "application/json",
            },
            timeout=30.0,
        )

    if not _schema_ensured:
        _schema_ensured = True  # Set before to prevent recursion via _execute
        await _ensure_schema()

    return _http_client


async def _execute(query: str, params: list[Any] | None = None) -> dict[str, Any]:
    """Execute a SQL statement via Neon's HTTP API."""
    client = await _get_client()
    body = {"query": query, "params": params or []}
    resp = await client.post(_neon_endpoint, json=body)
    resp.raise_for_status()
    data = resp.json()

    if isinstance(data, dict) and "message" in data and "rows" not in data:
        raise RuntimeError(f"Neon SQL error: {data['message']}")

    return data


async def _ensure_schema():
    """Create the oauth_codes table if it doesn't exist."""
    await _execute("""
        CREATE TABLE IF NOT EXISTS oauth_codes (
            state TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)


async def _cleanup_expired():
    """Remove expired rows (older than TTL)."""
    await _execute(
        f"DELETE FROM oauth_codes WHERE received_at < NOW() - INTERVAL '{_TTL_SECONDS} seconds'"
    )


# ---------------------------------------------------------------------------
# Code encryption — AES-256-GCM with random IV, keyed on SHA-256(state)
# ---------------------------------------------------------------------------


def _encrypt_code(code: str, state: str) -> str:
    """Encrypt an authorization code using AES-256-GCM.

    Delegates to the SDK's canonical ``encrypt_collector_code`` — the single
    source of this contract, whose peer ``decrypt_collector_code`` the
    originating MCP server uses. Keeping both halves in tollbooth-dpyc stops the
    collector and the servers from drifting apart on key derivation or framing.
    """
    from tollbooth.oauth2_collector import encrypt_collector_code
    return encrypt_collector_code(code, state)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def store_code(code: str, state: str) -> dict[str, Any]:
    """Store an encrypted OAuth2 authorization code.

    Called by the serverless callback function after the browser redirect.
    The code is encrypted with SHA-256(state) before storage.

    Args:
        code: The authorization code from the OAuth provider.
        state: The state token (patron npub) from the authorization request.

    Returns:
        Dict with ``success`` key and a message.
    """
    try:
        encrypted_code = _encrypt_code(code, state)
        await _cleanup_expired()
        await _execute(
            "INSERT INTO oauth_codes (state, code) VALUES ($1, $2) "
            "ON CONFLICT (state) DO UPDATE SET code = $2, received_at = NOW()",
            [state, encrypted_code],
        )
        logger.info("Stored encrypted OAuth code for state=%s", state[:16])
        return {"success": True, "message": "Code stored successfully."}
    except Exception as e:
        logger.exception("Failed to store OAuth code")
        return {"success": False, "error": str(e)}


@mcp.tool()
async def retrieve_code(state: str) -> dict[str, Any]:
    """Retrieve a stored authorization code (one-time read, auto-deleted).

    Called by the originating MCP server to pick up the code after the user
    has authorized in the browser. Returns the encrypted code which the
    caller decrypts using the same state token.

    Args:
        state: The state token (patron npub) used during authorization.

    Returns:
        Dict with ``code`` (encrypted) on success, or ``error`` if not found.
    """
    try:
        await _cleanup_expired()
        result = await _execute(
            "DELETE FROM oauth_codes WHERE state = $1 RETURNING code", [state]
        )

        rows = result.get("rows", [])
        if not rows:
            return {"found": False, "error": "not found or expired"}

        logger.info("Retrieved and deleted OAuth code for state=%s", state[:16])
        return {"found": True, "code": rows[0]["code"]}
    except Exception as e:
        logger.exception("Failed to retrieve OAuth code")
        return {"found": False, "error": str(e)}


@mcp.tool()
async def collector_status() -> dict[str, Any]:
    """Health check — shows the number of pending authorization codes and TTL."""
    try:
        await _cleanup_expired()
        result = await _execute("SELECT COUNT(*) AS cnt FROM oauth_codes")
        count = result["rows"][0]["cnt"] if result.get("rows") else 0
        return {"status": "healthy", "pending_codes": count, "ttl_seconds": _TTL_SECONDS}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


def _wheel_version(package: str) -> str:
    """Resolve an installed wheel's version, or ``"unknown"`` if unavailable."""
    try:
        import importlib.metadata
        return importlib.metadata.version(package)
    except Exception:
        return "unknown"


@mcp.tool()
async def service_status() -> dict[str, Any]:
    """Report the running build so a redeploy can be verified. Free.

    Delegates to the SDK's canonical ``build_service_status`` — the single
    source of the service_status payload shape — so this collector reports the
    same envelope as every other DPYC service. The load-bearing field is
    ``build_info.fastmcp_cloud_git_commit_sha``: the commit Horizon actually
    deployed. The post-merge deploy-verify probe reads it to confirm the live
    service redeployed the merged sha; with no ``service_status`` tool to probe,
    that sha reads as ``<none>`` and an otherwise-healthy deploy is flagged as
    "did not land".

    The vault/courier/operator fields are ``False``/empty by construction —
    this is an unauthenticated community utility with no operator runtime.
    """
    from tollbooth.tools.status import build_service_status

    return build_service_status(
        service=_SERVICE_NAME,
        slug=_SERVICE_NAME,
        version=_wheel_version(_SERVICE_NAME),
        tollbooth_version=_wheel_version("tollbooth-dpyc"),
        vault_ok=False,
        courier_ok=False,
        operator_npub=None,
        process_id=os.getpid(),
        env=os.environ,
    )
