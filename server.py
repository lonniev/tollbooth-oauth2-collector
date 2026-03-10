"""Tollbooth OAuth2 Collector — unauthenticated mailbox for OAuth2 authorization codes.

Receives authorization codes from browser redirects and holds them for retrieval
by the originating MCP server. Solves Horizon's auth-proxy problem: since
Horizon enforces Bearer auth on ALL HTTP routes (including custom_route), OAuth
providers cannot redirect browsers to an MCP server's callback endpoint.

This collector runs as a separate, unauthenticated FastMCP server that simply:
1. Captures auth codes from browser redirects (GET /oauth/callback)
2. Holds them briefly in Postgres (600s TTL)
3. Serves them once to the originating MCP server (GET /oauth/retrieve)

Uses Neon's SQL-over-HTTP API via httpx — no asyncpg or C extensions needed.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlparse

import httpx
from fastmcp import FastMCP

logger = logging.getLogger(__name__)

_TTL_SECONDS = 600  # 10 minutes — matches schwab-mcp _STATE_TTL_SECONDS

mcp = FastMCP(
    "Tollbooth OAuth2 Collector",
    instructions=(
        "Tollbooth OAuth2 Collector — unauthenticated mailbox for OAuth2 "
        "authorization codes. This is a community utility with no monetization.\n\n"
        "## How It Works\n\n"
        "1. An MCP server (e.g., schwab-mcp) directs the user's browser to an "
        "OAuth provider, with `redirect_uri` pointing to this collector.\n"
        "2. After the user authorizes, the provider redirects the browser here "
        "with `?code=...&state=...`.\n"
        "3. The originating MCP server polls `GET /oauth/retrieve?state=...` "
        "to pick up the code (one-time read, auto-deleted).\n\n"
        "## Tools\n\n"
        "- `collector_status` — Health check showing pending code count and TTL."
    ),
)

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
# HTTP Routes
# ---------------------------------------------------------------------------

_SUCCESS_HTML = (
    "<!DOCTYPE html><html><head><title>Authorization Code Received</title></head>"
    '<body style="font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;'
    'text-align:center">'
    "<h1>Authorization Code Received</h1>"
    "<p>You can close this tab and return to your MCP client.</p>"
    "</body></html>"
)

_ERROR_HTML = (
    "<!DOCTYPE html><html><head><title>Error</title></head>"
    '<body style="font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;'
    'text-align:center">'
    "<h1>Missing Parameters</h1>"
    "<p>Both <code>code</code> and <code>state</code> query parameters are required.</p>"
    "</body></html>"
)


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request):
    """Receive an OAuth2 authorization code from a browser redirect."""
    from starlette.responses import HTMLResponse

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    if not code or not state:
        return HTMLResponse(_ERROR_HTML, status_code=400)

    try:
        await _cleanup_expired()
        await _execute(
            "INSERT INTO oauth_codes (state, code) VALUES ($1, $2) "
            "ON CONFLICT (state) DO UPDATE SET code = $2, received_at = NOW()",
            [state, code],
        )
        logger.info("Stored OAuth code for state=%s", state[:16])
        return HTMLResponse(_SUCCESS_HTML)
    except Exception as e:
        logger.exception("Failed to store OAuth code")
        return HTMLResponse(
            f"<html><body><h1>Internal Error</h1><pre>{e}</pre></body></html>",
            status_code=500,
        )


@mcp.custom_route("/oauth/retrieve", methods=["GET"])
async def oauth_retrieve(request):
    """Retrieve a stored authorization code (one-time read)."""
    from starlette.responses import JSONResponse

    state = request.query_params.get("state")
    if not state:
        return JSONResponse({"error": "state parameter required"}, status_code=400)

    try:
        await _cleanup_expired()
        result = await _execute(
            "DELETE FROM oauth_codes WHERE state = $1 RETURNING code", [state]
        )

        rows = result.get("rows", [])
        if not rows:
            return JSONResponse({"error": "not found or expired"}, status_code=404)

        logger.info("Retrieved and deleted OAuth code for state=%s", state[:16])
        return JSONResponse({"code": rows[0]["code"]})
    except Exception as e:
        logger.exception("Failed to retrieve OAuth code")
        return JSONResponse({"error": f"internal error: {e}"}, status_code=500)


# ---------------------------------------------------------------------------
# MCP Tool
# ---------------------------------------------------------------------------


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
