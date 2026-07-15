"""Tests for tollbooth-oauth2-collector server.

Mocks Neon's SQL-over-HTTP API so no real Postgres is required. Targets the
current MCP-tool surface (`store_code`, `retrieve_code`, `collector_status`)
and the AES-256-GCM `_encrypt_code` primitive.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_neon_response(data: dict, status_code: int = 200):
    """Create a mock httpx Response matching Neon HTTP API format."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


def _install_mock_client(server_module, side_effect=None, return_value=None):
    """Wire a mock httpx.AsyncClient into the server module's globals.

    Bypasses _get_client's lazy initialization (which would otherwise require
    NEON_DATABASE_URL to be set in the environment).
    """
    mock_client = AsyncMock()
    if side_effect is not None:
        mock_client.post.side_effect = side_effect
    elif return_value is not None:
        mock_client.post.return_value = return_value
    server_module._http_client = mock_client
    server_module._neon_endpoint = "https://test.neon.tech/sql"
    server_module._schema_ensured = True
    return mock_client


def _reset_server_state(server_module):
    """Tear down the mock client wiring so other tests start clean."""
    server_module._http_client = None
    server_module._neon_endpoint = None
    server_module._schema_ensured = False


# ---------------------------------------------------------------------------
# store_code tests
# ---------------------------------------------------------------------------


class TestStoreCode:
    """Tests for the `store_code` MCP tool."""

    @pytest.mark.asyncio
    async def test_store_code_encrypts_before_persisting(self):
        """The plaintext code never reaches Neon — the INSERT params must
        contain ciphertext, not the raw authorization code."""
        import server

        mock_client = _install_mock_client(
            server, return_value=_mock_neon_response({"rows": [], "command": "INSERT"})
        )

        try:
            result = await server.store_code(code="auth-code-xyz", state="state-token-123")
            assert result["success"] is True

            insert_calls = [
                call for call in mock_client.post.call_args_list
                if "INSERT INTO oauth_codes" in str(call)
            ]
            assert len(insert_calls) >= 1

            body = insert_calls[0].kwargs.get("json")
            stored_code = body["params"][1]
            assert stored_code != "auth-code-xyz", \
                "Code must be encrypted, not stored as plaintext"
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_store_code_runs_cleanup_first(self):
        """The cleanup DELETE runs before the INSERT so expired rows are
        purged on every store."""
        import server

        mock_client = _install_mock_client(
            server, return_value=_mock_neon_response({"rows": [], "command": "DELETE"})
        )

        try:
            await server.store_code(code="c", state="s")
            cleanup_calls = [
                call for call in mock_client.post.call_args_list
                if "DELETE FROM oauth_codes WHERE received_at" in str(call)
            ]
            assert len(cleanup_calls) >= 1
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_store_code_returns_error_on_db_failure(self):
        """If Neon raises, the tool returns success=False with an error
        message rather than propagating the exception."""
        import server

        mock_client = AsyncMock()
        mock_client.post.side_effect = RuntimeError("Neon unreachable")
        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            result = await server.store_code(code="c", state="s")
            assert result["success"] is False
            assert "Neon unreachable" in result["error"]
        finally:
            _reset_server_state(server)


# ---------------------------------------------------------------------------
# retrieve_code tests
# ---------------------------------------------------------------------------


class TestRetrieveCode:
    """Tests for the `retrieve_code` MCP tool — one-time read with delete."""

    @pytest.mark.asyncio
    async def test_retrieve_returns_stored_code(self):
        """DELETE ... RETURNING surfaces the encrypted code to the caller."""
        import server

        _install_mock_client(server, side_effect=[
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response(
                {"rows": [{"code": "ENCRYPTED_BLOB"}], "command": "DELETE"}
            ),
        ])

        try:
            result = await server.retrieve_code(state="state-token-123")
            assert result["found"] is True
            assert result["code"] == "ENCRYPTED_BLOB"
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_retrieve_uses_delete_returning(self):
        """The retrieve path issues a DELETE ... RETURNING — it is a
        one-time read; a subsequent retrieve_code for the same state finds
        nothing."""
        import server

        _install_mock_client(server, side_effect=[
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response(
                {"rows": [{"code": "BLOB"}], "command": "DELETE"}
            ),
        ])
        mock_client = server._http_client

        try:
            await server.retrieve_code(state="s")
            delete_returning = [
                call for call in mock_client.post.call_args_list
                if "DELETE FROM oauth_codes WHERE state" in str(call)
                and "RETURNING code" in str(call)
            ]
            assert len(delete_returning) >= 1
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_retrieve_not_found_returns_found_false(self):
        """An unknown state returns found=False with an error string,
        not an exception."""
        import server

        _install_mock_client(server, side_effect=[
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # not found
        ])

        try:
            result = await server.retrieve_code(state="unknown.state")
            assert result["found"] is False
            assert "not found" in result["error"]
        finally:
            _reset_server_state(server)


# ---------------------------------------------------------------------------
# collector_status tests
# ---------------------------------------------------------------------------


class TestCollectorStatus:
    """Tests for the `collector_status` MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_healthy_with_pending_count(self):
        """When DB is reachable, status='healthy' with the live row count
        and the static TTL."""
        import server

        _install_mock_client(server, side_effect=[
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response({"rows": [{"cnt": 3}], "command": "SELECT"}),
        ])

        try:
            result = await server.collector_status()
            assert result["status"] == "healthy"
            assert result["pending_codes"] == 3
            assert result["ttl_seconds"] == 600
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_returns_unhealthy_when_neon_url_missing(self):
        """No NEON_DATABASE_URL → unhealthy with that name in the error."""
        import server
        _reset_server_state(server)

        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NEON_DATABASE_URL", None)
            result = await server.collector_status()
            assert result["status"] == "unhealthy"
            assert "NEON_DATABASE_URL" in result["error"]


# ---------------------------------------------------------------------------
# Encryption tests
# ---------------------------------------------------------------------------


class TestEncryption:
    """Tests for `_encrypt_code` — AES-256-GCM with SHA-256(state) as the key
    and a 12-byte random IV prepended to the ciphertext."""

    def test_encrypt_produces_non_plaintext(self):
        """Encrypted output differs from plaintext."""
        from server import _encrypt_code

        encrypted = _encrypt_code("auth-code-xyz", "state-token-123")
        assert encrypted != "auth-code-xyz"

    def test_encrypt_decrypt_roundtrip(self):
        """AES-256-GCM with SHA-256(state) decrypts the ciphertext that
        _encrypt_code produced. Mirrors what the originating MCP server
        does when it retrieves the code."""
        import base64
        import hashlib

        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        from server import _encrypt_code

        code = "my-secret-auth-code-1234"
        state = "nonce.hmac-signature"

        encrypted_b64 = _encrypt_code(code, state)

        raw = base64.urlsafe_b64decode(encrypted_b64)
        iv, ct = raw[:12], raw[12:]
        key = hashlib.sha256(state.encode()).digest()
        decrypted = AESGCM(key).decrypt(iv, ct, None)

        assert decrypted.decode() == code

    def test_different_states_produce_different_ciphertext(self):
        """Same code under two different state tokens yields distinct
        ciphertexts (different keys + random IVs make repetition statistically
        impossible)."""
        from server import _encrypt_code

        enc1 = _encrypt_code("auth-code-xyz", "state-a")
        enc2 = _encrypt_code("auth-code-xyz", "state-b")
        assert enc1 != enc2

    def test_same_state_same_code_produces_different_ciphertext(self):
        """Even with identical inputs, a fresh random IV makes each call
        produce different ciphertext — defends against IV-reuse attacks
        on AES-GCM."""
        from server import _encrypt_code

        enc1 = _encrypt_code("auth-code-xyz", "state-a")
        enc2 = _encrypt_code("auth-code-xyz", "state-a")
        assert enc1 != enc2, \
            "IV must be random per call; identical ciphertext indicates IV reuse"
