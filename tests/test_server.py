"""Tests for tollbooth-oauth2-collector server — mock Neon HTTP API, no real Postgres."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_request(params: dict, headers: dict | None = None):
    """Create a mock Starlette Request."""
    req = MagicMock()
    req.query_params = params
    req.headers = headers or {}
    return req


def _mock_neon_response(data: dict, status_code: int = 200):
    """Create a mock httpx Response matching Neon HTTP API format."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = data
    resp.raise_for_status = MagicMock()
    return resp


# ---------------------------------------------------------------------------
# /oauth/callback tests
# ---------------------------------------------------------------------------


class TestOAuthCallback:
    """Tests for the /oauth/callback route."""

    @pytest.mark.asyncio
    async def test_callback_stores_code(self):
        """Callback with code+state stores the code via Neon HTTP API."""
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_neon_response({"rows": [], "command": "INSERT"})

        request = _mock_request({"code": "auth-code-xyz", "state": "nonce.sig"})

        import server

        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            resp = await server.oauth_callback(request)
            assert resp.status_code == 200

            # Verify INSERT was called (second call after cleanup)
            insert_calls = [
                call for call in mock_client.post.call_args_list
                if "INSERT INTO oauth_codes" in str(call)
            ]
            assert len(insert_calls) >= 1
        finally:
            server._http_client = None
            server._neon_endpoint = None
            server._schema_ensured = False

    @pytest.mark.asyncio
    async def test_callback_missing_code(self):
        """Callback returns 400 when code is missing."""
        request = _mock_request({"state": "nonce.sig"})

        import server

        resp = await server.oauth_callback(request)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_callback_missing_state(self):
        """Callback returns 400 when state is missing."""
        request = _mock_request({"code": "auth-code-xyz"})

        import server

        resp = await server.oauth_callback(request)
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_callback_missing_both(self):
        """Callback returns 400 when both params are missing."""
        request = _mock_request({})

        import server

        resp = await server.oauth_callback(request)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# /oauth/retrieve tests
# ---------------------------------------------------------------------------


class TestOAuthRetrieve:
    """Tests for the /oauth/retrieve route."""

    @pytest.mark.asyncio
    async def test_retrieve_returns_and_deletes(self):
        """Retrieve returns the code from Neon DELETE RETURNING."""
        mock_client = AsyncMock()
        # cleanup returns empty, then DELETE RETURNING returns the code
        mock_client.post.side_effect = [
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response({"rows": [{"code": "auth-code-xyz"}], "command": "DELETE"}),
        ]

        request = _mock_request({"state": "nonce.sig"})

        import server

        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            resp = await server.oauth_retrieve(request)
            assert resp.status_code == 200

            import json

            body = json.loads(resp.body.decode())
            assert body["code"] == "auth-code-xyz"
        finally:
            server._http_client = None
            server._neon_endpoint = None
            server._schema_ensured = False

    @pytest.mark.asyncio
    async def test_retrieve_not_found(self):
        """Retrieve returns 404 for unknown state."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = [
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # not found
        ]

        request = _mock_request({"state": "unknown.state"})

        import server

        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            resp = await server.oauth_retrieve(request)
            assert resp.status_code == 404
        finally:
            server._http_client = None
            server._neon_endpoint = None
            server._schema_ensured = False

    @pytest.mark.asyncio
    async def test_retrieve_missing_state(self):
        """Retrieve returns 400 when state param is missing."""
        request = _mock_request({})

        import server

        resp = await server.oauth_retrieve(request)
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Cleanup tests
# ---------------------------------------------------------------------------


class TestCleanup:
    """Tests for expired entry cleanup."""

    @pytest.mark.asyncio
    async def test_expired_entries_cleaned_on_callback(self):
        """Cleanup DELETE runs during callback handling."""
        mock_client = AsyncMock()
        mock_client.post.return_value = _mock_neon_response(
            {"rows": [], "command": "DELETE"}
        )

        request = _mock_request({"code": "code123", "state": "state456"})

        import server

        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            await server.oauth_callback(request)

            # The cleanup query should have been called
            cleanup_calls = [
                call
                for call in mock_client.post.call_args_list
                if "DELETE FROM oauth_codes WHERE received_at" in str(call)
            ]
            assert len(cleanup_calls) >= 1
        finally:
            server._http_client = None
            server._neon_endpoint = None
            server._schema_ensured = False


# ---------------------------------------------------------------------------
# collector_status tool tests
# ---------------------------------------------------------------------------


class TestCollectorStatus:
    """Tests for the collector_status MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_healthy_status(self):
        """collector_status returns healthy with pending count."""
        mock_client = AsyncMock()
        mock_client.post.side_effect = [
            _mock_neon_response({"rows": [], "command": "DELETE"}),  # cleanup
            _mock_neon_response({"rows": [{"cnt": 3}], "command": "SELECT"}),  # count
        ]

        import server

        server._http_client = mock_client
        server._neon_endpoint = "https://test.neon.tech/sql"
        server._schema_ensured = True

        try:
            result = await server.collector_status()
            assert result["status"] == "healthy"
            assert result["pending_codes"] == 3
            assert result["ttl_seconds"] == 600
        finally:
            server._http_client = None
            server._neon_endpoint = None
            server._schema_ensured = False

    @pytest.mark.asyncio
    async def test_returns_unhealthy_on_error(self):
        """collector_status returns unhealthy when DB is unreachable."""
        import server

        server._http_client = None
        server._neon_endpoint = None
        server._schema_ensured = False

        with patch.dict(os.environ, {}, clear=False):
            # Remove NEON_DATABASE_URL if set
            os.environ.pop("NEON_DATABASE_URL", None)
            result = await server.collector_status()
            assert result["status"] == "unhealthy"
            assert "NEON_DATABASE_URL" in result["error"]


import os
