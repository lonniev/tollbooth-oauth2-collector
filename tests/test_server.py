"""Tests for tollbooth-oauth2-collector server — mock asyncpg, no real Postgres."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_pool():
    """Create a mock asyncpg connection pool."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock()
    mock_conn.fetchrow = AsyncMock()
    mock_conn.fetchval = AsyncMock()

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_ctx.__aexit__ = AsyncMock(return_value=False)

    pool = AsyncMock()
    pool.acquire = MagicMock(return_value=mock_ctx)

    return pool, mock_conn


def _mock_request(params: dict, headers: dict | None = None):
    """Create a mock Starlette Request."""
    req = MagicMock()
    req.query_params = params
    req.headers = headers or {}
    return req


# ---------------------------------------------------------------------------
# /oauth/callback tests
# ---------------------------------------------------------------------------


class TestOAuthCallback:
    """Tests for the /oauth/callback route."""

    @pytest.mark.asyncio
    async def test_callback_stores_code(self):
        """Callback with code+state stores the code in Postgres."""
        pool, conn = _mock_pool()
        request = _mock_request({"code": "auth-code-xyz", "state": "nonce.sig"})

        import server

        server._pool = pool

        try:
            resp = await server.oauth_callback(request)
            assert resp.status_code == 200

            # Verify INSERT was called with correct params
            conn.execute.assert_any_call(
                "INSERT INTO oauth_codes (state, code) VALUES ($1, $2) "
                "ON CONFLICT (state) DO UPDATE SET code = $2, received_at = NOW()",
                "nonce.sig",
                "auth-code-xyz",
            )
        finally:
            server._pool = None

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
        """Retrieve returns the code and deletes the row."""
        pool, conn = _mock_pool()
        conn.fetchrow.return_value = {"code": "auth-code-xyz"}
        request = _mock_request({"state": "nonce.sig"})

        import server

        server._pool = pool

        try:
            resp = await server.oauth_retrieve(request)
            assert resp.status_code == 200

            import json

            body = json.loads(resp.body.decode())
            assert body["code"] == "auth-code-xyz"

            # Verify DELETE RETURNING was used
            conn.fetchrow.assert_called_with(
                "DELETE FROM oauth_codes WHERE state = $1 RETURNING code",
                "nonce.sig",
            )
        finally:
            server._pool = None

    @pytest.mark.asyncio
    async def test_retrieve_not_found(self):
        """Retrieve returns 404 for unknown state."""
        pool, conn = _mock_pool()
        conn.fetchrow.return_value = None
        request = _mock_request({"state": "unknown.state"})

        import server

        server._pool = pool

        try:
            resp = await server.oauth_retrieve(request)
            assert resp.status_code == 404
        finally:
            server._pool = None

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
        pool, conn = _mock_pool()
        request = _mock_request({"code": "code123", "state": "state456"})

        import server

        server._pool = pool

        try:
            await server.oauth_callback(request)

            # The cleanup query should have been called
            cleanup_calls = [
                call
                for call in conn.execute.call_args_list
                if "DELETE FROM oauth_codes WHERE received_at" in str(call)
            ]
            assert len(cleanup_calls) >= 1
        finally:
            server._pool = None


# ---------------------------------------------------------------------------
# collector_status tool tests
# ---------------------------------------------------------------------------


class TestCollectorStatus:
    """Tests for the collector_status MCP tool."""

    @pytest.mark.asyncio
    async def test_returns_healthy_status(self):
        """collector_status returns healthy with pending count."""
        pool, conn = _mock_pool()
        conn.fetchval.return_value = 3

        import server

        server._pool = pool

        try:
            result = await server.collector_status()
            assert result["status"] == "healthy"
            assert result["pending_codes"] == 3
            assert result["ttl_seconds"] == 600
        finally:
            server._pool = None

    @pytest.mark.asyncio
    async def test_returns_unhealthy_on_error(self):
        """collector_status returns unhealthy when DB is unreachable."""
        import server

        server._pool = None

        with patch("server._get_pool", new_callable=AsyncMock, side_effect=RuntimeError("no DB")):
            result = await server.collector_status()
            assert result["status"] == "unhealthy"
            assert "no DB" in result["error"]
