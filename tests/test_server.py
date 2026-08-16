"""Tests for tollbooth-oauth2-collector server.

Mocks Neon's SQL-over-HTTP API so no real Postgres is required. Targets the
current MCP-tool surface (`store_code`, `retrieve_code`, `collector_status`)
and the NIP-44 `_seal_code` primitive.
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


# A packed OAuth state: "<patron_npub>.<operator_npub>". store_code seals the code
# to the operator npub (NIP-44) and keys the Neon row by the patron npub.
_PATRON = "npub1y20qa7d3ddmh6730hdr0u0r08zys4p7pyk30uhur9edx4d88q4zqnr3q2h"
_OPERATOR = "npub1ymgfh46ace33zgld5zdc7gyhc5keyu42v36td0q7c44ks45d79eslwe2q2"
_PACKED_STATE = f"{_PATRON}.{_OPERATOR}"


class TestStoreCode:
    """Tests for the `store_code` MCP tool."""

    @pytest.mark.asyncio
    async def test_store_code_seals_before_persisting(self):
        """The plaintext code never reaches Neon — the INSERT params must carry
        the NIP-44 sealed envelope, and the row is keyed by the patron npub."""
        import server

        mock_client = _install_mock_client(
            server, return_value=_mock_neon_response({"rows": [], "command": "INSERT"})
        )

        try:
            result = await server.store_code(code="auth-code-xyz", state=_PACKED_STATE)
            assert result["success"] is True

            insert_calls = [
                call for call in mock_client.post.call_args_list
                if "INSERT INTO oauth_codes" in str(call)
            ]
            assert len(insert_calls) >= 1

            body = insert_calls[0].kwargs.get("json")
            keyed_by, stored_code = body["params"][0], body["params"][1]
            assert keyed_by == _PATRON, "Row must be keyed by the patron npub, not the packed state"
            assert stored_code != "auth-code-xyz", "Code must be sealed, not stored as plaintext"
        finally:
            _reset_server_state(server)

    @pytest.mark.asyncio
    async def test_store_code_refuses_state_without_operator(self):
        """A legacy patron-only state has no operator to seal to — refuse it
        rather than seal to the wrong (public) key."""
        import server

        _install_mock_client(
            server, return_value=_mock_neon_response({"rows": [], "command": "INSERT"})
        )
        try:
            result = await server.store_code(code="c", state="npub1patrononly")
            assert result["success"] is False
            assert "operator" in result["error"].lower()
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
            await server.store_code(code="c", state=_PACKED_STATE)
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
            result = await server.store_code(code="c", state=_PACKED_STATE)
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
# service_status tests
# ---------------------------------------------------------------------------


class TestServiceStatus:
    """Tests for the `service_status` tool.

    The post-merge deploy-verify probe reads the running commit sha from this
    tool's `build_info` to confirm a redeploy actually landed. Its absence is
    why an otherwise-healthy deploy was reported as serving `<none>`.
    """

    @pytest.mark.asyncio
    async def test_reports_deployed_git_sha_for_deploy_verify(self):
        """`build_info` surfaces FASTMCP_CLOUD_GIT_COMMIT_SHA so deploy-verify
        can compare the live sha against the merged sha."""
        import server

        sha = "8c2302cde532cc32d786366ca299f358f2dac28d"
        with patch.dict(os.environ, {"FASTMCP_CLOUD_GIT_COMMIT_SHA": sha}):
            result = await server.service_status()

        assert result["success"] is True
        assert result["service"] == "tollbooth-oauth2-collector"
        assert result["build_info"]["fastmcp_cloud_git_commit_sha"] == sha

    @pytest.mark.asyncio
    async def test_reports_tollbooth_dpyc_wheel_version(self):
        """The status echoes the installed tollbooth-dpyc wheel version — the
        dep whose silent absence stranded every consumer's OAuth on `pending`."""
        import server

        result = await server.service_status()
        assert result["tollbooth_dpyc_version"] != "unknown"
