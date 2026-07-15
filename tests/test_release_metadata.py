"""Release-metadata invariants for tollbooth-oauth2-collector.

The version is declared in more than one place: ``pyproject.toml`` (what the
deploy platform builds a wheel from) and ``server.json`` (what the MCP registry
advertises). When these drift, two things break:

* The registry advertises a version that no longer matches the deployed code.
* Horizon keys its wheel cache on the package version, so a version that never
  advances lets a stale wheel be re-served on redeploy — the "stale-wheel"
  failure mode that leaves the live service serving cached bytes (or, on a
  half-failed rebuild, unreachable).

This test pins the two declarations together so the drift cannot recur
unnoticed. It runs offline against the repo files — no deploy access needed.
"""

import json
from pathlib import Path

import tomllib

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    data = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text())
    return data["project"]["version"]


def _server_json_version() -> str:
    data = json.loads((_REPO_ROOT / "server.json").read_text())
    return data["version"]


def test_server_json_version_matches_pyproject():
    """``server.json`` (MCP registry) must declare the same version the deploy
    builds from (``pyproject.toml``). Drift means the registry advertises stale
    bytes and lets Horizon re-serve a cached wheel."""
    assert _server_json_version() == _pyproject_version(), (
        f"version drift: server.json={_server_json_version()!r} vs "
        f"pyproject.toml={_pyproject_version()!r}. Bump both together so the "
        f"registry and the deployed wheel stay in lockstep."
    )
