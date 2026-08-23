# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed — deploy-verify could not confirm a redeploy (served `<none>` / "did not land")

- The post-merge deploy-verify probe reads the live commit sha from the canonical
  `service_status` tool's `build_info.fastmcp_cloud_git_commit_sha`. This collector
  exposed only `collector_status`, never `service_status`, so the probe found no sha
  to read and reported the deploy as serving `<none>` — flagging an otherwise-healthy
  service as "did not land" (issue #9).
- Added a `service_status` MCP tool that delegates to the SDK's canonical
  `build_service_status` (tollbooth-dpyc) — the single source of the status payload
  shape — surfacing the deployed git sha, wheel versions, and build info. The
  vault/courier/operator fields are reported empty by construction: this is an
  unauthenticated community utility with no operator runtime.

## [0.2.9] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.3

Recovering an orphaned job now uses the detached executor it was
dispatched to. The recovery path never resolved the executor, so a
job orphaned by a container recycle was retried in-process on the
new front — bypassing the detached runner precisely when it was
the point.

## [0.2.8] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.2

An object argument a client serialised as a JSON string is now parsed
rather than refused as `dict_type`. Fixes `update_post` rejecting a
large patch and `update_design_text` rejecting a multi-key edits
object.

## [0.2.7] — 2026-08-22

### Changed — track tollbooth-dpyc 0.87.1

Picks up the relay-reliability work: `COURIER_RELAY_UNREACHABLE` so an
unreachable pinned rendezvous is no longer reported as the patron never
replying, relay-failure reporting to the Oracle, and a publish that counts
only when the relay acknowledges that exact event.

## 0.2.6 — 2026-08-17

### Changed — track tollbooth-dpyc 0.86.0 (GitHub-free bootstrap)

Picks up the GitHub-free operator bootstrap: relays and Authority resolution now come from the Oracle via MCP, so this operator no longer reads the dpyc-community registry on GitHub — closing the fleet-wide bootstrap SPOF.

## 0.2.5 — 2026-08-10

### Added — a canonical `service_status`, so a deploy can be confirmed

The collector could not be asked what it was running, which is why deploy-verify was removed
from it rather than fixed: the probe had nothing to read. `service_status` now reports the
landed sha like every other service.

### Changed — track tollbooth-dpyc 0.85.0, in both files

This repo pins in `pyproject.toml` **and** `requirements.txt`, because Horizon builds from
the latter while local tooling reads the former. They must not drift: when they did, the
deployed collector had no `tollbooth` module at all and `store_code` failed on every call,
stranding OAuth for the whole fleet. Both now read 0.85.0.

Picks up `check_authority_balance`, dead for every operator, and the shared param-default
binding.

### Changed — CI runs the check the deploy runs

`ci.yml` inspects the deploy entrypoint, the check Horizon performs at build time — the gap
that let optionality-mcp sit four days stale behind a green suite. `release.yml` notes
extraction accepts this CHANGELOG's heading style instead of publishing a 16-byte body.

Note: 0.2.4 was written here but never tagged, so it never shipped a release. This entry
covers that work too.

## [0.2.4] — 2026-07-15

### Fixed — collector deployed without `tollbooth-dpyc`, so `store_code` crashed on every call

- v0.2.3 made `_encrypt_code` `from tollbooth.oauth2_collector import encrypt_collector_code`
  and added `tollbooth-dpyc` to **pyproject.toml only**. The platform builds from
  **requirements.txt**, which listed just `fastmcp` + `httpx` — so the deployed collector
  had no `tollbooth` module. Every `store_code` returned
  `{"success": false, "error": "No module named 'tollbooth'"}`, codes were never stored,
  and so every consuming server's `check_oauth_status` (schwab-mcp, etc.) stranded on
  `pending` forever — the true cause of the 2026-07-09 ecosystem-wide OAuth outage.
- `requirements.txt` now carries `tollbooth-dpyc==0.63.2` and `cryptography`, matching
  `pyproject.toml`.

### Changed — pin deps for reproducible deploys

- `fastmcp==3.1.0` and `tollbooth-dpyc==0.63.2` are now pinned exactly (were unpinned
  floors) in both `requirements.txt` and `pyproject.toml`. Unpinned floors let the
  transport framing (SSE↔JSON) and the auth-code crypto resolve differently on each
  redeploy — the non-determinism behind this whole class of intermittent breakage.

## [0.2.3] — 2026-07-09

- refactor: `_encrypt_code` now delegates to the SDK's canonical `encrypt_collector_code` — the peer of `decrypt_collector_code`. Both halves of the auth-code crypto contract now live in `tollbooth-dpyc`, so the collector and the MCP servers that decrypt can't drift on key derivation or framing.
- deps: add `tollbooth-dpyc>=0.62.1` (introduces `encrypt_collector_code`).
- build: raise `requires-python` to `>=3.12` to match the SDK's floor.

## [0.2.2] — 2026-05-13

- security: encrypt OAuth authorization codes with **AES-256-GCM**, replacing the prior XOR scheme
- deps: bump `cryptography` >= 46.0.5 to match the SDK floor
- test: rewrite `test_server` against the current API + AES-256-GCM
- docs: refresh the val.run callback URL in the docstring header

## [0.2.1] — 2026-03-15

- chore: bump version to 0.2.1
- add the success image
- feat: add DPYC Tollbooth branding to OAuth callback success page

## [0.2.0] — 2026-03-10

- feat: MCP tools + serverless val for OAuth callback

## [0.1.2] — 2026-03-10

- fix: accept POST on callback and retrieve for Horizon compat

## [0.1.1] — 2026-03-10

- feat: polished success page with encryption messaging
- feat: document DPYC Advocate identity (#1)
- feat: encrypt OAuth codes at rest using SHA-256(state) XOR keystream
- Remove debug error surfacing from responses
- Fix infinite recursion in schema initialization
- Debug: surface exception details in error responses
- Remove uv.lock (confuses Horizon), add NOTICE file
- Add requirements.txt for Horizon dependency detection
- Add .fastmcp.yaml for Horizon deployment
- Replace asyncpg with Neon SQL-over-HTTP API via httpx
- Initial commit: OAuth2 callback collector for Tollbooth MCP services

