# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

