# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

