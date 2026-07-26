# Tollbooth OAuth2 Collector

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)

An unauthenticated "dumb mailbox" FastMCP server that holds OAuth2 authorization codes for retrieval by the originating MCP server. A companion serverless function (Val Town) receives the browser redirect from the OAuth provider and hands the code to this collector's `store_code` MCP tool. This two-part design works around Horizon proxying only POST traffic on the `/mcp/` path — browser GET redirects from OAuth providers cannot reach `@mcp.custom_route` endpoints, so a serverless callback bridges the gap.

## How It Works

```
┌───────────────┐   1. redirect_uri → serverless    ┌──────────────────────┐
│ OAuth Provider│ ─────────────────────────────────→│ Serverless callback  │
│ (e.g. Schwab) │   GET ?code=AUTH_CODE&state=TOKEN  │ (Val Town)           │
└───────────────┘                                    └──────────────────────┘
                                                               │
                                        2. POST store_code     │
                                           (JSON-RPC /mcp/)     ▼
                                                     ┌──────────────────────┐
                                                     │ OAuth2 Collector     │
                                                     │ store_code tool      │
                                                     │ → encrypts + Postgres│
                                                     └──────────────────────┘
                                                               │
                                                               │ 3. code stored
                                                               ▼
┌──────────────┐   4. retrieve_code(state=TOKEN)     ┌──────────────────────┐
│ MCP Server   │ ─────────────────────────────────→  │ OAuth2 Collector     │
│ (e.g.        │        (JSON-RPC /mcp/)             │ retrieve_code tool   │
│  schwab-mcp) │ ←───────────────────────────────── │ → returns code once  │
└──────────────┘   {"found": true, "code": ...}      │ → deletes from DB    │
                                                     └──────────────────────┘
```

1. **MCP server** starts an OAuth flow, setting `redirect_uri` to the serverless callback function's URL
2. **User** authorizes in the browser; the OAuth provider redirects to the serverless callback with `?code=...&state=...`
3. **Serverless callback** (Val Town) POSTs the code to the collector's `store_code` MCP tool over `/mcp/`
4. **Collector** encrypts the code (AES-256-GCM keyed on SHA-256 of the state) and stores it in Postgres (600s TTL)
5. **MCP server** calls the `retrieve_code(state=...)` MCP tool to pick up the code (one-time read, auto-deleted)
6. **MCP server** decrypts and exchanges the code for a token using its own credentials

The collector also exposes `collector_status` (pending-code count and TTL) and `service_status` (deployed build, incl. git sha) as free MCP tools. The serverless callback source lives in [`val/oauth_callback.js`](val/oauth_callback.js).

## Deployment

Deploy to Horizon:

```bash
fastmcp deploy server.py
```

Set the `NEON_DATABASE_URL` environment variable in Horizon to point to your Neon Postgres instance.

## DPYC Advocate Identity

This collector is registered as an **Advocate** in the [DPYC Social Contract](https://github.com/lonniev/dpyc-community). Consuming MCP servers discover its URL automatically via the DPYC registry:

```python
from tollbooth.registry import resolve_service_by_name

svc = await resolve_service_by_name("tollbooth-oauth2-collector")
collector_url = svc["url"]  # e.g., "https://tollbooth-oauth2-collector.fastmcp.app"
```

No `OAUTH_COLLECTOR_URL` env var needed — peer discovery is handled by the registry.

Register the **serverless callback function's** URL (not the collector's) in your OAuth provider's developer portal. It is registered separately in the DPYC registry under the name `tollbooth-oauth2-callback`:
```python
callback = await resolve_service_by_name("tollbooth-oauth2-callback")
redirect_uri = callback["url"]  # e.g., "https://tollbooth-dpyc-oauth.val.run"
```

## Security Model

- **Auth codes are useless alone** — exchanging a code requires `client_id` + `client_secret`, held only by the consuming MCP server
- **Encrypted at rest** — codes are stored AES-256-GCM-encrypted (keyed on SHA-256 of the state) via the SDK's `encrypt_collector_code`; the consuming MCP server decrypts with the same state
- **HMAC-signed state tokens** — the originating MCP server generates tamper-proof state tokens
- **One-time read** — codes are deleted immediately after retrieval (prevents replay)
- **Short TTL** — expired codes are automatically cleaned up (600s)
- **No secrets stored** — the collector never sees client credentials or tokens

## Related Repositories

| Repository | Description |
|---|---|
| [tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc) | Python SDK for Tollbooth monetization |
| [dpyc-community](https://github.com/lonniev/dpyc-community) | DPYC Social Contract registry and governance |
| [dpyc-oracle](https://github.com/lonniev/dpyc-oracle) | Free community concierge — membership, governance, onboarding |
| [tollbooth-authority](https://github.com/lonniev/tollbooth-authority) | Certification Authority MCP service |
| [tollbooth-sample](https://github.com/lonniev/tollbooth-sample) | Reference Operator implementation / template |
| [tollbooth-pricing-studio](https://github.com/lonniev/tollbooth-pricing-studio) | iOS pricing editor for Operators |
| [cypher-mcp](https://github.com/lonniev/cypher-mcp) | Monetized graph answers — named Cypher over Neo4j/AuraDB |
| [schwab-mcp](https://github.com/lonniev/schwab-mcp) | Schwab brokerage MCP server |
| [thebrain-mcp](https://github.com/lonniev/thebrain-mcp) | Personal Brain knowledge-graph MCP server |
| [excalibur-mcp](https://github.com/lonniev/excalibur-mcp) | X (Twitter) posting MCP server |
| [taxsort-mcp](https://github.com/lonniev/taxsort-mcp) | Tax sorting and classification MCP server |
| [optionality-mcp](https://github.com/lonniev/optionality-mcp) | Options analytics MCP server |
| [tollbooth-oauth2-collector](https://github.com/lonniev/tollbooth-oauth2-collector) | OAuth2 callback collector (Advocate) |
| [tollbooth-shortlinks](https://github.com/lonniev/tollbooth-shortlinks) | URL shortener utility Operator |

## License

Copyright 2026 Lonnie VanZandt. Licensed under the [Apache License, Version 2.0](LICENSE).
