# Tollbooth OAuth2 Collector

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12+-green.svg)](https://python.org)

An unauthenticated "dumb mailbox" FastMCP server that holds OAuth2 authorization codes for retrieval by the originating MCP server. A companion serverless function (Val Town) receives the browser redirect from the OAuth provider and hands the code to this collector's `store_code` MCP tool. This two-part design works around Horizon proxying only POST traffic on the `/mcp/` path — browser GET redirects from OAuth providers cannot reach `@mcp.custom_route` endpoints, so a serverless callback bridges the gap.

## How It Works

```
┌───────────────┐   1. redirect_uri → serverless    ┌──────────────────────┐
│ OAuth Provider│ ─────────────────────────────────→│ Serverless callback  │
│ (e.g. Schwab) │   GET ?code=AUTH_CODE&state=STATE  │ (Val Town)           │
└───────────────┘                                    └──────────────────────┘
                                                               │
                                        2. POST store_code     │
                                           (JSON-RPC /mcp/)     ▼
                                                     ┌──────────────────────┐
                                                     │ OAuth2 Collector     │
                                                     │ store_code tool      │
                                                     │ → seals + Postgres   │
                                                     └──────────────────────┘
                                                               │
                                                               │ 3. code stored
                                                               ▼
┌──────────────┐   4. retrieve_code(state=PATRON)    ┌──────────────────────┐
│ MCP Server   │ ─────────────────────────────────→  │ OAuth2 Collector     │
│ (e.g.        │        (JSON-RPC /mcp/)             │ retrieve_code tool   │
│  schwab-mcp) │ ←───────────────────────────────── │ → returns code once  │
└──────────────┘   {"found": true, "code": ...}      │ → deletes from DB    │
                                                     └──────────────────────┘
```

1. **MCP server** starts an OAuth flow, setting `redirect_uri` to the serverless callback function's URL. Its `state` is `<patron npub>.<operator npub>` (the SDK's `pack_oauth_state`)
2. **User** authorizes in the browser; the OAuth provider redirects to the serverless callback with `?code=...&state=...`
3. **Serverless callback** (Val Town) POSTs the code to the collector's `store_code` MCP tool over `/mcp/`
4. **Collector** seals the code to the operator npub with NIP-44 (the SDK's `encrypt_collector_code`) and stores it in Postgres under the patron npub (600s TTL)
5. **MCP server** calls the `retrieve_code(state=<patron npub>)` MCP tool to pick up the sealed code (one-time read, auto-deleted)
6. **MCP server** opens the seal with its own nsec (`decrypt_collector_code`) and exchanges the code for a token using its own credentials

The collector also exposes `collector_status` (pending-code count and TTL) and `service_status` (deployed build, incl. git sha) as free MCP tools. The serverless callback source lives in [`val/oauth_callback.js`](val/oauth_callback.js).

## Deployment

Deploy to Horizon:

```bash
fastmcp deploy server.py
```

Set the `NEON_DATABASE_URL` environment variable in Horizon to point to your Neon Postgres instance.

## DPYC Advocate Identity

This collector is registered as an **Advocate** in the [DPYC Social Contract](https://github.com/lonniev/dpyc-community). Consuming MCP servers discover its URL by asking the Oracle:

```python
from tollbooth.oracle_client import default_oracle_client

svc = await default_oracle_client().resolve_service(name="tollbooth-oauth2-collector")
collector_url = svc["url"]  # e.g., "https://tollbooth-oauth2-collector.fastmcp.app"
```

No `OAUTH_COLLECTOR_URL` env var needed — peer discovery is handled by the registry.

Register the **serverless callback function's** URL (not the collector's) in your OAuth provider's developer portal. It is registered separately in the DPYC registry under the name `tollbooth-oauth2-callback`, and the SDK's `begin_oauth` uses it as the `redirect_uri`:
```python
callback = await default_oracle_client().resolve_service(name="tollbooth-oauth2-callback")
redirect_uri = callback["url"]  # e.g., "https://tollbooth-dpyc-oauth.val.run"
```

## Security Model

- **Auth codes are useless alone** — exchanging a code requires `client_id` + `client_secret`, held only by the consuming MCP server
- **Sealed at rest** — codes are sealed with NIP-44 to the operator npub carried in the state (the SDK's `encrypt_collector_code`); only that operator's nsec opens them, and the state is never a key
- **Public state** — the state carries only two npubs, public keys that are safe to route through the browser; a state with no operator npub is refused
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
| [goodearth-mcp](https://github.com/lonniev/goodearth-mcp) | Region-scoped farm climate analytics MCP server |
| [beesknees-mcp](https://github.com/lonniev/beesknees-mcp) | The Bee's Knees multiplayer race MCP server |
| [roastify-mcp](https://github.com/lonniev/roastify-mcp) | Roastify coffee catalog and packaging artwork MCP server |
| [ChartRemotely-mcp](https://github.com/lonniev/ChartRemotely-mcp) | Desktop chart relay MCP server |
| [tollbooth-web](https://github.com/lonniev/tollbooth-web) | Shared browser SDK for operator front ends |
| [tollbooth-oauth2-collector](https://github.com/lonniev/tollbooth-oauth2-collector) | OAuth2 callback collector (Advocate) |
| [tollbooth-shortlinks](https://github.com/lonniev/tollbooth-shortlinks) | URL shortener utility (Advocate) |

## License

Copyright 2026 Lonnie VanZandt. Licensed under the [Apache License, Version 2.0](LICENSE).
