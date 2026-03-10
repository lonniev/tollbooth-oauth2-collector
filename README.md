# Tollbooth OAuth2 Collector

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-green.svg)](https://python.org)

An unauthenticated "dumb mailbox" FastMCP server that captures OAuth2 authorization codes from browser redirects and holds them for retrieval by the originating MCP server. Solves the problem of Horizon's auth-proxy rejecting unauthenticated browser redirects to `@mcp.custom_route` endpoints.

## How It Works

```
┌──────────────┐    1. redirect_uri → collector    ┌─────────────────────┐
│ OAuth Provider│ ─────────────────────────────────→│ OAuth2 Collector    │
│ (e.g. Schwab) │   ?code=AUTH_CODE&state=TOKEN     │ GET /oauth/callback │
└──────────────┘                                    │ → stores in Postgres│
                                                    └─────────────────────┘
                                                              │
                                                              │ 2. code stored
                                                              ▼
┌──────────────┐    3. poll for code                ┌─────────────────────┐
│ MCP Server   │ ─────────────────────────────────→ │ OAuth2 Collector    │
│ (e.g.        │   GET /oauth/retrieve?state=TOKEN  │ → returns code once │
│  schwab-mcp) │ ←───────────────────────────────── │ → deletes from DB   │
└──────────────┘   {"code": "AUTH_CODE"}            └─────────────────────┘
```

1. **MCP server** starts an OAuth flow, setting `redirect_uri` to `https://<collector>/oauth/callback`
2. **User** authorizes in the browser; the OAuth provider redirects to the collector with `?code=...&state=...`
3. **Collector** stores the code in Postgres (600s TTL)
4. **MCP server** calls `GET /oauth/retrieve?state=...` to pick up the code (one-time read, auto-deleted)
5. **MCP server** exchanges the code for a token using its own credentials

## Deployment

Deploy to FastMCP Cloud (Horizon):

```bash
fastmcp deploy server.py
```

Set the `NEON_DATABASE_URL` environment variable in Horizon to point to your Neon Postgres instance.

## DPYC Advocate Identity

This collector is registered as an **Advocate** in the [DPYC Honor Chain](https://github.com/lonniev/dpyc-community). Consuming MCP servers discover its URL automatically via the DPYC registry:

```python
from tollbooth.registry import resolve_service_by_name

svc = await resolve_service_by_name("tollbooth-oauth2-collector")
collector_url = svc["url"]  # e.g., "https://tollbooth-oauth2-collector.fastmcp.app"
```

No `OAUTH_COLLECTOR_URL` env var needed — peer discovery is handled by the registry.

Register the collector's callback URL in your OAuth provider's developer portal:
```
https://tollbooth-oauth2-collector.fastmcp.app/oauth/callback
```

## Security Model

- **Auth codes are useless alone** — exchanging a code requires `client_id` + `client_secret`, held only by the consuming MCP server
- **HMAC-signed state tokens** — the originating MCP server generates tamper-proof state tokens
- **One-time read** — codes are deleted immediately after retrieval (prevents replay)
- **Short TTL** — expired codes are automatically cleaned up (600s)
- **No secrets stored** — the collector never sees client credentials or tokens

## Related Repositories

| Repository | Description |
|---|---|
| [dpyc-community](https://github.com/lonniev/dpyc-community) | DPYC Honor Chain registry and governance |
| [tollbooth-dpyc](https://github.com/lonniev/tollbooth-dpyc) | Python SDK for Tollbooth monetization |
| [tollbooth-authority](https://github.com/lonniev/tollbooth-authority) | Authority MCP service |
| [schwab-mcp](https://github.com/lonniev/schwab-mcp) | Schwab brokerage MCP server |
| [thebrain-mcp](https://github.com/lonniev/thebrain-mcp) | Personal Brain MCP server |
| [excalibur-mcp](https://github.com/lonniev/excalibur-mcp) | X (Twitter) posting MCP server |

## License

Copyright 2026 Lonnie VanZandt. Licensed under the [Apache License, Version 2.0](LICENSE).
