/**
 * Tollbooth OAuth2 Callback — serverless GET handler for OAuth provider redirects.
 *
 * Deployed as a Val Town HTTP val at:
 *   https://tollbooth-oauth2-callback-serverless.web.val.run
 *
 * This function receives the browser GET redirect from an OAuth provider
 * (e.g., Schwab, Google) with ?code=...&state=... query parameters, then
 * forwards the code to the Tollbooth OAuth2 Collector's `store_code` MCP
 * tool via a single JSON-RPC POST to the collector's /mcp/ endpoint.
 *
 * The collector encrypts the code at rest using SHA-256(state) and stores
 * it in Neon Postgres. The originating MCP server later retrieves it via
 * the collector's `retrieve_code` tool.
 *
 * Why this exists: Horizon (FastMCP Cloud) only proxies POST traffic on
 * the /mcp/ path. Browser GET redirects from OAuth providers cannot reach
 * custom_route endpoints. This serverless function bridges the gap.
 */

const COLLECTOR_MCP_URL =
  "https://tollbooth-oauth2-collector.fastmcp.app/mcp/";

const SUCCESS_HTML = `<!DOCTYPE html>
<html><head><title>Authorization Code Received</title></head>
<body style="font-family:system-ui,sans-serif;max-width:520px;margin:60px auto;
text-align:center;color:#1a1a1a;padding:0 20px">
<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:12px;
padding:40px 32px;box-shadow:0 1px 3px rgba(0,0,0,0.08)">
<div style="font-size:48px;margin-bottom:16px">\u2705</div>
<h1 style="font-size:22px;font-weight:600;margin:0 0 12px">
Authorization Code Received &amp; Saved</h1>
<p style="font-size:15px;line-height:1.5;color:#374151;margin:0 0 20px">
Your authorization code has been securely encrypted for your identity
and stored for retrieval.</p>
<hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0">
<p style="font-size:15px;line-height:1.5;color:#374151;margin:0 0 8px">
You can close this tab and return to your agentic app
(e.g.&nbsp;Claude&nbsp;Desktop, Claude&nbsp;Code).</p>
<p style="font-size:14px;color:#6b7280;margin:0">
The originating MCP server will automatically pick up the code.</p>
</div>
<p style="font-size:12px;color:#9ca3af;margin-top:20px">
\uD83D\uDD12 The code is encrypted at rest and can only be decrypted by the
requesting identity.</p>
</body></html>`;

const ERROR_HTML = `<!DOCTYPE html>
<html><head><title>Error</title></head>
<body style="font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;
text-align:center">
<h1>Missing Parameters</h1>
<p>Both <code>code</code> and <code>state</code> query parameters are required.</p>
</body></html>`;

const FAIL_HTML = `<!DOCTYPE html>
<html><head><title>Error</title></head>
<body style="font-family:system-ui,sans-serif;max-width:480px;margin:80px auto;
text-align:center">
<h1>Storage Error</h1>
<p>Failed to store the authorization code. Please try again.</p>
</body></html>`;

export default async function handler(req) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response(ERROR_HTML, {
      status: 400,
      headers: { "Content-Type": "text/html" },
    });
  }

  try {
    const resp = await fetch(COLLECTOR_MCP_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: "store_code", arguments: { code, state } },
        id: 1,
      }),
    });

    if (!resp.ok) {
      console.error(`Collector returned ${resp.status}: ${await resp.text()}`);
      return new Response(FAIL_HTML, {
        status: 502,
        headers: { "Content-Type": "text/html" },
      });
    }

    return new Response(SUCCESS_HTML, {
      status: 200,
      headers: { "Content-Type": "text/html" },
    });
  } catch (err) {
    console.error("Failed to call collector:", err);
    return new Response(FAIL_HTML, {
      status: 502,
      headers: { "Content-Type": "text/html" },
    });
  }
}
