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
