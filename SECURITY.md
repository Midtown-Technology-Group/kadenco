# Security

## Supported release and reporting

Only the latest experimental source revision receives fixes. There is no stable
support or response-time guarantee. Use private vulnerability reporting linked
below; do not post proof-of-concept credentials or customer data publicly.

## Trust and resource boundaries

- MCP reads require a current host/project read grant; commands require separate
  live host/provider authorization. Event subscriptions confer no execution.
- Remote MCP HTTP reads reject redirects, enforce a 15-second request deadline,
  and cap response bodies at 2 MiB, even without Content-Length. Session cleanup
  is best effort with a five-second deadline. These caps apply to this HTTP read
  transport, not arbitrary provider/native-WebSocket data paths.
- Webhooks require HTTPS, an allowlisted host and exclusively public DNS answers.
  DNS resolution is deadline-bounded, validated addresses are pinned for the TLS
  connection, responses are capped and redirects are not followed. The deadline
  bounds application waiting; the OS DNS operation itself may finish later.
- The MCP listener has explicit header/request/keepalive timeouts and a per-socket
  request cap. These are resource limits, not a substitute for an authenticated
  private ingress, operator rate limiting or network access controls.
- Permission approvals, new credentials and grants are never created by passive
  inbox handling or monitoring. Unknown send outcomes are reconciled, not replayed.

## Repository controls

Main uses PRs, one independent approval, stale-review dismissal, approval after
the last push, resolved review threads, a current base, required CI/CodeQL and no
bypass actors. Force-push/deletion are blocked. Merge is squash-only and merged
branches are deleted. GitHub Actions defaults to read-only tokens and cannot
approve pull requests. CI disables checkout credential persistence, pins actions
by SHA, skips install scripts and never uses pull_request_target.

Secret scanning/push protection, private vulnerability reporting, Dependabot
security updates and extended default CodeQL are enabled. Dependabot configuration
updates npm and action pins weekly; scheduled CI audits development dependencies
as well as runtime dependencies. CodeQL is GitHub-managed default setup, not a
second competing producer in our workflow.

Do not put credentials, private thread contents or infrastructure identifiers in public issues. Report suspected vulnerabilities privately at https://github.com/Midtown-Technology-Group/kadenco/security/advisories/new . Do not include sensitive data in public issues. Do not deploy this experimental candidate exposed directly to the Internet. Use operator-managed HTTPS/private connectivity, owner-only state permissions, allowlisted routes and scoped credentials.

Persistent diagnostic values and operational records are encrypted; host/timestamp/sequence indices and legacy audit metadata are plaintext. Keys must be provided separately. Diagnostics never record raw error text, tokens, response bodies or user messages. Logs can still reveal operational topology and must remain private. No secret scan can prove absence of every sensitive value.
