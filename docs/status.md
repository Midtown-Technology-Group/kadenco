# Operational status

`GET /status` on the MCP listener (default `http://127.0.0.1:41880/status`)
answers one question for an authenticated owner: what is running, and which of
its journeys have actually worked recently? It is read-only. It never creates
subscriptions, contacts T3, sends events or extends grants. On the central edge
it bypasses the lease gate so it stays observable during an outage, and reports
`state_authority: local_cache_without_lease` when the lease is not held.

Authenticate with any enabled principal's bearer (`Authorization: Bearer …`).
Each owner sees only exchanges where it is the inbox or the caller, and
deliveries for its own subscriptions.

| Field                     | Meaning                                                                                                                                                                                                     |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `overall`                 | `ok` (every journey verified), `unverified` (no fresh evidence yet), `degraded` (a journey is failing or the lease is renewing badly), `down` (edge lease lost)                                             |
| `build`                   | `package_version` from the installed `package.json`, `source_commit` and `build_run` from a release's `BUILD.json` (null in a source checkout)                                                              |
| `runtime.lease`           | `held`, `renewal_failing` (renewals failing, lease not yet expired), `lost` (fenced/refused/expired), or `not_applicable` for the standalone sidecar; with the last renewal, expiry and last failure reason |
| `journeys.ask_eddie`      | Last full round trip (asked → delivered → read → replied → acknowledged by the asking agent), and the stage the newest attempt reached                                                                      |
| `journeys.event_delivery` | Last 2xx webhook acknowledgement and last failed attempt. A 2xx proves receipt by the callback endpoint, not agent execution                                                                                |
| `hosts`                   | The newest stored diagnostic per readable host                                                                                                                                                              |

Journey states, evaluated in this order:

- `failing`: an attempt with no later success has been unfinished for more than
  15 minutes (any unanswered or expired ask-Eddie request; a pending or
  centrally queued delivery), or the newest delivery outcome is a failure and
  nothing is still pending.
- `verified`: the last complete round trip finished within 24 hours.
- `stale`: there is a complete round trip, but it is older than 24 hours.
- `unverified`: no complete round trip yet. Recent pending attempts are reported
  in `latest` / `pending` but are not yet proof that the journey works.

## Acceptance check

```sh
KADENCO_STATUS_TOKEN=<owner bearer> npm run status          # summary
npm run status -- --json < bearer.txt                         # full JSON, bearer on stdin
```

Exit codes: `0` every journey verified, `1` degraded/unverified/down, `2`
unreachable or refused. Set `KADENCO_STATUS_URL` for a non-default listener.
It only observes organic evidence; generating test traffic against a live
install is a separate, owner-approved step.
