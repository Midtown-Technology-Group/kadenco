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

A journey is `verified` when its last complete round trip is under 24 hours old,
`stale` when older, `failing` when an attempt newer than the last success has been
unfinished for 15 minutes, and `unverified` when there is no evidence at all.

## Acceptance check

```sh
KADENCO_STATUS_TOKEN=<owner bearer> npm run status          # summary
npm run status -- --json < bearer.txt                         # full JSON, bearer on stdin
```

Exit codes: `0` every journey verified, `1` degraded/unverified/down, `2`
unreachable or refused. Set `KADENCO_STATUS_URL` for a non-default listener.
It only observes organic evidence; generating test traffic against a live
install is a separate, owner-approved step.
