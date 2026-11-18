# Operational status

`GET /status` on the MCP listener (default `http://127.0.0.1:41880/status`)
answers one question for an authenticated owner: what is running, and which of
its journeys have actually worked recently? It is read-only. It never creates
subscriptions, contacts T3, sends events or extends grants. On the central edge
it bypasses the lease gate so it stays observable during an outage, and reports
`state_authority: local_cache_without_lease` when the lease is not held.

Authenticate with an enabled operator-style principal's bearer
(`Authorization: Bearer …`). Thread caller principals (`eddieCaller`,
`eddieHostCaller`) get `403 operator_status_only`. A principal sees exchanges
only while it is currently an Eddie inbox (`eddieInbox`), deliveries only for
its currently active subscriptions, and hosts only from its current read
grants. Unauthenticated requests write nothing. Store-derived evidence is
reused for up to 5 seconds (`evidence_observed_at`) only while the principal's
grants and active subscriptions are unchanged; the lease state is always current.

| Field                     | Meaning                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `overall`                 | `ok` only when every journey is verified **and** the lease is `held` or `not_applicable`; `unverified` (no fresh evidence yet), `degraded` (a journey is failing, or the lease is `renewal_failing` or `unknown`), `down` (edge lease lost)                                                                                                                                                      |
| `build`                   | `package_version` from the installed `package.json`, `source_commit` and `build_run` from a release's `BUILD.json` (null in a source checkout)                                                                                                                                                                                                                                                   |
| `runtime.central`         | Central Worker/DO `release_version` and `epoch` read when the edge started (central edge only)                                                                                                                                                                                                                                                                                                   |
| `native.t3_build`         | Installed T3 build; `null` until adapter negotiation (#62) observes it                                                                                                                                                                                                                                                                                                                           |
| `runtime.lease`           | `held`, `renewal_failing` (renewals failing, lease not yet expired), `lost` (fenced/refused/expired), `unknown` (no renewal evidence yet), or `not_applicable` for the standalone sidecar; with the last renewal, expiry and last failure reason                                                                                                                                                 |
| `journeys.ask_eddie`      | Last completed question/answer loop (asked → read → replied → acknowledged by the asking agent), whether its wake webhook was delivered (`wake_delivered`; Eddie may have found it by polling), and the stage the newest attempt reached; `stuck` names the oldest request holding the journey in `failing`                                                                                      |
| `journeys.event_delivery` | Last 2xx acknowledgement and last failed attempt, timed when the outcome happened: local attempts from the audit log, central ones from the central result time stored on the replicated delivery record. Terminal central receipts without a result time are counted in `untimed_central_receipts` and never count as fresh. A 2xx proves receipt by the callback endpoint, not agent execution |
| `hosts`                   | The newest stored diagnostic per readable host                                                                                                                                                                                                                                                                                                                                                   |

Journey states, evaluated in this order:

- `failing`: a terminal delivery outcome (`stopped`, `revoked`) with no later
  acknowledgement, even while other deliveries are still pending; or an attempt
  with no later success has been unfinished for more than 15 minutes (any unanswered or expired ask-Eddie request; a pending or
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

The check validates the report (state values, hosts, and that `overall`
matches its own lease and journey states) before trusting it.

Exit codes: `0` every journey verified, `1` degraded/unverified/down, `2`
unreachable or refused. Set `KADENCO_STATUS_URL` for a non-default listener.
It only observes organic evidence; generating test traffic against a live
install is a separate, owner-approved step.
