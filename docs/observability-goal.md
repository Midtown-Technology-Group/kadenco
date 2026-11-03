# Delivery and recovery evidence

This is the fresh observability goal approved after the six public-repository
scouts. The earlier production-deployment goal remains unfinished; alpha.14 is
published separately and this source work does not qualify its deployment.

## Finish line

Expose a bounded, read-only delivery history through the existing owner MCP
surface, using retained audit and receipt truth. Recheck current owner, host and
project access. Preserve subscriptions, grants, approval controls and uncertain
commands. Show source, pagination and evidence limits. A dispatch permit, webhook
acknowledgement, agent acknowledgement and completed execution are distinct.

Add redacted attribution to the central HTTP transport Kadenco owns. Capture the
bound principal, operation, request correlation, duration and response category;
never tokens, URLs, payloads or arbitrary errors. It is not a fleet-wide GitHub
usage monitor or an estimate of quota spent by other programs.

Acceptance: owner isolation and revocation; restart/recovery readback; duplicate
and out-of-order evidence; bounded pagination and explicit source changes;
secret-marker exclusion; diagnostics failure cannot alter/retry an operation;
no source reads, webhook posts or native execution caused by history reads.

## Scout dispositions

| Prior art                                                                                               | Decision                                                                                                                                                                                                                                                                                                          |
| ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Svix](https://github.com/svix/svix-webhooks/tree/03e3488fb1f3300efd6f42ad370fc6778a75b464)             | Adopt the separate message/attempt inspection vocabulary. Scout implementation reads failed; no code reuse established. Manual redelivery is excluded.                                                                                                                                                            |
| [Temporal](https://github.com/temporalio/temporal/tree/8ac42361480ce7df37aec4adab8d4358e8e1f278)        | Reuse the recovery-timeline and stale-generation test ideas. Existing Kadenco fencing stays authoritative; no engine adoption.                                                                                                                                                                                    |
| [DBOS](https://github.com/dbos-inc/dbos-transact-ts/tree/54f3eb4fe1618cd3019384c74baabf7c815949c9)      | Compare reserve-before-await and compatibility invariants. One receipt is not proof of one external effect. Its version-scoped recovery does not diagnose Kadenco's failures.                                                                                                                                     |
| [Happy](https://github.com/slopus/happy/tree/e68ac4001dc7b96bc4468c34fc179ef1e8cd79c8)                  | Review scoped uniqueness and after-commit notification patterns against existing sharing. Do not copy friendship semantics or infer that opaque message encryption prevents checking external ownership metadata.                                                                                                 |
| [Context Forge](https://github.com/IBM/mcp-context-forge/tree/12e91c9f77c5ac942ffadb3503781dd536219b5e) | Adopt fixed-field attribution/redaction principles. Ingress throttling is not upstream GitHub quota accounting; no generic gateway or new limits.                                                                                                                                                                 |
| [Cloudflare Agents](https://github.com/cloudflare/agents/tree/1f3bd9215239ccd973da87506d4771ac13a20bd2) | Defer event-store adoption: MCP stream replay and durable completion-webhook history are different concerns. The parent independently inspected the pinned event-store implementation; final POST cleanup and unbounded standalone GET retention do not match this receipt-history requirement. No code imported. |

These are bounded scout reports, not independently executed upstream tests.
No upstream code has been copied. File-level attribution and license review are
required if a later change actually imports code. No new scheduler, credentials,
resources, subscriptions, automatic nudges or native replay is in this goal.

## Rollout boundary

Source, CI, merge, artifact, deployed code and independent runtime acceptance are
separate. Existing audit records cannot reconstruct missing historical response
bodies, per-attempt HTTP codes, or agent execution. Local-only diagnostics may
be absent after replacing the edge cache; never claim historical completeness.

## Read-only interfaces

`get_event_delivery_history` accepts `subscription_id`, `event_id`, optional
`limit` (1-100), and the previous response's `next_cursor`. The cursor is bound
to this exact delivery and its central/edge source. Changing sources requires a
fresh read; the API returns `history_source_changed` instead of mixing sequence
spaces. Existing active subscription, owner and host/project checks still apply.
Expired/revoked subscriptions or access are denied, as with central receipts.

Central rows mean `claim_processed`, `dispatch_permitted`, `result_recorded` or
`source_stop_recorded`. A processed claim may have been denied; it is not proof
of acquisition. Rows retain audit ordering, not a reconstructed wall-clock order
or invented attempt IDs. The current receipt is separate and can be newer than
the page. Edge-local historical HTTP results have the retained status code.
Neither source claims agent acknowledgement or completion. No additional audit
history is generated or migrated; queries cover at most seven retained days.

`get_relay_request_diagnostics` is exposed with the central runtime binding.
It accepts `after_sequence` and `limit` (1-100). Current central owner authority is
checked before reading. Results are central HTTP calls whose bound principal or
originating MCP principal matches the reader. A page may be empty while its
`next_cursor` advances past other principals' records. System executor calls
without that originating context are not attributed to a user. Records use the
existing encrypted seven-day/25,000-row diagnostics retention and stay on the
edge; replacing that cache can remove them. An upstream numeric
`x-ratelimit-remaining` value is an observation, not a per-caller quota delta.
No other program's requests are intercepted.
