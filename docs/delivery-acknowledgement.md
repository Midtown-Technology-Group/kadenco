# Delivery acknowledgement and stall diagnosis

Host-bound callers expose acknowledge_thread_delivery alongside the existing
passive tools. Supply exact thread_id, request_id and current run_id. The server
binds host and reviewer from the existing credential, checks the stored command
recipient and retained native run/message placement, verifies the active native
run and project using existing read credentials, then rechecks authorization.
It never issues an RPC credential, submits a turn or treats acknowledgement as
execution/completion. acknowledged_run_id is separate from the original native
accepted run, since a queued message can be observed in a different active run.

Missing run evidence returns delivery_run_unobserved: the reviewer must reconcile
the original receipt through its existing authorized path. Old completed runs
cannot be acknowledged by substituting the latest run. Duplicate acknowledgements
retain the original timestamp. Scope revocation during a source read fails closed.
No new host/thread enrollment, credential or execution grant is created.

caller.mjs, caller-mcp.mjs, agent-tool.mjs and the Pi extension use the same host
schema. The universal CLI supports ack_delivery. Its client accepts the legacy
five-tool surface and the new optional acknowledgement; unrelated tools remain
rejected. Legacy cached provider sessions are not proof of refreshed discovery.
An operator must update already-owned launcher/catalog entries through its normal
installer, preserving credentials and unrelated config. The terminal path can be
validated immediately without restarting an active agent. Do not switch to an
owner/reviewer credential when a caller credential is denied.

The existing worker diagnostic also attributes the maximum synchronous local
span to a fixed operation name (policy, backend.read, or a Store operation), with
process CPU deltas. Only timings/names are recorded, never SQL, arguments, paths,
exception text or request contents. A backend.read span measures its synchronous
portion before returning a Promise, not network waiting. Nested Store transactions
can include child operations. These wall-clock measurements can include OS
preemption; they identify a path to investigate, not prove SQLite or CPU causality.
The read-only fleet status exposes the last completed worker measurement and age;
an in-progress cycle is not observed and an old sample is not a health guarantee.
No additional polling worker or permission changes are introduced.
