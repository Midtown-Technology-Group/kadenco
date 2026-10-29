# Fleet visibility and recovery

Fleet coverage describes observation, not execution authority. A successful
complete scan is retained with its timestamp across transport failures. Status
reports the latest read (`ok`, `partial`, `failed`), consecutive failed pages,
last successful inventory read, last failure, and complete-scan age separately.
A complete scan older than five minutes is labeled `stale`; this is a reporting
threshold, not a credential expiry, retry delay or availability guarantee.

After a complete scan, a failed transport/inventory read reports `degraded`
with the sanitized reason immediately. Recovery remains degraded while pages
are reconciled and becomes `available` only after a complete successful scan.
Without any complete scan, failure remains `unavailable`. Authentication,
authorization and identity failures remain `unavailable` even with retained
coverage. Revoked/expired monitoring scopes are excluded as before. Retained
coverage never authorizes a new read or delivery.

Coverage events carry a revision, latest read state and last complete timestamp.
Repeated identical failures update status without additional events. At delivery,
an unsent revision older than the stored coverage revision is marked
`superseded` and audited, rather than waking an agent with obsolete status.
Already submitted webhooks cannot be recalled. Legacy events without revisions
retain their delivery behavior. Event IDs, signing, callback validation, retries
and acknowledgement semantics are unchanged. HTTP acknowledgement is not agent
execution. No failure triggers credential refresh, task execution or a new
monitor.

The existing encrypted worker diagnostic now measures the entire cycle,
including aggregate observation and delivery, and records bounded numeric
`event_loop_delay_max_ms` using Node's event-loop histogram. It samples across
the previous idle interval and current cycle, resets after each cycle, and is
disabled at shutdown. The existing retention applies. Operators can correlate
this with per-host SSH/native-read timings; it does not identify the cause of a
stall by itself. No request bodies, credentials or exception text are captured.

Before sampling, the worker yields one 20 ms sampler interval so a final synchronous stall can be recorded. Success and failure diagnostics both retain the measurement. This adds a sampling yield to the existing cycle, not a source retry.

Fleet per-thread authorization now checks the exact requested host directly,
retaining live principal/read/project/provider/command-grant checks without
rescanning sibling host grants. It caches no authorization or policy. Synthetic
resolved-promise host pages yield to I/O at least once per 16 visited threads,
preventing a burst of otherwise synchronous observations from starving timers.
No retry, sleep/backoff, subscription or task-execution behavior changes.
