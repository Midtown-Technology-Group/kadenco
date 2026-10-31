# Nightshift recovery qualification

Local source only. Production entry and activation remain disabled. No cloud
resource, installed credential/grant, callback identity or alpha6 process changed.

- `legacy-adoption.ts` validates the known Store kind set and decryptability through
  the existing edge codec, then transactionally adopts command/settings/follow-up
  evidence, current-day reservations, subscription target children and callback
  attempts/IDs. Caller first authenticates the snapshot and supplies exact existing
  policy/session targets. Unknown kinds/owners, missing targets, invalid lifetime,
  incomplete references and conflicting UUIDs abort. Passive collaboration/exchange
  records stay in the authenticated opaque snapshot and the single encrypted edge
  Store. Every adopted native command is non-dispatchable `uncertain`, never a new
  pending task. Callback secrets remain on edge; no decryption key goes to DO.
- `freeze_recovery` has a durable owner+expected-epoch receipt. Same unchanged
  request returns the same freeze; intervening audited writes invalidate it.
  Recovery export paginates all coordinator tables, including current receipts,
  budgets, policy, outbox, subscriptions and lease state. A security revocation or
  late authorized receipt invalidates the audit watermark rather than producing a
  silently mixed snapshot. Origin/executor authorization remains current.
- `recovery-archive.ts` signs bounded, ordered pages, full-header/row digest and
  table counts. Missing/tampered pages and stale epoch/watermark are rejected.
  `restoreInert` validates complete counts/schema before replacing an EMPTY local
  fixture destination in a transaction. Restored mode is quiesced with a new epoch;
  pending/claimed native commands become uncertain and budgets remain spent.
  No production HTTP restore endpoint or activation switch is installed.
- `leaseGatedHttp` checks long-lived responses after admission and destroys them
  on lease loss, clearing timers on close/finish. This is bounded failure detection,
  not instantaneous per-frame revocation, provider cancellation, or alpha6 fencing.
- `cancel_reserved` only releases quota before a begin permit. It fences the old
  generation atomically; uncertain/receipted native work cannot be refunded.
  `coordinatorForBridge` uses the existing settings read schema/fingerprint for
  no-op/denial preflight. `record_preflight` stores a non-dispatchable receipt even
  with zero remaining allowance, so already-Standard consumes no native quota.
  Native uncertainty is never reclassified from agent text. Other post-permit
  failures remain spent unless independently reconciled; no general refund path.
- Executor scope now validates exact project/provider/run/grant as well as host.
  Ordinary receipt reads retain scope restrictions; explicit migration authority
  can inspect/export historical state under its separate reviewed role. The flag
  defaults absent/denied and cannot be self-added through policy tightening.

Acceptance fixtures: real workerd export/reconstruction retains a receipt written
AFTER the original snapshot and an unresolved native command with both reservations;
partial restore leaves destination empty; revocation invalidates export; encrypted
legacy adoption rolls back after a late owner mismatch; signer bytes never enter
normalized subscription rows; live HTTP stream closes after lease loss; zero-quota
settings no-op never invokes the journal/native executor. Non-Error runtime faults
produce sanitized500 (the remaining PR20 review finding is fixed only here).

Remaining deployment gates are the account/host/cost/trust and enforceable old-writer
retirement decisions in the private decision packet. Source qualification still
needs actual-version/volume policy and schema mapping review, full current-state
archive custody/restore rehearsal on approved staging, exact-head Linux/Node22 CI,
and independent security review. Limits are explicit (10000 legacy fixture records,
100000 recovery rows, bounded packets/rows); unknown/oversized estates refuse rather
than truncate. This is not an assertion that historical production state was read,
that all legacy formats are accepted, or that independent HA acceptance occurred.
