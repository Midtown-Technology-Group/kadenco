# Best-effort completion goalkeeper: prepared, disabled

The implementation belongs to the existing `Commands` service:

- `src/commands.mts`: `prepareGoalkeeper`, `goalkeeperState`, and the `goalkeeper`
  instance. The send adapter reuses `Commands.continue`, the existing expiring
  host/provider grant, budget checks and native dispatch/receipt path.
- `src/goalkeeper.mts`: persistent candidate, dispatch intent, cooldown, exact
  receipt reconciliation and continuation-entry check.
- `test/goalkeeper.test.mjs`, `test/commands.test.mjs`: synthetic fault/race tests
  and actual Commands/native-session integration without a native write.

There is no new owner, runner, timer, event subscription, monitor or public MCP
tool. Existing completion events and Eddie's judgment remain the decision input.
No production process, standing monitor or credential is changed. Preparation
does not activate a goal, authorize work or modify manual `continue_thread`.

## Persistent contract

`Commands.prepareGoalkeeper(owner, {host, thread_id, source_run_id})` first checks
the existing command grant and reads the exact native projection. The source must
still be latest and completed. It then atomically stores one encrypted candidate
keyed by principal, host, owner thread and source run. Duplicate observations and
processes sharing that Store receive the same persisted request UUID.

The candidate's states are `prepared`, `dispatched`, `accepted_queued`,
`observed_running`, `completed`, `refused`, and `uncertain`. The last observed
receipt stage remains separate when receipt availability becomes uncertain.
Dispatched intent is durable before submission; a crash there is ambiguous even
if no IO actually happened. Reconstruct and reconcile the same UUID. Neither a
missing receipt nor an exception permits another submission. Receipt identity
distinguishes a locally observed read-only guard refusal before entering the send
adapter: that refusal atomically releases only its own unbound lane clock and
retains the fifteen-minute cooldown. The refused source keeps its UUID and is
never resent; a later completed source can become eligible after cooldown. Any
failure after entering the send adapter remains uncertain, including an adapter's
own final guard error.

Receipt identity
includes principal, host, thread, source run, request UUID and any observed run.
Terminal state is immutable; an older accepted receipt cannot regress observed
running evidence. Accepted/queued is not execution or completion.

Default cooldown is **15 minutes per principal/host/thread**, consumed by an
attempt, not an observation. Clock rollback relative to that attempt holds the
candidate. A continuation's own completion is suppressed under the same
authorization revision, preventing an automatic no-op chain. Unknown or absent
remaining authorized work refuses. No delayed wake is installed; a caller may
later reconsider a held prepared candidate without creating a new UUID.
An unbound prior accepted/uncertain run suspends further automatic candidates
until its exact receipt can establish the run binding.

Atomic claims are proved across processes using one SQLite Store. This is not a
claim of global multi-replica compare-and-swap. A central runtime must retain its
single active writer and checkpoint the claim before enabling dispatch. The
current production checkpoint adapter deliberately refuses activation.

## Dispatch and entry

The service reads exact current state before admission and again after the
durable dispatch checkpoint. The adapter invokes a final guard before the
existing send. It suppresses newer/active runs, known queued work, native
questions/approvals, missing authority, stop/snooze, unknown safety state and no
remaining authorized work. Unknown public queue visibility is explicitly allowed
only as best effort; it is never described as an empty queue.

The fixed queued instruction requires the recipient to recheck current state and
latest user instructions, do nothing when stopped/snoozed/paused/superseded,
already covered or awaiting required input/approval, and continue only previously
authorized Kadenco work. It confers no new scope or permission. `enter` additionally
requires the exact bound running continuation and unchanged authorization. It
returns a narrow decision; it does not execute substantive work itself.

Tests use a synthetic adapter that can preserve stop through enqueue and enforce
entry. They demonstrate the contract, not a capability of installed native T3.
A manual run or Stop after the last read remains a race unless the native
interface preserves that decision. The fixed instruction alone is not an
enforced entry hook or a substantive-work deduplication guarantee.

## Exact native blocker and activation state

The installed native adapter uses `orchestration.getThreadProjection`, then
`orchestration.dispatchCommand` with `dispatchMode.type=queue_after_active`.
The existing capability response explicitly says source-run attribution is not
an atomic stale-run fence. Public reads expose snooze/settled/archived and pending
request observations, but pending-request count is not queue-empty evidence.

No verified durable explicit-user-stop marker is available through this projection
contract. No supported dispatch argument binds a preserved stop/snooze revision,
and no required continuation-entry callback revalidates current user controls and
authorization before the recipient executes work. The production adapter thus
uses `stopped:null`, does not invent goal-work authority from a native permission,
and has both `preservesStopThroughSubmission` and `enforcesContinuationEntry`
fixed false. Its activation checkpoint refuses. Agent arguments cannot enable it.

Unattended dispatch remains disabled until those actual interfaces exist and are
independently verified. Residual duplicate-turn risk was accepted; overriding Stop
or permitting duplicate substantive work was not. This change does not advertise
atomic idle dispatch, exactly-once execution or a live deployment.

## Race evidence

| Required case                                                  | Deterministic test evidence                                                                                                            |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Duplicate event; concurrent atomic claims; restart after claim | One UUID across three separate processes; reopen and submit that candidate once                                                        |
| Crash before/after submission; accepted response lost          | Persisted intent and exact receipt lookup; no resend or replacement UUID                                                               |
| Receipt stages and identity                                    | Separate accepted/running/completed; terminal no regression; wrong owner/host/thread/source/request/run remains uncertain              |
| Delayed event; active/newer run; final-read competition        | Stale/read-time changes suppressed; explicit post-read race remains best effort, entry suppresses already-covered work                 |
| Queue visibility                                               | Known queued work refused; unknown queue remains unknown; no queue-empty claim                                                         |
| Stop/snooze before and during dispatch                         | Refuse before send; native fixture preserves the race; unknown control state refuses                                                   |
| Queued entry after Stop; changed authority/approval/no work    | Entry refuses without executing work; only exact authorized running continuation can pass                                              |
| Cooldown boundary and rollback                                 | Boundary minus one holds; exact boundary permits; rollback holds; own completion does not chain                                        |
| Expired/withdrawn scope; pending questions/approvals           | Fresh authorization/control fixture refuses; Commands preparation rechecks its actual grant                                            |
| Read/receipt outage                                            | Read outage refuses; receipt outage retains uncertain state without resend                                                             |
| Monitor/manual regression; audit                               | No subscription or command from preparation; existing Commands suite unchanged; audit stores UUID/state only, no message or error text |

The full native queue and enforced stop/entry races cannot be qualified live with
the current interface. No live continuation is sent as a test.
