# Existing-thread speed

`read_thread_options` returns exact host/thread/project selection, live provider
speed support, fingerprint, active run identity and classification. It uses only
existing credentials; no auth session is issued/refreshed. The fixed native MCP
handle requires an existing read+operate credential because the native configure
endpoint serves both reads and writes. Remote native authorization remains in
force. Unknown or unavailable model/provider metadata remains unknown. An absent
serviceTier is Standard only when live metadata explicitly defaults to default.
Model names containing flash, reasoning effort and permission modes are not speed.

`set_thread_speed_standard` accepts only standard, exact host/thread, expected
fingerprint and stable UUID. It changes only serviceTier priority to default for
a live Codex model advertising both values. It requires existing host, project,
provider and unexpired command grants and consumes the shared existing daily
command budget. No-op/rejected preparations do not consume that budget. It never
sends a message, starts/resumes a turn, changes runtime mode or alters schedules.
Other providers and unknown options are not mutated. All other selection fields
and modes are checked before and after the native write.

The native configure endpoint has no caller UUID or atomic compare-and-swap.
Two preflight snapshots reject observed drift, but cannot eliminate the remaining
native check/write race or prove that another writer's intervening update was
not overwritten. Receipts explicitly report native_compare_and_swap false.
A crash or lost response after submitting is uncertain. Reusing the same UUID
reconciles observed state without another native write; observation after an
uncertain send is not proof this request caused it. Never retry under a fresh UUID
without independently resolving whether the previous mutation happened. Changed
arguments under a reused UUID conflict. Receipts persist encrypted before I/O.

The adapter does not call any provider turn-reconfiguration or interruption API.
It records active run IDs, but active_run_speed_verified is false: thread-option
readback alone cannot establish a running provider turn's service tier. Qualify
apply-on-next-turn behavior against each installed native provider implementation
before claiming the current turn changed or retained its original tier. There is
no automatic monitor invocation, bulk write, credential expansion or new monitor.

Fleet conversion is an owner-controlled operation: enumerate every inventory
page including settled/snoozed/subagent threads, read options, retain exact Fast
candidates, apply individually with stable receipts, and report per-host gaps,
unknown/unsupported counts and before/after evidence. Enumeration is live, not
an atomic fleet snapshot. One host failure must not become a fleet success claim.

get_thread_speed_receipt reads the stored owner/host/thread/UUID receipt under current grants even when the native source is offline. It does not claim current state; current_state_checked is false.

Local installed native qualification (operator observation, not a universal version
promise): CodexAdapterV2.planSelectionTransition uses turnScopedSelectionTransition,
whose outcome is apply_on_next_turn. This supports preserving the current turn
while changing the saved selection. The adapter still reports running-turn speed
as unverified because option readback does not measure provider execution.
