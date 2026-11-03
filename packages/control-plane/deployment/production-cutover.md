# Production cutover boundary

This revision supplies operational adoption and authenticated activation. It is
not evidence that production has moved. The immutable release, private supervisor
composition, trust installation and actual cutover still require qualification.

`prepareLegacyRecovery` authenticates the source segments, preserves every
original encrypted record, and builds a recovery archive in disposable memory.
Inactive or expired subscriptions remain retained records, never live lanes.
Previously accepted or uncertain native commands become inert no-replay markers;
the SQL receipt holds only a reference to the encrypted original, not a prompt.
Audit and diagnostic history stay in the original local database. Its exact
`$history_archive` descriptor must be present in the imported operational state.

Use `uploadRecovery` with a stable import ID. Receipt lookup precedes commit
recovery. A successful import remains quiesced. Do not import the original
snapshot again after central writes: use CURRENT `captureRecovery` state for
recovery, including pending operations, dedup and immutable receipts.

The explicit `cf --mode production` profile targets `kadenco-control-plane`,
independently of the staging Worker and its SQLite lifecycle. Preview is refused.
It has authenticated HTTPS ingress and no embedded policy or bearer values.
Missing policy refuses requests before contacting a Durable Object; a matching
configured token must still pass current persisted authorization inside the DO.
Build and prebuilt dry-run are local qualification, not resource creation.

`activateManagedSource` first reconciles the stable activation ID. For a new
activation it obtains a short-lived challenge, invokes the actual Windows
managed-bootstrap retirement verifier, and signs the resulting observations with
the temporary migration credential. The DO checks origin, expiry, exact import,
epoch, archive descriptor, current policy and audit watermark transactionally.
It advances the epoch once and stores an immutable activation receipt. After an
uncertain response, query that same receipt; never repeat transfer or invent an ID.

The signature authenticates an operator report. It cannot stop an old process.
Before the verifier can succeed, the operator must drain/stop the exact managed
legacy process tree, relocate its original DPAPI credential bundle into new
private custody, and replace its old launcher with the exact retirement tombstone.
The verifier checks original credential-path absence, actual process inventory,
closed loopback ingress, unchanged archive bytes, and a real failed old-launcher
revival. It does not stop processes, move credentials or install the tombstone.
It refuses non-Windows hosts rather than treating synthetic probes as evidence.
This boundary prevents managed launcher revival; a privileged OS owner can
deliberately restore old code/keys and is outside that enforcement claim.

Create the approved central executor separately from existing caller credentials,
with authority bounded by original fleet grants and no later than their expiry.
Create the approved one-hour migration credential immediately before transfer;
keep it separate from native execution and existing Eddie owner/caller identities.
Never place bearer values or the original encryption key in source, logs or CLI
arguments. Preserve original callback signing and all six standing subscriptions.

Acceptance must separately record source/CI, immutable release, Cloudflare
deployment, quiesced import, physical retirement, activation receipt, original
MCP/portal/tunnel paths, each fleet route, callback receipt and actual agent result.
An always-on executor and laptop-loss recovery remain independent runtime tests.
Neither green CI nor this activation API establishes those outcomes.
