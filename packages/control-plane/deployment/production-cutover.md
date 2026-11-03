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

`prepareManagedRecovery` is the actual Windows transfer entry point. It invokes
the physical retirement verifier before and after a read-only SQLite transaction,
checks the operational digest against the unchanged archive descriptor and passes
the authenticated segments to operational adoption. It returns an encrypted
archive in memory; it does not write the source or upload anything automatically.

`operator/run-edge.mjs` is the compiled runtime's supervisor entry point. Its one
argument is an absolute nonsecret configuration path. A private inherited stdin
pipe supplies JSON with `stateKey` (original base64 key), `executorToken`, and
`ownerTokens` (pairs of original owner ID and original bearer). Bootstrap fields
and original/cache/config paths belong in the nonsecret configuration. Secrets
never enter argv or a persistent JSON file. Startup failures are sanitized and
never fall back to the historical local writer. The backend composition retains
the original projection/fleet helper/local-followup choices and all original
authorization checks. The existing private supervisor continues to own the
tunnel, caller reverse forwards, private custody and process lifecycle.

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
Use the explicit `migration` role with `migrationAuthority: true`, zero command
budget, no scopes/native grants and no state-custodian privilege. This role permits
only status, authenticated recovery transfer, freeze/export and activation receipts.
It cannot revoke principals, tighten policy, issue native operations or acquire an
edge lease. Unknown future operations fail closed. Existing owners retain their
original permissions; this does not promote a caller to owner.

Use `encodePolicy(JSON.stringify(policy))` for the `AUTH_POLICY` binding. Cloudflare
[limits each binding, including secrets, to 5 KB](https://developers.cloudflare.com/workers/platform/limits/#environment-variables); the observed full six-host policy
does not fit as plain JSON. The versioned gzip/base64 transport is bounded before
upload and during decompression. `decodePolicy` restores the identical policy
before the existing parser validates it; persisted policy and authorization logic
use the expanded object. Do not reduce grants or omit principals to fit the wire.
Plain JSON remains accepted for smaller policies and existing installations.
Never place bearer values or the original encryption key in source, logs or CLI
arguments. Preserve original callback signing and all six standing subscriptions.

Acceptance must separately record source/CI, immutable release, Cloudflare
deployment, quiesced import, physical retirement, activation receipt, original
MCP/portal/tunnel paths, each fleet route, callback receipt and actual agent result.
An always-on executor and laptop-loss recovery remain independent runtime tests.
Neither green CI nor this activation API establishes those outcomes.

For callback acceptance evidence, `outbox_receipt` reads an exact central outbox ID
and epoch using the existing owner or executor identity. It returns only state,
attempt count and HTTP status; it rechecks current subscription ownership,
authorization and expiry. `delivery_acknowledged` never proves agent completion.
This read does not claim, send, retry or revive a delivery. Migration credentials
cannot use it. A missing receipt is not permission to replay an uncertain event.

During upgrades, distinguish Worker traffic rollout from Durable Object code adoption.
Cloudflare defaults to deferred object code updates (up to five minutes). Read
back the target operation after that window before declaring the new handler live.
A fenced edge remains fail-closed; restart the same qualified edge with its existing
journal and current central state. Do not replay uncertain operations or restore
an obsolete cache. See https://developers.cloudflare.com/changelog/post/2026-10-30-durable-objects-deferred-code-updates/ .
Central receipt reconciliation is read-only at the control plane and bounded per
cycle. Only validated terminal receipts update the existing local delivery view;
local revocation or changed central identity cannot be overwritten.
