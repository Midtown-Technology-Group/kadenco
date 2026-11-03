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

### Current frozen-state reactivation

`captureRecovery` fences the current epoch and returns a signed/encrypted current
snapshot. To reopen that same SQL state, use `resumeManagedRecovery` with the
verified archive digest, its frozen epoch, and a separately persisted stable
resume UUID. It uses `recovery_resume_challenge`, `resume_recovery` and
`recovery_resume_receipt`; it does not reimport the initial historical snapshot.
The original import activation path remains unchanged.

The control plane recomputes the current bounded recovery digest transactionally,
binds the exact freeze owner and audit watermark, and requires a fresh short-lived
signed report from the existing physical managed-writer retirement verifier.
Current principal authorization, expiry and revocation apply to every call.
An executor or another recovery owner cannot reopen the freeze. A successful
resume advances the epoch once and persists an immutable receipt. Old edges stay
fenced; restart only the qualified edge with the returned epoch and existing
journal. A matching receipt reconciles an uncertain response without repeating
an external effect. No native command or callback is replayed by reactivation.

Stop the edge before the physical ingress probe. Preserve the current archive and
all receipts. If late command receipts change the audit watermark, the captured
snapshot is no longer current and reactivation refuses. Reconcile that state and
prepare a fresh freeze explicitly; do not forge a matching watermark or reuse an
obsolete snapshot. A challenge expires after two minutes and is not silently
renewed. Snapshot bounds remain 100,000 rows and 32 MiB.

A valid recovery principal is required. Expired migration credentials are not
renewed, promoted or replaced by this API. Persisted policy rotation or new trust
requires its own reviewed authorization; replacing an environment binding alone
does not replace the persisted policy. The production entry does not mint keys.

### Explicit one-time recovery reauthorization

With a separate explicit owner approval, the authenticated owner may use the
non-MCP operator endpoints `migration_reauthorization_challenge`,
`reauthorize_migration` and `migration_reauthorization_receipt`. This is the only
exception to tightening-only policy updates. It renews an existing expired
`migration` principal once in its retained lifetime, never creates a principal
or token, and never clears revocation. The target must retain zero command budget,
no operation/native grants, no custody privilege, and hosts within the owner scope.

Read the challenge with `principal_id`, then persist one exact request containing
`principal_id`, stable `request_id`, `expected_revision`,
`expected_principal_sha256`, `previous_expires_at`, `expires_at` and an
`approval_reference`. Expiry must be in the future, at most one hour from apply,
and no later than the acting owner's expiry. All target fields except expiry
remain byte-for-byte equivalent in the decoded policy. The revision, policy,
receipt and audit update commit in one transaction. Quiesced fleets refuse a new
authorization change. Do this before freezing recovery, not during its watermark.

Reconcile `migration_reauthorization_receipt` with the exact principal/request
after an uncertain response. Never generate another UUID or expiry to retry.
Identical replay returns the immutable receipt; another extension is refused.
Only after a matching committed receipt may the operator update local credential
expiry metadata, preserving the existing encrypted bearer. No Worker binding
replacement is needed. Current-state recovery retains the authorization receipt
and single-use fence; older archives lacking the new table fail closed.
