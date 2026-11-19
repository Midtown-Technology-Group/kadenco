# Renewing the central policy

Every central principal carries an expiry, and the durable policy can otherwise
only be tightened: `tighten_policy` refuses a later expiry, and owner enrollment
is capped at its sponsor's expiry. Native grant fingerprints also bind the exact
local routes, so moving the edge (new SSH or executable paths, a host dropped)
produces fingerprints that central refuses until they are reconciled. Renewal is
that reconciliation. It must run **before** the owner expires: an expired
principal can no longer authenticate.

## What renewal can change

`renew_configured_policy` adopts the deployed `AUTH_POLICY` as the next durable
revision (`current + 1`), like owner enrollment: the operator-deployed policy is
the independent approval input, and an MCP caller cannot supply one. It is
refused unless, for every principal in the configured policy:

- the principal already exists, with the same token hash and role, and it gains
  no migration or state-custody authority;
- its hosts, operation scopes and thread budgets (including their expiries) are
  the same or narrower, and its daily limit is the same or lower;
- each native grant replaces its own distinct prior grant (a one-to-one
  matching): same host and purpose, the same or narrower projects and providers,
  and an expiry no later than its principal and, unless that principal's expiry
  is being extended, no later than that same predecessor. An expired grant has
  no successor that outlasts it. A successor cannot sit
  beside the fingerprint it replaces or borrow another grant's scope or expiry,
  and a retained fingerprint can only renew its own predecessor. The fingerprint
  may differ;
- a fleet-wide executor stays fleet-wide (host links admit only executors bound
  to a single host, so narrowing to one host would grant link access);
- only an owner or executor expiry moves later, to at most 366 days from apply
  time, never for a revoked principal and never for one that has already
  expired (renewal does not revive). Migration principals keep their
  separate one-time reauthorization path.

Renewal never makes a stored binding usable again. If a live subscription
(as rebound), command or host-link reference cannot be used by its recorded
owner or by an executor under the current policy (a fingerprint retired earlier, a grant tightened below the binding's
expiry, an expired grant or principal) but could be under the configured one, the
renewal is refused. Unsubscribe or otherwise retire such records first.

Principals can be dropped, but the initiating owner must stay live so it can
reconcile its receipt. The fleet must not change. Renewal runs only while the
control plane is `active`: staging may hold an uploaded recovery import and a
freeze compares exact policies. A receipt is bound to the initiating owner's
credential hash, not only its principal ID.

## Standing subscriptions

A subscription stores the observation binding it was created with, and queued
callbacks, cursors and receipts are all authorized against it. In the same
transaction as the policy write, renewal moves every active subscription whose
binding tracks its owner's only observation grant for that host (same
fingerprint, revision and expiry) to that owner's only renewed observation grant
for the host: new fingerprint, revision and expiry, everything else unchanged.
That is exactly the binding the edge derives once it restarts with the renewed
policy, so nothing has to be resubmitted. The receipt counts these as
`rebound_subscriptions`. Nothing is revived: inactive or ended subscriptions,
subscriptions whose owner is expired or revoked, expired bindings and ambiguous
ones (several observation grants for one host) are left alone and fail closed.

## Procedure

1. As an existing owner, POST `/policy_renewal_challenge` with `{}`. It returns
   the current revision, the exact current policy (token hashes and grant
   metadata only) and the digests of the current and deployed policies.
2. Update the edge's local policy for the new routes and expiries, keeping the
   change staged until step 6. Build the next revision offline with
   `projectRenewalPolicy(currentPolicy, localPolicy, bootstrap)` from the edge
   bundle. Every enrolled owner must be in `bootstrap.ownerTokens`, because the
   executor's grants are rebuilt from those owners. It refuses while an owner
   holds a live dedicated verification scope: those stay capped at the old
   ceiling while the restarted edge would bind at the new one, so let them expire
   or remove them first: the deployed central policy must hold no live
   verification scope for any configured owner or executor. Re-preparing a
   verification request re-derives the same live scope, and deploying a policy
   without it does not change the durable policy: remove it from the durable
   policy with `tighten_policy`, or wait for it to expire. A scope that runs to
   the owner's own expiry leaves no renewal window: that owner cannot be renewed
   through this path. Every enrolled owner must be renewed together; retire an
   owner (even an expired one) with `tighten_policy` before renewing the rest. Verification-
   only hosts are kept. It re-projects the owners' and
   executor's grants from the local policy,
   sets their expiry to `bootstrap.serviceExpiresAt` and leaves everything else
   unchanged. It needs the owner and executor bearers only to check their hashes;
   it creates no credential.
3. Deploy that policy as `AUTH_POLICY` (`encodePolicy`), through the normal
   release promotion's secrets file. Authentication uses the deployed policy's
   token hashes, which renewal does not change.
4. Stop the edge. While it runs on the old policy it derives the replaced
   bindings, which central refuses after renewal, so deliveries processed in
   between would be quarantined. Drain and reconcile commands first: a command
   reserved under a replaced command grant is refused afterwards, and an edge
   retry of the same request with a newly derived binding is an
   `idempotency_conflict`.
5. Challenge again. Require the same current revision and digest as step 1, the
   next revision as `configured_revision`, and `configured_policy_sha256` equal
   to the digest of the policy built in step 2. Persist those values with one
   request UUID before committing. Then POST `/renew_configured_policy`:

   ```json
   {
     "request_id": "ONE_PERSISTED_UUID",
     "expected_revision": 0,
     "expected_policy_sha256": "CONFIGURED_POLICY_SHA256_FROM_THE_SECOND_CHALLENGE"
   }
   ```

   Use the exact current revision. Authentication, fencing, the policy write and
   the audit receipt share one Durable Object transaction. After an uncertain
   response, POST `/policy_renewal_receipt` with the same `request_id`; never
   retry with a new UUID.

6. Only after a confirmed commit (the renewal or its receipt returns
   `committed: true`), install the staged local policy and the new
   `serviceExpiresAt`, then start the edge. If the receipt shows no commit and
   the fence still holds (same revision and deployed digest), retry the renewal
   with the same request UUID. Until a commit is confirmed, keep the edge stopped
   and the old local policy installed; never start it on the renewed bindings
   against an unrenewed policy.

Command records keep the binding they were authorized under; renewal does not
rewrite history. `receipt` re-authorizes that binding against current grants, so
after renewal a command bound to a replaced command grant can no longer be read
through it, exactly as when its grant expires. The outcome stays in the
command's central row and the edge's own records; the audit log records only
that a receipt was recorded. This is why no command
may be in flight: an uncertain command could not be reconciled afterwards.

A renewal grants no new host, provider, project or role; it changes when access
ends and which routes it is bound to.
