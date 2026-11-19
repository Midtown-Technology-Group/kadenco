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
- each native grant replaces a prior grant of the same host and purpose, one for
  one (a host/purpose pair never gains grants, so a successor cannot sit beside
  the fingerprint it replaces), with the same or narrower project and provider
  scope. The fingerprint may differ. A grant expires no later than its
  principal, and no later than the grant it replaces unless that principal's
  expiry is being extended;
- only an owner or executor expiry moves later, to at most 366 days from apply
  time, and never for a revoked principal. Migration principals keep their
  separate one-time reauthorization path.

Principals can be dropped, but the initiating owner must stay live so it can
reconcile its receipt. The fleet must not change. Renewal runs only while the
control plane is `active`: staging may hold an uploaded recovery import and a
freeze compares exact policies. A receipt is bound to the initiating owner's
credential hash, not only its principal ID.

## Standing subscriptions

A subscription stores the binding it was created with. After renewal the edge
derives the same observation authority with a new expiry (and, after a route
change, a new fingerprint). Its next `subscribe_central` for that subscription
is a conflict; it then reads the snapshot and retries with `expected_expires`,
which **rebinds** the subscription: the replacement binding must pass current
authority and keep the same project, provider and run, and the subscription's
identity, cursor and outbox history are kept. Every other field must still match.

## Procedure

1. As an existing owner, POST `/policy_renewal_challenge` with `{}`. It returns
   the current revision, the exact current policy (token hashes and grant
   metadata only) and the digests of the current and deployed policies.
2. Update the edge's local policy for the new routes and expiries, keeping the
   change staged until step 5. Build the next revision offline with
   `projectRenewalPolicy(currentPolicy, localPolicy, bootstrap)` from the edge
   bundle. Every enrolled owner must be in `bootstrap.ownerTokens`, because the
   executor's grants are rebuilt from those owners. It re-projects the owners' and
   executor's grants from the local policy,
   sets their expiry to `bootstrap.serviceExpiresAt` and leaves everything else
   unchanged. It needs the owner and executor bearers only to check their hashes;
   it creates no credential.
3. Deploy that policy as `AUTH_POLICY` (`encodePolicy`), through the normal
   release promotion's secrets file. Authentication uses the deployed policy's
   token hashes, which renewal does not change.
4. Challenge again. Require the same current revision and digest as step 1, the
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

5. Install the staged local policy and the new `serviceExpiresAt`, then restart
   the edge so its observation scopes take the new expiry. Commands whose
   fingerprints changed fail closed between steps 4 and 5.

A renewal grants no new host, provider, project or role; it changes when access
ends and which routes it is bound to.
