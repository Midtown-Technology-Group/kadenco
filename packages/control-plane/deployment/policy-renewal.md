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
- its hosts, operation scopes and thread budgets are the same or narrower, and
  its daily limit is the same or lower;
- each native grant keeps an existing host and purpose with the same or
  narrower project and provider scope. The fingerprint may differ, and the grant
  expires no later than its principal;
- only an owner or executor expiry moves later, to at most 366 days from apply
  time, and never for a revoked principal. Migration principals keep their
  separate one-time reauthorization path.

Principals can be dropped. The fleet must not change. The operation is refused
while a recovery freeze holds the control plane (`quiesced`), because recovery
compares exact policies.

## Procedure

1. As an existing owner, POST `/policy_renewal_challenge` with `{}`. It returns
   the current revision, the exact current policy (token hashes and grant
   metadata only) and the digests of the current and deployed policies.
2. Update the edge's local policy for the new routes and expiries, keeping the
   change staged until step 5. Build the next revision offline with
   `projectRenewalPolicy(currentPolicy, localPolicy, bootstrap)` from the edge
   bundle. It re-projects the owners' and executor's grants from the local policy,
   sets their expiry to `bootstrap.serviceExpiresAt` and leaves everything else
   unchanged. It needs the owner and executor bearers only to check their hashes;
   it creates no credential.
3. Deploy that policy as `AUTH_POLICY` (`encodePolicy`), through the normal
   release promotion's secrets file. Authentication uses the deployed policy's
   token hashes, which renewal does not change.
4. POST `/renew_configured_policy` with one persisted request UUID:

   ```json
   {
     "request_id": "ONE_PERSISTED_UUID",
     "expected_revision": 0,
     "expected_policy_sha256": "DEPLOYED_POLICY_DIGEST_FROM_THE_CHALLENGE"
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
