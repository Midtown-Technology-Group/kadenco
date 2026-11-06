# Edge HA preparation

The supported production runtime is still one active edge. Do not start a second
production adapter merely because both hosts can connect to the control plane.

Each new runtime generates a UUID for its process lifetime and includes it in
lease acquisition and renewal. A live lease fences another process even when it
uses the same executor principal. Repeating an initial claim from the same
process preserves the generation while that lease remains live. Renewing an
expired or superseded generation refuses; a running process never silently
reacquires after losing ownership. Replica writes retain generation fencing.

The schema adds a nullable instance column without replacing the existing lease.
A live legacy lease can still renew; an instance-aware runtime waits for its
expiry. Once an instance-aware lease is live, legacy acquisition cannot steal it.
Deploy the Worker first: the new runtime refuses a lease response without its
matching instance. Do not bypass that refusal during an old-Worker rollout.

This is necessary fencing, not a completed HA supervisor or native exactly-once
guarantee. Before activating a primary/standby pair, qualify:

- Explicit host mappings. `local` must keep referring to the original authorized
  native host; it must never silently become whichever machine runs the adapter.
- Secure custody for existing state encryption, owner/caller credentials,
  callback signing and tunnel identity. Windows DPAPI ciphertext is not a Linux
  credential installation. Never generate substitute signing keys to avoid this.
- A lease-aware Linux supervisor that keeps standby admission closed, stops its
  tunnel/listeners on fencing and preserves existing service ownership.
- Current-state rehydration and immutable attempt recovery. Do not clone a live
  SQLite cache or restore an old replica over new central receipts. A missing
  local journal cannot authorize replay of a central uncertain command.
- The same ingress/caller bindings on either active host without competing
  reverse forwards. Test the actual installed tunnel transport and backend.
- Primary crash, partition, delayed old-process revival, failure after a native
  effect but before receipt, revocation and recovery while the original desktop
  is unavailable. Use synthetic commands until live cutover is authorized and
  its trust/custody prerequisites have been reviewed.

Keep the historical Windows DB in its existing custody. State-key placement on
another host requires an explicit custody decision; this source change does not
export any key, install a service or change executor policy.
