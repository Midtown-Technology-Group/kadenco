# Authenticated current-state recovery transport

The Worker accepts `stage_recovery`, `recovery_chunk`, `commit_recovery` and
`recovery_import_receipt` only for a current, unrevoked owner principal with
explicit `migrationAuthority`. Ordinary owners, callers and executors do not
inherit this permission. These are operator API operations, not public MCP tools.

`uploadRecovery` first authenticates the retained archive locally with its
existing key. It queries the exact import receipt before sending anything else.
It preserves a stable import ID, ordered chunk numbers, header and full digest.
An uncertain response is returned to the operator; there is no automatic retry.
An explicit same-input invocation resumes an interrupted upload or reads its
already committed receipt. The signing/encryption key never enters the request.

The destination must be staging at the expected epoch. Chunks are bounded to
100 rows / 60 KB; the full staged upload is bounded to 100,000 rows / 32 MiB.
Source counts, complete ordered digest and exact schema are checked before
restoration. The source policy must equal the currently authenticated destination
policy, so an archive cannot install broader authority. Revocation and expiry
are checked on every operation. A second principal cannot take over an upload.

Commit runs inside the existing SQL transaction. It removes staging records,
restores the verified inventory inertly and records an immutable import receipt.
A constraint or validation failure rolls back the entire operation, including
staging removal. Pending/claimed commands become uncertain; old edge leases are
fenced; receipts, deduplication and quota records survive. The destination remains
quiesced at the next epoch. This transport never activates it.

`spec/recovery.node.mts` uses actual authenticated Worker HTTP and SQLite Durable
Objects, including complete local Worker disposal/recreation with Miniflare 5's
`resourcePersistencePath`. It exercises lost commit responses, interrupted
uploads, changed duplicates, wrong epoch/actor, archive tampering, policy
replacement, revocation/expiry and rollback after partial SQL writes.

This completes the recovery transport, not the full production cutover. Legacy
operational-state preparation/adoption, enforceable old-writer retirement,
production trust provisioning and activation still require their own validation.
No real database, credential, native task or callback is used by the fixtures.
