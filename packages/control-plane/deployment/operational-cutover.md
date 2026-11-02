# Operational state cutover with local historical archive

Owner decision: retain the original local DB as historical record rather than copy
historical audit/diagnostic rows into Cloudflare. This supersedes the requirement
to build streaming history transfer before cutover. It does not authorize dropping
current receipts/deduplication, budgets, policy, subscriptions or uncertain work.

```sh
npm run migration:preflight -- --source-db EXPLICIT_SOURCE_DATABASE --retain-local-history
```

This is an aggregate read-only check, not extraction or activation. It counts only
operational records plus one archive reference against transfer limits; historical
row counts remain visible. Default preflight/extraction still include history and
retain their existing refusal behavior. Unknown modes refuse.

The operator can supply `extractSnapshot` with a `retainedArchive.verify` callback
using `localArchiveReference` only after independently enforced quiescence and local
archive retention are established. All encrypted `records` rows transfer unchanged;
no command/receipt is discarded by age. Historical `audit`/`diagnostics` rows remain
in the local DB. The snapshot includes a `$history_archive` reference containing the
SHA256 fingerprint of existing main DB and WAL bytes, operational-record digest and
retained history counts. The reference is part of the authenticated snapshot manifest.
It carries no local path, keys or authority to start execution.

Archive reads are read-only; files are hashed with bounded buffers and retained
records are checked against operational-state limits before materializing them.
Extraction checks the archive against every transferred operational row and the
history counts, then re-verifies it before commit. Missing, changing, mismatched or
oversized evidence refuses and rolls back. An arbitrary callback is not independent
proof: operator control, immutable retention and real custody remain acceptance steps.

The local DB must stop receiving new relay writes and remain recoverable under the
existing key-custody arrangement. SQLite main and WAL files are one archive unit;
never delete a WAL or copy only the main file to make a checksum pass. Keep the archive
readable for historical investigation, but prevent the old alpha6 process/supervisor
from reviving as a writer. A retained archive is not permission to restart alpha6.

Staging and production activation remain separate. The deployed staging foundation
has no public ingress or production trust. The new source path does not enable its
hard-disabled activation endpoint, provision an executor identity or move signing
keys. Current central+edge receipt recovery and externally enforced old-writer fencing
must pass before production writes. After cutover, old local history stays historical;
rollback must use CURRENT new receipts/dedup/budgets, never the pre-cutover archive.
