# Local staging and deployment boundary

The central edge composition now runs through the real sidecar lifecycle in local
fixtures. Its encrypted record change journal, revision-checked DO commits,
receipt reconciliation, durable HTTP/SSE responses and native/callback checkpoints
are exercised with workerd and the official MCP client. The build emits a Node
ESM edge bundle and a source/checksum manifest; CI retains the matching public
runtime and Worker. No production compiler or TypeScript loader is required.
Existing grant/identity mapping, secret custody, old-writer retirement, activation
and live acceptance remain separate unfinished deployment requirements. This
does not promote the staging Worker or claim a production replacement.

Native cf build/prebuilt dry-run qualification is now available in
[cf-staging.md](cf-staging.md). Production activation and the default deploy refusal
remain unchanged. That document supersedes the old assumption that only Wrangler
configuration exists; it does not claim a deployed service or complete relay replacement.

The control-plane candidate is not a replacement for the existing sidecar.
Read `deployment/coverage.json`: it enumerates every currently registered MCP
tool and the unported event, collaboration, caller, diagnostics and budget
boundaries. `replacement_ready` is false. Opaque row migration does not implement
those services. No new observation or delivery loop is started by these tools.

From the repository root, use Node22/24 and locked dependencies:

```sh
npm ci --ignore-scripts
npm run build
cd packages/control-plane
npm ci --ignore-scripts
npm run types
npm run typecheck
npm test
npm run operator:fixture -- bootstrap
```

Bootstrap prints a newly created temporary fixture directory, never a key.
Replace FIXTURE below with that exact returned path:

```sh
npm run operator:fixture -- quiesce FIXTURE
npm run operator:fixture -- snapshot FIXTURE
npm run operator:fixture -- migrate FIXTURE
npm run operator:fixture -- rollback FIXTURE
```

All commands refuse unmarked/non-temporary paths and symbolic links. They never
accept a production database, credential path, host, callback or Cloudflare
account. Test-only trust is generated under the fixture root. `migrate` runs a
local workerd/SQLite DO, authenticates every segment, exhausts inventory and
verifies that activation is refused. `rollback` exports CURRENT fixture records
to a new candidate, refuses overwrite, and never restores an earlier snapshot.
This is a fixture rollback rehearsal; it does not export live central receipts
or authorize production rollback. The automated harness adds a newer receipt
after the snapshot and verifies its retention.

`npm run deploy` always refuses. `deployment/wrangler.disabled.jsonc` points to
an entry that returns 503, has no bindings/routes and starts no DO migration.
It is only a source/dry-run artifact, not permission to provision a script.
The regular candidate config is used for local tests; it must not be deployed
by substituting production secrets or changing its staging flag.

Production sequencing requires a separate approved plan, current account and
host verification, least-privilege trust provisioning, completed distributed
budget/event/collaboration service ports or an explicit narrowly limited pilot,
enforceable old-writer retirement, current-state rollback qualification and
independent acceptance. Changing a DO epoch cannot fence the installed alpha6
executable. Callback URL/signing identity and all existing subscription/grant
identities must survive unchanged; uncertain effects are reconciled, never
replayed. No production activation implementation exists in this revision.
