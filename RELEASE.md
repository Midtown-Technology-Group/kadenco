# Releases and versioning

Kadenco releases independently of T3 Code. Package SemVer identifies the shipped
sidecar; `backend_version: 0.11.0` identifies the compatibility contract and is
not a package release counter. A commit, green PR, tag, downloadable artifact,
selected runtime and verified live result are separate evidence stages.

## Cadence

- Merge focused changes as their gates pass. Do not release for every PR.
- While alpha, cut one numbered prerelease per coherent, deployable batch with
  an observable acceptance result. Review unreleased changes weekly when work
  is active; this is a maintainer checkpoint, not a new scheduled worker.
- Ship a qualified security or availability fix promptly rather than waiting
  for that checkpoint. Preserve all normal checks and source attribution.
- Never deploy changed package bytes under a previously shipped version.
  Increment `0.1.0-alpha.N` for compatible iterations in this alpha series;
  use a new minor series for incompatible pre-1.0 contracts, with migration
  notes. Stable compatible fixes/features use patch/minor respectively;
  incompatible stable contracts require a major bump.
- Move to beta when supported installation, update and rollback paths are
  repeatable. Stable 1.0 requires documented compatibility and end-to-end
  qualification of the supported read/event/acknowledgement paths. Do not use
  a stability label to hide unresolved visibility or delivery limitations.

`0.1.0-alpha.4` is the next candidate, adding native-inspired authorization UI
to the published alpha.3 package. Previous alpha.2 SHA-qualified
source deployments remain historical evidence; do not move tags or relabel them.

## Prepare and qualify

1. In a focused PR update `package.json`, both root versions in the lockfile,
   the changelog and current-version documentation together. Run
   `npm run release:check` (optionally append the intended `v...` tag). CI runs
   this read-only check; a matching version is necessary, not release approval.
2. Pass existing compiler/lint/test/audit/browser requirements and exact-head
   repository gates. Review the assembled candidate, including security and
   compatibility changes, rather than relying only on individual PR results.
3. Merge through protected main. Read back the merged commit and verify its
   tree against the qualified candidate. Prepare the tag only on that commit.
   For a resumed release, reuse a tag only after verifying its resolved commit
   and tagged package version. Abort on a local/remote mismatch; never move or
   force-push a published tag.
4. Build release artifacts in clean CI with pinned dependencies and
   `npm ci --ignore-scripts`. Build with the pinned compiler, then smoke-test
   the actual packaged output after extraction into a clean directory with
   production dependencies only. Confirm package version, sidecar import and
   synthetic startup/shutdown; compilation alone is insufficient. Include
   compiled output, declarations, license/notices, dependency inventory/SBOM,
   checksums, changelog and source/build identity. Exclude machine-local state,
   credentials, private operator adapters and development dependencies.
5. Publish an alpha/beta/rc as a GitHub prerelease. Never overwrite an attached
   artifact: compare its checksum on resume, reuse identical bytes, and stop on
   a mismatch. Reconcile an uncertain publication/dispatch response before
   retrying; no duplicate workflow dispatch or release on guessed failure.

The `Release artifact` workflow builds and smoke-tests packages on PRs, and can
be dispatched on protected main after merge. It has read-only repository
permissions and uploads one artifact set per exact SHA/attempt. The package
includes an npm shrinkwrap for production-only, install-script-free installation.
`BUILD.json`, the CycloneDX production SBOM and `SHA256SUMS` accompany the tarball.
PR artifacts qualify packaging only; publish the artifact built from the merged
main commit. Download it by exact run ID, verify all checksums and BUILD source,
then create an immutable `v<version>` tag at that source and a GitHub prerelease
with those exact files. Reconcile existing tag/release/assets before publication;
never replace an asset or move a tag. This uses the existing maintainer GitHub
connection; the workflow receives no publishing token or production secrets.

Run `node scripts/package-release.mjs` only in a clean Linux checkout after the
pinned build. It refuses a dirty checkout or an existing output directory. Its
smoke test imports the extracted package and starts/stops a loopback sidecar
with a synthetic backend, no sessions and no execution authority. This is
artifact lifecycle evidence, not real fleet or colleague acceptance. The package
remains private to prevent accidental npm publication.

## Deploy, observe and resume

Promote the same verified artifact, not a workstation rebuild. Keep a release
record containing version, tag, merged source SHA, artifact SHA256, producing
workflow/run/attempt, environment, previous release and rollback snapshot.
Check active deployment and permissions read-only first. Stage and qualify the
existing private supervisor/bootstrap integration separately; it is not part of
the public package. Preserve state, credentials, grants, callback identity and
subscriptions. Cut over through the existing owned supervisor procedure.

Wait for actual health/readiness before an MCP readback. Verify tool discovery,
existing caller bindings, retained subscription identities and coverage. A
webhook HTTP acknowledgement is not agent acknowledgement or task execution.
Record untested paths explicitly; use an organic delivery for live acknowledgement
proof instead of creating a new task merely for a release. Keep sustained worker
latency evidence separate from immediate startup readiness.

Resume from retained evidence after interruption. Before each mutation reconcile
its exact tag, workflow, artifact or deployment state; log timestamped stage
transitions without secrets. Use the existing T3 PR watcher for pending gates,
not a polling loop. Roll back to the previous verified source/artifact through
the existing supervisor procedure while preserving current durable state and
receipts. Recheck health, caller discovery and subscriptions after rollback.
Do not restore old state over new receipts or blindly resend uncertain work.

## Source of the process

Adapted from halocli's [release checklist](https://github.com/Midtown-Technology-Group/halocli/blob/dd1451f586ef2118d8823857ef1a95f2097cbfe7/RELEASE.md),
[resumable release script](https://github.com/Midtown-Technology-Group/halocli/blob/dd1451f586ef2118d8823857ef1a95f2097cbfe7/scripts/release.py)
and [release workflow](https://github.com/Midtown-Technology-Group/halocli/blob/dd1451f586ef2118d8823857ef1a95f2097cbfe7/.github/workflows/release.yml).
The useful lessons are immutable identity, artifact-level smoke tests, clean CI
builds and reconciliation before retry. Its Python/MSI/winget publication lanes,
local polling loops and environment-specific release actions do not apply here.
No halocli source or private evidence is copied into this repository.
