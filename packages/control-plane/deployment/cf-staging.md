# cf staging qualification

The control-plane now has a native `cloudflare.config.ts`, pinned cf CLI and an
executable credential-free build/dry-run path. It does not enable production.

```sh
cd packages/control-plane
npm ci --ignore-scripts
npm run staging:qualify
```

This builds with mode `staging`, then validates the exact prebuilt output with
`cf deploy --prebuilt --dry-run --mode staging`. No upload/API request occurs.
The normal control-plane CI job runs this qualification. Modes other than exactly
`staging`, including an omitted mode, throw before deployment configuration exists.
Do not remove this guard to enable production or use the candidate's Wrangler
configuration to evade it. `npm run deploy` still refuses.

The new isolated Worker name is `kadenco-control-plane-staging`. Its `FleetState`
export declares SQLite lifecycle via `exports.durableObject`, and FLEETS points to
that same staging export. This is a NEW namespace, not an in-place conversion or
transfer of an existing production namespace. No routes, custom domains,
workers.dev URL, previews, schedules, production credentials or AUTH_POLICY are
configured. Without separately provisioned reviewed trust, HTTP requests remain
denied. Native command activation still refuses inside the service.

Why explicit conversion: the official `cf migrate --dry-run` reports that Wrangler
Durable Object migrations are unsupported. A blind CLI substitution loses lifecycle
semantics. The generated configuration was reviewed and replaced with the explicit
SQLite export. Existing Wrangler-based unit tests/builds remain available separately.
The pinned build dependency is cf1.0.0-beta.26; installing beta.22 introduced known
transitive advisories, whereas beta.26 audited clean during preparation. This changes
only the package dependency, not any global/fleet CLI installation or credential.

## Acceptance boundaries

Source fixtures already cover authenticated snapshot import, current receipt recovery,
partial/tampered archive refusal, origin/executor revocation, stale generations,
uncertain native outcomes and old cooperating-worker revival. The staging config
tests add exact-mode refusal, isolated lifecycle and absence of ingress/credentials.
These are local workerd/mock tests, not proof of a deployed fleet or laptop loss.

After source review/CI, a separately recorded deployment attempt must bind the exact
commit/build digest, current approved account and the staging-only resource name.
Check existing resource ownership first; never overwrite a similarly named resource.
Retain no public ingress and never upload synthetic test secrets as production trust.
Any future live staging rehearsal needs its scoped trust/custody and acceptance plan
reviewed before provisioning. Real production snapshots and keys are not fixtures.

For post-write recovery, freeze dispatch, reconcile native uncertainty and capture
CURRENT central state plus CURRENT single-edge journal, encrypted collaboration and
source cursors. Restore into an inert compatible destination, compare inventory and
establish one writer before reopening. The local archive tests do not yet qualify
actual production-volume/key-custody restoration. An old pre-cutover alpha6 snapshot
is never a valid rollback after newer central receipts exist.

The old alpha6 process ignores DO epochs. Cutover therefore requires an independently
enforced native/callback/restart boundary and negative revival probes across every old
route. Stopping a task, a signed statement or a lease alone is insufficient. Preserve
standing IDs, callback/signing identity and grants; no policy relaxation is implied.

References: [official migration procedure](https://developers.cloudflare.com/cf/wrangler/migrate/),
[prebuilt build deployment](https://developers.cloudflare.com/cf/projects/#deploy-a-prebuilt-build).
The source-only dry run is deliberately separate from deployment and runtime acceptance.
