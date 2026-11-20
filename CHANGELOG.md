# Changelog

Entries describe source candidates. A heading alone does not mean a tag,
GitHub Release, artifact or fleet rollout exists; consult release evidence.

## Unreleased

## 0.1.0-alpha.26

- Add the Linux edge host files (`packages/control-plane/operator/linux/`): a
  systemd supervisor that reads its secrets from a secret-store REST endpoint at
  start and passes them to `run-edge.mjs` on private stdin, the unit (restarts
  wait out the 120 s central lease), a root control script for status, verified
  stop/start, manifest-checked release install and config install, and the SSH
  forced commands that fleet hosts use to bound the edge's key (Linux, and
  Windows through pre-minted read and read+operate delivery sessions because
  Windows OpenSSH cannot open key sessions for Entra ID accounts). The forced
  commands accept only the edge's exact request strings and never evaluate them;
  Linux revocation is limited to delivery sessions. The control script never
  follows links in the service-writable directory, vets archives before
  extraction and serializes changes. Runbook:
  `packages/control-plane/deployment/linux-edge.md`. No authorization changes.
- Fleet members update their Eddie caller automatically
  (`scripts/fleet-update.mjs`, [docs/fleet-update.md](docs/fleet-update.md)):
  an hourly systemd user timer or Windows scheduled task installs the newest
  published release only when GitHub attests its package was built by the
  release workflow on main from the commit in `BUILD.json`, checks the new
  caller against the live server, then switches a stable `current` link that
  provider catalogs launch through; rollback and a hold file are supported.
  The release workflow gains a separate `attest` job (main dispatches only) and
  the package now ships the Linux and Windows caller launchers and the catalog
  installer. Adds `sigstore` as an optional dependency for verification (it needs Node 22.22.2+, 24.15+ or 26+; the base package keeps its supported range). Releases up to
  0.1.0-alpha.25 carry no attestation and are never installed automatically.

## 0.1.0-alpha.25

- `livePolicy` forgets its cached value when a read fails to parse, and its
  test no longer assumes every write changes the file's timestamp (Windows
  file times tick about every 15 ms).

- Add an owner-only central policy renewal (`policy_renewal_challenge`,
  `renew_configured_policy`, `policy_renewal_receipt`). Every central principal
  has an expiry and the durable policy could only be tightened, so the service
  stopped for good at its ceiling, and moving the edge to new routes produced
  native grant fingerprints that central refused. Renewal adopts the
  operator-deployed `AUTH_POLICY` as the next revision only when it keeps every
  principal's identity, role and custody, adds no principal, host, scope or
  budget, and matches each renewed native grant to its own predecessor (same
  host and purpose, no wider scope). Owner and executor expiries may move up to
  366 days from apply time; grants and thread budgets cannot outlast what they
  replace unless their principal is renewed. Renewal runs only while active,
  keeps the initiating owner live and binds its receipt to that owner's
  credential. It is refused if it would make any stored binding (subscription,
  command, host-link reference) usable again. In the same transaction, standing subscriptions whose observation
  binding tracks the replaced grant move to the renewed grant, so queued
  callbacks and receipts keep working after the edge restarts.
  `tighten_policy`, owner enrollment and `subscribe_central` are unchanged. `projectRenewalPolicy` builds the next
  revision offline from the current policy and the edge's local policy. See
  `packages/control-plane/deployment/policy-renewal.md`.

## 0.1.0-alpha.24

- Defer routine fleet coverage updates to the 60 s heartbeat (#73). After
  alpha.23, hosts that fail every pass (rising failure count) and hosts that
  page through a large inventory (advancing cursor) still rewrote their coverage
  record every ~12 s cycle, so requests still queued behind a central push.
  The latest pass is now kept in memory, used by the fleet loop and status, and
  written only on a material change (state, reason or read outcome; scanning
  starting or stopping; failures starting or recovering; first completion or
  success) or on the heartbeat. After a restart, paging resumes from the last
  persisted cursor; observation is idempotent.

## 0.1.0-alpha.23

- Stop pushing unchanged fleet coverage to central every cycle (#73). Each
  ~12 s pass rewrote every host's coverage record just to refresh its
  timestamps, and every record write is replicated to central before the next
  HTTP response, so requests (`/healthz` and MCP calls alike) regularly queued
  behind a 1-8 s central push. A pass that changes nothing material now
  refreshes the timestamps at most every 60 s (coverage turns stale only after
  300 s). State, reason, cursor and failure changes are still written at once;
  state and reason changes also emit a coverage event, as before. Timestamps
  from skipped passes carry into the next write and into status.

## 0.1.0-alpha.22

- Cut the remaining edge stalls (#73). Every policy read re-read the config
  file, `JSON.parse`d it and ran the full schema validation (~1.5 ms on the
  production config), and fleet observation reads policy several times per
  thread per cycle, so a cycle spent seconds of CPU there. The parsed policy is
  now reused while the file's identity (size, modification and change times,
  inode, device) is unchanged and for at most 5 s; any edit or replacement is
  read on the next call and an invalid file keeps failing. The trusted per-read validation hook still
  runs every time and each caller still gets its own copy (~0.23 ms per read in
  total).

## 0.1.0-alpha.21

- Fix multi-second edge response times (#73). Every HTTP request, `/healthz`
  included, first joined the in-flight lease renewal: a central round trip of up
  to the 8 s lease-call deadline, and the 2.5 s heartbeat keeps one in flight
  most of the time. A transient renewal failure also answered 503
  `edge_lease_unavailable` while the lease was still valid, which the
  supervisor counts toward a restart. A held lease that the synchronous fence
  accepts, with more than a quarter of its TTL left (at most 10 s), now admits
  requests at once; only near expiry does a request wait for a renewal.
  Mutations still renew through the coordinator and every effect still passes
  the send-point guard.

## 0.1.0-alpha.20

- Fix edge event-loop stalls of 1-6 s every worker cycle (#73). Each cycle
  decrypted and parsed every delivery record (14k in production) to find the
  few pending or centralized ones. `Store.select` now caches each record's
  match verdict keyed by its ciphertext signature (fresh random nonce and GCM
  tag on every write, by any writer), reads signatures from a new covering index
  (`records_signature`) and decodes only matching rows. Only verdicts are
  cached, never plaintext. On a 14k-record store a scan drops from ~200 ms to
  ~25 ms. The index is additive; older releases simply maintain it.

## 0.1.0-alpha.19

- Longer edge lease, so upstream network drops no longer restart the edge.
  After alpha.18, the remaining restarts (about every 10 minutes) coincided
  with 30-90 s losses of connectivity to Cloudflare from the edge's network:
  renewals kept retrying but the 30 s lease expired first. The Worker now
  grants a 120 s lease (reported as `ttl_ms`), the edge's own bound is 120 s,
  and the startup claim retry covers 150 s. Trade-off: a killed or crashed
  edge's successor waits up to 120 s for the old lease before it starts.
  Deploy the Worker before the edge, as before (an alpha.18 edge keeps its
  30 s bound against the new Worker). To roll back to a Worker that grants a
  shorter lease, stop the edge first.
- Remove the picomatch audit exception (GHSA-fc5q-39xc-vjpf): npm audit no
  longer reports it, so the audit gate flagged it as stale. Audit is clean.

## 0.1.0-alpha.18

- Fix the central edge restart loop seen in production after alpha.17. Renewals
  had a 4 s deadline against a 10 s lease, while Durable Object round trips run
  at about 2-3 s, so two slow renewals in a row expired the lease and the edge
  exited. The Worker now grants a 30 s lease and reports `ttl_ms`; the edge
  judges expiry with the reported TTL (never longer than its own bound,
  10 s if a Worker reports none). Renewals get an 8 s deadline, and the startup
  claim retry covers 45 s. Normal replies have ample room and an occasional
  timeout is absorbed; two consecutive timeouts can still exhaust the lease.
  Deploy the Worker before the edge, as before. To roll back to a Worker that
  grants a shorter lease (alpha.17 or earlier), stop the edge first.

## 0.1.0-alpha.17

- Fleet monitoring now requires only the principal's current read scope
  (`readHosts`, with project limits): `t3.fleet.activity` discovery and
  subscription, `get_fleet_event_status`, pending-question observation and
  delivery, and event history (host-level `coverage_changed` history is readable
  by any reader of that host; thread events keep the project check). It no
  longer disappears when a command grant expires. Commands, answers and
  continuations keep their own expiring host/provider grant, checked
  immediately before any effect; monitoring never authorizes execution
  (#55, owner-approved).
- Recover the central edge from lease loss without operator action (#57). A
  startup claim fenced by a predecessor's unexpired lease is retried with the
  same instance for up to 30 s instead of failing into the supervisor restart
  loop. Lease renewals use a 4 s deadline, well under the 10 s lease, so one
  slow request cannot consume the lease. A running edge whose generation is
  irrecoverably lost now exits with code 75 for a prompt restart, instead of
  serving 503 until a health probe kills it. Fencing and no-replay are unchanged.
- Latch irrecoverable lease loss in the shared renewal path: no further central
  calls (including the shutdown flush), and a synchronous effect guard refuses
  native dispatch and webhook POSTs at their send points. Signals and lease loss
  share one bounded exit (75 wins, key always zeroed). Edges now require the
  Worker to advertise `edge_lease_instance` before any claim, so deploy the
  Worker first: an older Worker would let a new claim displace a live edge.
- Add authenticated, read-only `GET /status`: build identity, runtime mode, edge
  lease state (held / renewal_failing / lost with the last failure reason), the
  last verified ask-Eddie and event-delivery round trips with freshness and the
  stage a stuck attempt reached, plus per-host last observation. It stays
  reachable while the edge lease is lost. `npm run status` checks an installed
  runtime and exits non-zero unless every journey has fresh evidence. Startup
  logs the real package version instead of a hard-coded one.
- Bind edge leases to process instances so a standby sharing an executor cannot
  steal a live generation. Preserve legacy leases during the schema upgrade and
  retain generation fencing across process takeover and lost-claim responses.
  This prepares HA; it does not install or activate a second production edge.

## 0.1.0-alpha.16

- Return the public subscription identity in central delivery history while
  retaining the internal host/thread key for authorization and receipt lookup.
  Fixes fail-closed history reads discovered during alpha.15 live verification.

## 0.1.0-alpha.15

- Expose exact-event delivery history from retained central/edge audit and current
  receipts, with owner/scope checks, bounded pagination and explicit evidence gaps.
- Attribute central HTTP diagnostics to bound principals and originating MCP
  requests without storing URLs, tokens, payloads or arbitrary errors. The scoped
  read-only view does not claim fleet-wide GitHub quota accounting.
- Record the six public-repository scout dispositions and the observability goal.
  No upstream runtime, event store, scheduler or code is imported.

## 0.1.0-alpha.14

- Add a resumable maintainer release command that binds one build request to an
  immutable source, qualifies extracted artifacts, and reconciles publication
  before retry. Keep the existing account and private promotion boundary.
- Report the deployed package version from the Durable Object and sanitize
  supervisor startup failures into explicit reasons and fingerprints.
- Prepare the existing Windows-edge / Cloudflare deployment scope for beta;
  always-on PVE, guest sharing acceptance and automatic goalkeeper remain excluded.

## 0.1.0-alpha.13

- Add an owner-only operator path to reauthorize an existing expired migration
  principal once for at most one hour. Preserve token, hosts, recovery-only role
  and all other policy fields, with transactional drift checks and a durable receipt.

## 0.1.0-alpha.12

- Reactivate the exact current frozen recovery state with current authority,
  snapshot digest, audit watermark and fresh managed-writer retirement evidence.
  Preserve receipts and fence stale epochs without reimporting local history.

## 0.1.0-alpha.11

- Reconcile central callback outcomes into existing local delivery views without
  resending events. Keep centralized passive requests pending until a receipt
  proves acknowledgement or stopped delivery; never imply agent execution.

## 0.1.0-alpha.10

- Read central callback receipts without claiming agent execution or exposing event
  payloads and signing details. Recheck current owner/executor scope and revocation.

## 0.1.0-alpha.9

- Bound and encode authorization policy transport to fit Cloudflare's per-binding
  limit without removing principals, scopes or expiry. Expanded policy validation
  and persisted authorization remain unchanged; plain JSON stays compatible.

## 0.1.0-alpha.8

- Restrict temporary migration credentials to explicit import, recovery and
  activation operations. Deny native execution, general administration and
  future unlisted operations; preserve ordinary owner/executor behavior.

## 0.1.0-alpha.7

- Cloudflare SQLite coordination and encrypted operational replication with
  durable request reconciliation, exact grant bindings and no uncertain replay.
- Protected operational adoption, local history retention, managed-writer
  retirement checks and challenge-bound activation receipts.
- Compiled central supervisor and read-only transfer entry points; matching
  central Worker/edge artifacts now ship through the immutable release lane.
- Source and package qualification do not establish production cutover or HA.

## 0.1.0-alpha.6

- Match native guest join and conversation screens: name/Join form, compact title
  and expiry, conversation bubbles and bottom composer. Display names remain
  separate from verified identity and authorization.

## 0.1.0-alpha.5

- Forward negotiated sharing request/receipt tools through the stdio caller, with
  a full terminal-to-MCP regression. Alpha.4 backend/UI shipped without this path.

## 0.1.0-alpha.4

- Durable exact-thread sharing requests with owner scope review, explicit approval,
  decline, duplicate suppression and uncertain-outcome reconciliation.

- T3-inspired sharing and access-review dialogs with explicit scope, cancellation,
  keyboard focus management and no authorization changes.

## 0.1.0-alpha.3

- Qualify immutable release packages in clean CI with production-only installation,
  sidecar lifecycle smoke tests, source/build identity, SBOM and checksums.

Next consolidated candidate after the source-only alpha.2 deployments:

- Email-bound first-time guest invitations, explicit join, in-conversation proposal review and revocation.

- Host-bound delivery acknowledgement and exact native-message evidence recovery.
- Worker timing diagnostics, fewer repeated grant checks and bounded I/O yields.
- Coalesced fleet observations and replaceable pending coverage notices.
- Owner sharing onboarding with a colleague sign-in link and exact-thread grant guidance.
- Version/changelog consistency checks and documented release/rollback cadence.

Protocol compatibility identifier remains 0.11.0. Event-loop stalls remain an
open limitation; no exactly-once agent execution guarantee. Current-run live
acknowledgement success still requires fresh organic delivery evidence.

## 0.1.0-alpha.2

Historical experimental source baseline: TypeScript sidecar, typed build and
separate CI. Multiple later deployments reused this package version and were
identified by exact source SHA. They are not retrospectively retagged or
claimed as published release artifacts.
