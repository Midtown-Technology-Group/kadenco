# Host-local outbound connectors: implementation sequence

Package `0.1.0-alpha.16`; source-only work based on PR43
`b0393b570716d88bfae6ba094f496d5750675f41`, with current main security gates
`535a222f6ad2654dbdc060bb3e141add5966e184` retained. PR43's process-instance
lease fencing is a dependency, not evidence of HA. No running configuration,
cloud resource, access grant, credential or standing subscription changes here.

## Target and invariants

Each existing allowlisted **T3 instance** owns an outbound authenticated link to
the existing Cloudflare control plane. A stable `host` identifies that native
instance/service route, not just a physical computer or transient IP. Multiple
T3 instances on one machine need distinct stable bindings and journals. A new
process has a new connection UUID; that UUID fences a session, not authenticates
a host. Host authority comes from the existing server-verified principal and
current policy. The source prototype refuses broad multi-host executor identities.

The logical mesh is `T3 A -> Cloudflare <- T3 B`, with the same pattern for every
additional instance. There is no requirement for an all-pairs physical network.
Links and catch-up advance independently; a lost desktop/host connection must
not tear down other links. Connections grow linearly, not quadratically. Cloudflare
remains a coordination dependency; cloud failure must hold effects rather than
create independent local writers. Owner/fleet coordination is still serialized
in the existing DO. Capacity/sharding needs measured qualification; this is not
a claim of unlimited throughput or a decision to provision new namespaces.

Connectivity never grants execution ownership. A connected host, successful
page acknowledgement or observed native projection is not a command permit,
proof of queue emptiness, execution or completion. Preserve original host/thread,
request UUID, current originator authority and immutable native receipts. Unknown
submission stays unknown, with read-only reconciliation and no resend/new UUID.

## Reversible slice implemented now

`packages/control-plane/src/host-links.ts` supplies a synchronous SQL protocol for
host-bound sessions and immutable references to **existing** authoritative requests.
Its context is supplied by a trusted authenticated server, not decoded from body
role/name fields. A trusted reference lookup must resolve the original owner,
host, thread and binding. Publisher/receiver scope, principal expiry and originator
authority are rechecked. A receiver can query status only for its own connection.
Read/ack mutations require the exact host, principal, connection and generation.

Session leases last ten seconds, capped by principal expiry. Lost open responses
reconcile that exact connection without a second open. An expired/replaced UUID
cannot re-register. Host A can expire while B renews. Persisted session history
retains fencing across reconstruction. These are **connectivity leases only**;
the existing fleet-wide execution lease is unchanged.

The protocol retains up to 256 pending references, 4,096 total references and
256 historical connection IDs per host, refusing growth at the limits rather
than deleting deduplication/fencing evidence. Pages contain at most 32 references,
with an 8-KiB frame limit and a 48,000-byte item budget inside the existing 64-KiB
HTTP limit. Host/thread IDs are exact strings capped at 200 characters;
request/connection IDs must be UUIDv4. Unsupported historical identities are held,
never renamed or given a substitute UUID to evade these bounds. The prototype is
not a history migration or replacement for the existing receipt lookup.
Unbounded operation requires reviewed compaction; reaching a limit is visible
backpressure, not permission to discard unknown outcomes. No runtime budget or
access grant has changed.

`host-connector.ts` reuses the existing `centralTransport` contract. Its caller-driven
tick has one in-flight operation per local connector. A separate encrypted Store
inbox commits references and cursor in one transaction before acknowledgement;
it refuses less-than-FULL SQLite synchronous durability. It validates exact
host/connection/generation and returns `page_committed` plus `more`, not a claim
of full native scan or execution. Metadata pages can be fetched again after a
lost response. They are not native command resubmissions. A persisted unknown
command is never rewritten by this inbox. A journal bound to host A refuses B.

There is **no execution function, autonomous loop, new service, production HTTP
registration, new production schema creation or capability enable switch** in
this slice. The tests install the schema only in synthetic SQLite/Workers fixtures.
Adding these tables to the current production DO without updating its exact
recovery inventory would correctly fail existing schema validation. Do not do it.
The trusted lookup and authentication seam are fixture-tested, not a production
ingress qualification. Existing migrated Cloudflare state is reused conceptually;
no production snapshot was read or transferred.

## Remaining source integration sequence

1. **Admit connectivity through the existing Worker.** Bind its verified principal
   to one exact native T3 instance. Implement the trusted reference lookup from
   existing command rows and atomic reference publication alongside their state
   transitions. Keep control mode/epoch, revocation and policy checks; default off.
   Add schema-versioned recovery inventory/export/import and bounded compaction
   preserving active cursors and stale-session tombstones. This is source work,
   not an assumed owner approval blocker.
2. **Partition execution ownership.** Add host/request-level claims and begin
   fencing tied to epoch and current originator grant, then re-use existing
   consume/journal/native adapters. A link UUID cannot substitute for claim/begin.
   Do not instantiate the current fleet-wide `createEdgeRuntime` once per host:
   its singleton lease and whole-fleet replica would conflict. Partition cache,
   observation and mutation ownership explicitly, retaining uncertain attempts.
   An unknown attempt must hold its original host/thread execution lane across
   reconnect or failover. A new UUID/generation cannot escape that hold. Expiry
   cannot retract an already-issued native permit; reconcile its possible effects
   before admitting a successor on that lane.
3. **Complete the receipt/event path.** Resolve each stable UUID to its exact
   native message ID and run ID, keeping submitted, accepted/queued, observed
   running, completed, refused and unknown distinct. Add host-local event cursors,
   bounded replay, pending-question routing and callback-outbox reconciliation.
   Reconnection never re-executes an uncertain native operation. Connectivity
   catch-up alone does not prove a completed source scan or callback delivery.
4. **Remove all desktop ingress dependencies.** Route owner/caller MCP and
   collaboration through reviewed always-on ingress, preserving existing principal
   identity, scope denials, guest isolation, expiry, callback URL/signing identity
   and current per-command budgets. Replace Windows SSH/reverse-forward routing
   with exact host-local native routes. Specify supported connector packaging,
   lifecycle/backoff and endpoint/build attestation. Do not infer that a proposed
   PVE/remote02 edge host is itself the correct native T3 service endpoint.
5. **Review and qualify, then request runtime promotion.** Normal CI/security and
   actual review precede any service installation or source deployment. Verify
   existing host-scoped identity availability; if absent, exact provisioning and
   scope need owner/security authorization. None was requested or created here.
   Live installations, control-plane update, old-writer retirement and cutover
   each remain outside this source-only request.

## Minimum acceptance before declaring Windows removable

| Boundary          | Local evidence in this slice                                                              | Required promotion evidence                                                                                                           |
| ----------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Independent links | Two synthetic hosts coexist via real HTTP transport and Workers SQL                       | Simultaneous approved native instances, attested builds/routes, independent outbound links                                            |
| Host loss         | A partition/expiry leaves B renewing; A later reconstructs its inbox                      | Disconnect desktop/one host under approval; other hosts retain native reads, permitted writes and callbacks                           |
| Stale connector   | Expired/replaced generation and old UUID refused, tombstones persist                      | Revived old process gets no new permits; reconcile already-permitted effects and keep uncertain lanes held without duplicate dispatch |
| Scope isolation   | Cross-host cursor, broad identity, forged body fields and foreign replies refused         | Exact installed host/thread/principal/grant mapping, revocation/expiry/policy-change tests                                            |
| Unknown outcomes  | Lost open/page/ack and write rollback never invoke native APIs or rewrite unknown command | Lost native response before/after effect; original UUID resolves to exact message/run without replay                                  |
| Catch-up          | Encrypted inbox/central SQL reconstruction, bounded pages and per-host backpressure       | Event/subscription cursors, all six standing subscriptions and passive inbox retain identity and continuity                           |
| Ownership         | No native execution is exposed; existing singleton execution path unchanged               | Per-host claims/begin plus native fencing prove no second writer during failover                                                      |
| Ingress           | Not integrated                                                                            | Owner/caller MCP, collaboration, pending input and callback signing work with desktop absent                                          |
| Rollback          | Source modules unregistered; can remain unused                                            | Restore compatible code against CURRENT receipts, journals, generations/cursors; never an obsolete state snapshot                     |

Managed old-writer retirement must prove the old path cannot perform native
effects, including process revival. A DO epoch or signed assertion alone cannot
stop a legacy process with still-valid native access. Rollback must preserve new
receipts and fencing state, not revive an earlier generation or recreate a lost
attempt journal. No live HA, desktop independence or successful cutover is claimed.

## Follow-up: authenticated execution candidate (source only)

The matrix above records the first metadata-only slice. This follow-up adds a
fixture-qualified execution path; it does not qualify a replacement relay.

- Worker `link_*` routes reuse actual bearer authentication, persisted current
  policy, activation/epoch checks and SQL transactions. `HOST_CONNECTORS=enabled`
  is required; no running configuration enables it. Single-host executor identity
  is mandatory. Connection liveness does not authorize an operation.
- Owner reservation retains the existing budgets, bindings and digest. The owner
  publishes an immutable AES-GCM encrypted signed envelope; the Worker never
  receives its encryption/signing keys. Associated data binds original
  host/thread/request/digest. No production key was provisioned or transmitted.
- `createHostLocalConnector` is exported in the existing edge bundle for an
  existing host lifecycle's cycle hook. It has no timer or listener. Its bounded
  drain uses the durable inbox, existing sidecar services and encrypted attempt
  journal. It is not wired into the running singleton production bootstrap.
- Claim/begin fence connection and command generations. A host/thread with an
  uncertain attempt refuses another request ID. Registered hosts and published
  commands cannot bypass this through legacy claim/begin; legacy receipt writes
  cannot settle connector commands. Current originator authorization is checked
  at begin, independently of executor liveness.
- Accepted observations are bounded and immutable, distinct from terminal
  receipts. Terminal settlement requires fresh matching native message/run
  projection evidence. It is host-reported observation, not independent proof
  of provider consumption or successful substantive work. Missing proof holds
  the lane; no automatic timeout releases uncertainty. Cancelled/rejected/no-op
  and operations without exact message/run completion evidence currently remain
  held for explicit future typed reconciliation, rather than being guessed safe.
- The exact legacy recovery inventory and complete connector inventory are
  supported versions. Partial/unknown inventories fail closed. Signed archive
  bytes are verified before upgrade. Restore stays quiesced, advances epoch and
  connector generations, expires sessions, and preserves UUIDs, tombstones,
  payloads and attempt identity. Old binaries that do not recognize these tables
  are not a qualified rollback target.

The combined local fixture now runs two host connections against the real
Worker/DO, fetches encrypted operations into encrypted host inboxes, invokes the
existing native command adapter with exact mock native arguments, reconstructs
SQLite journals after lost native responses, and loses a committed receipt
response. Neither loss causes a second native dispatch. The source composition
also suppresses settled inbox references on later cycles. Native transport is
mocked throughout; this is not a live-provider or installed-host test.

Remaining source coverage: integrate host-local observation/event cursors and
outbox ownership, pending-question routing, owner/caller and collaboration ingress,
and per-instance lifecycle packaging/attestation. The current singleton whole-fleet
replica cannot be installed unchanged on every instance. Extend typed settlement
for creation, answers, settings, follow-ups and definite non-submission outcomes;
mechanical adapter availability alone does not qualify their lane release.

Promotion gates: normal publication authority, exact-head secret/security scans,
CI and actual review; approved mapping to existing host-scoped identities and
configured per-host trust (availability unverified); reviewed per-instance startup
composition; compatible current-state rollback; then explicit runtime installation
and Worker update authorization. No new access, key, service or resource has been
created. Live acceptance must include simultaneous installed instances, loss of
one host with others unaffected, revived stale connector refusal, exact original
host mapping, uncertain native/receipt recovery, catch-up and current-state rollback.
The workerd pipe-abort diagnostic remains unresolved. Windows is not yet removable.
