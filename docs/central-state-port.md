# Central state port: reviewed boundary and staged implementation

Status: source candidate only. Production remains alpha.6 on the existing
laptop-owned sidecar. No central service, new principal, credential, subscription,
agent, native task or migration was provisioned. Existing callback/signing identity,
monitoring/passive inbox, target grants/expiry and encrypted state are untouched.
The owner handoff acknowledgement is retained privately with exact native
message/run evidence, separately from this implementation.

## Decision

Use one SQLite Durable Object per explicitly configured owner/fleet authorization
boundary, not per HTTP replica or host. Keep host/project/thread/run and original
request/subscription IDs inside that shard. Separate tenants must never share a
DO. Do not split one fleet until its atomic authorization/outbox/budget invariants
have been defined across shards. Reporting can project into D1 later. R2 is not a
shared writable SQLite file. Memory, including a host promise tail, is disposable.

The central Worker/DO owns coordination and eventually the existing state model;
always-on agents retain only their existing permitted native connectivity.
Moving the database alone does not remove laptop dependency: native host routes,
reverse caller forwards, portal backend and MCP serving must migrate too. A T3
host physically on the laptop is still unavailable when that host is off.

The existing Store API assumes synchronous node:sqlite reads, AES-GCM decode and
transactions throughout Bridge, Commands, ThreadSettings and collaboration. A
remote Store shim cannot honestly preserve those synchronous atomic sections.
Port operation-level transactional services and typed receipts instead. Profile
bounded queries, audit/diagnostic retention and async boundaries separately; the
23.6s store.diagnostic observation does not establish the underlying stall cause.

## Slice implemented

`packages/control-plane` is isolated from the sidecar release and live bootstrap.
The Worker binds callers to a configured shard; the DO persists the initial
policy and authoritative revocations, encrypted import envelopes, command
identity/hash, claims, executor generations, attempt state, receipts and audit.
No external native HTTP call happens inside its SQL transaction. Every mutation
rechecks principal expiry/revocation and host scope in transactionSync after all
request/auth awaits. IDs/payload identity are immutable and all body/batch sizes
are bounded. Old HTTP consumers cannot select an arbitrary shard.

Claims may be reassigned only before a one-use begin permit is consumed. Begin
atomically marks uncertainty before returning. After that, partitions, expiry,
consumer crash or lost responses never grant another attempt. Exact native
receipt lookup is required; recording an executor receipt explicitly does NOT
assert independent native execution verification. Outcome updates are immutable.
A generation/epoch fence rejects stale participating agents, including after DO
restart. Native systems do not understand this fence automatically: edge adapters
must still enforce native grants and reconcile original native request IDs.

The staged importer preserves original ciphertext/IDs verbatim, rejects changed
replays, commits batches atomically and cannot activate. It currently accepts
up to100records/64KiB body, with32KiB per envelope; larger records need a reviewed
chunk/manifest protocol. No source export, key transfer, full manifest verification,
quiescence certificate, production policy mapping, active outbox integration,
edge consumer, HTTP MCP/portal service or live route is implemented by this slice.
`activate` ALWAYS refuses with cutover_not_implemented. Tests set active state
only through fixture SQL in local workerd. There is no production activation flag.
This is a coordination port foundation, not a second scheduler or completed port.

## Migration and rollback acceptance gates

1. Inventory exact records/counts/IDs/ciphertext hashes and policy/key provenance;
   retain pending and uncertain native receipts. Export only after old writer is
   quiesced. Interrupted bounded imports resume under one migration ID, then
   independently verify complete manifests before any activation.
2. Establish an enforceable fence outside an old unmodified binary. A new epoch
   cannot stop an alpha.6 process that ignores it and still possesses valid native
   credentials or webhook signing access. Disabling a task alone is insufficient
   against arbitrary old-worker revival. Choose an approved retirement/egress or
   native credential custody boundary; preserve required identities deliberately.
3. Map existing principals/allowlists/expiry to central operations without turning
   passive host callers or monitors into execution agents. Validate Access/Entra
   portal and bearer MCP roles separately. Importing token hashes is not permission
   to install a new executor grant. No existing secret is uploaded by source work.
4. Qualify at least one always-on host's existing routes to authorized T3 hosts,
   including receipt reads during partitions and bounded reconnect replay. Any
   missing route/credential is a specific access prerequisite, not guessed access.
5. Switch only after old-writer fence, complete import, independent receipt/dedup
   verification and central readiness. Test crashes before/after effects and
   before responses, duplicate callbacks, stale generations, revocation during
   awaits, object restarts, interrupted import and laptop loss on real agent paths.
6. Once central state accepts writes it stays authoritative. Rollback re-points
   compatible executors/API code at CURRENT central receipts/dedup state. Never
   start a stale local snapshot. Before central activation, discard/rebuild only
   staging after reconciling its migration identity; do not alter live local state.

## Connectivity and provisioning boundary

Prefer direct HTTPS MCP on a Worker if the official SDK/runtime and existing
OpenAI consumer/auth contract qualify it; this can eliminate a tunnel hop. Preserve
current callback/signing and subscription identities. Otherwise retain the
existing HTTP tunnel identity with a compatible session backend. Official tunnel
HTTP active-active support is conditional; a shared queue selects a polling
consumer. Stdio must have one active consumer including restart overlap. A terminal
response404 is not permission to execute a tool again. These are protocol reviews,
not proof that the installed v0.0.16 binary/config supports a proposed deployment.
A read-only installed-profile check confirmed the existing loopback HTTP MCP
binding and no stdio command binding; it emitted booleans only. No tunnel
credential was printed, copied or changed. This does not qualify active-active
behavior of the installed binary.

Before live deployment we need a reviewed Cloudflare DO binding/resource/cost
boundary, an approved mapping/custody mechanism for existing auth/encryption and
signing material, an always-on executor with already permitted routes, and an
old-writer fence. No new credentials, broader grants, paid plan, public route,
secret upload, callback change or activation is authorized by this source PR.
Complete the missing source/consumer/migration gates before requesting a concrete
cutover approval; this list is not a request for general setup now.

## Evidence and continuation

Run `npm ci --ignore-scripts`, `npm run types`, `npm run typecheck`, `npm test`,
`npm run build` and `npm audit` in packages/control-plane. Tests use the current
Cloudflare Vitest plugin and real local workerd/SQLite, not a mocked Store. They
exercise competing claims, expired claim fencing, no uncertain replay, immutable
receipts, wrong roles/hosts, revocation, epoch change, actor reconstruction and
atomic interrupted import. Real effects/callbacks, encryption-key import,
independent execution verification, live agents, laptop loss and colleague join
remain unverified until their later integration slices. Existing sidecar CI and
security review remain required; central tests are included in the normal gate.

Primary references:

- https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
- https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/
- https://developers.cloudflare.com/workers/testing/vitest-integration/
- https://github.com/openai/tunnel-client/blob/master/docs/deployment/kubernetes-dedicated.md
- https://github.com/openai/tunnel-client/blob/master/docs/configuration.md
- https://github.com/openai/tunnel-client/blob/master/docs/protocol.md
