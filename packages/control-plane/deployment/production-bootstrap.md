# Existing-service bootstrap

`dist/edge-runtime.mjs` exports `createProductionRuntime`, `projectControlPolicy`
and `projectVerificationPolicy`. These are operator composition functions, not
public MCP tools or a credential installer. The original sidecar owns listeners,
timers, native transports, authorization and shutdown. Its `runtimeFactory`
selects the central runtime without a local-loop fallback.

The operator supplies the exact fleet, active epoch, HTTPS origin, original owner
credentials, a separately approved executor identity, original encryption key and
absolute encrypted journal path. Owner credentials must match existing principal
hashes; caller credentials cannot become owners. The executor cannot reuse an
existing identity or credential. Inputs are captured before asynchronous work.
The central service must already be active at the exact epoch.

`projectControlPolicy` emits hashes and native grant fingerprints, never bearer
values. It preserves project/provider restrictions and clips service authority
to its approved ceiling. Mixed per-host budgets and exceptional providers that
cannot be represented faithfully refuse projection. Dedicated verification
scopes require `projectVerificationPolicy`: the original session authorization
and a read-only native preflight derive each exact scope. No arbitrary scope
objects or automatic trust provisioning are accepted.

Continuation, answers, creation, Standard speed and verification bindings reuse
the original service schemas and authorization methods. Native reads establish
exact project/provider/run context. Owned duplicate reservations can reconcile
offline; unknown legacy bindings fail closed. Original services still perform
their final dispatch checks. An uncertain native result is never resubmitted.

Observation retains original subscription identities and callback signing.
Task-finished events resolve host/thread through the original session grant.
Events without project metadata require an unrestricted original host read grant;
a restricted grant fails closed rather than guessing a project. Callback claims
carry the binding and it is revalidated after the durable checkpoint immediately
before posting. Revoking or changing a subscription during that wait stops it.

`spec/bootstrap.node.mts` exercises the compiled bundle, real SQLite DO, official
MCP client and original command service with mocked native transport. It verifies
single dispatch, duplicate reconciliation, uncertain no-replay and revocation.
This is source/local runtime evidence, not production acceptance.

`startProductionSidecar` is the supported supervisor entry point. Supply an
existing private cache directory, the historical state directory, configuration
path, matching original state key and the bootstrap above. The journal must be
`central-attempts.db` directly inside the cache. Real-path validation rejects
overlap, nesting and directory aliases between cache and archive. The original
sidecar invokes this validation on every policy read and before constructing the
writable Store. An inactive or mismatched central epoch refuses startup; no local
delivery fallback or signal handler is installed. The supervisor must await its
returned `shutdown()` on termination. These functions neither write configuration
nor provision trust or retire another process.

Still required before live use: reviewed immutable release, authenticated central
ingress and policy installation, approved executor custody, verified operational
state transfer, enforceable retirement of the legacy writer, activation and
current-state rollback. The staging Worker still refuses activation. No production
secret, state export, process retirement or deployment occurs through these tests.
