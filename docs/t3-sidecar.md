# T3 Code sidecar contract

Kadenco is independently versioned and released from this repository. Its CI,
security settings, license and support surface live here. T3 Code remains the
native owner of projects, threads, runs, prompts, approvals and execution. No T3
source patch, bundled T3 checkout, replacement queue or shared release pipeline
is required. Integration failures are compatibility findings, not permission to
change native approval or authorization controls.

## Lifecycle and packaging

The runtime is TypeScript ESM (`src/*.mts`), compiled to `dist/*.mjs` with source
maps and declarations. HTML/CSS assets are copied alongside compiled modules.
Production uses the compiled artifact and locked production dependencies; no
compiler runs on service startup. Keep the artifact tied to its Git SHA and
lockfile, not a mutable source checkout. Retain a known-compatible prior artifact
for rollback without reverting the current encrypted receipt database.

`npm start` runs the standalone loopback profile. Operator supervisors can import
`startSidecar` from `kadenco/sidecar`; imports do not start listeners or install
signal handlers. Startup validates the live policy and private state permissions.
The returned handle exposes its address and idempotent asynchronous `shutdown`.
Startup failure releases owned resources. The CLI owns SIGINT/SIGTERM handling;
an embedding supervisor owns its own process lifecycle.

The environment key fallback is captured in private module memory and removed
from `process.env` before operator/native helpers run. Same-process retry/restart
can reuse it; explicit `stateKey` still takes precedence. A new environment value
on a later start replaces the fallback (and must validate normally). Startup
cleanup reports an aggregate with the original startup error as its cause when
cleanup also fails. Shutdown attempts every owned resource exactly once, and
authenticated stream requests resuming after shutdown are refused.

`backendFactory` is a startup-only composition hook for an operator's existing
reviewed helper adapter. It is code supplied by the process owner, never a remote
tool argument, config-selected module, enrollment mechanism or policy override.
All MCP authorization, exact-target/run binding, approval checks, idempotency,
event filtering and receipt reconciliation still run in Kadenco. The default
standalone factory continues to reject private helper startup profiles. Private
operator composition can now reuse the same public lifecycle instead of copying
the application entrypoint. Keep paths, identities and credential providers in
the private operator adapter.

## Discovery and native boundaries

Use native MCP tool/event discovery. Enumerate every authorized host and continue
inventory pagination until `next_cursor` is null, including empty pages. Report
unavailable hosts as incomplete coverage. The current native read adapter uses
supported MCP read APIs plus read-only orchestration projections. Optional command
delivery uses the existing native broker with explicit live grants; its protocol
is version-dependent. Qualify the actual installed T3 build before enabling it.
Never patch native T3 to satisfy Kadenco's expectations.

The `/healthz` endpoint means process liveness, not full fleet availability.
Official tunnel readiness is separate. Read fleet event status and encrypted
visibility diagnostics for host-level source, credential and transport health.
Do not silently change a directory or bootstrap authentication after a miss.
Private composition must explicitly select existing fleet files when upgrading
from different defaults; the public default is `~/.config/kadenco`.

Continue to distinguish storage, native submission, observation, agent
acknowledgement and completion. A webhook 200 only acknowledges delivery.
`continue_thread` starts or queues a new turn. Strict active-run steering remains
unavailable where the provider cannot atomically bind check and send.

## Type checking and tools

Vite+ retains formatting, linting and task execution. The pinned Rust `tsrs`
compiler builds output in fast mode. Both `tsrs` and the pinned Microsoft
TypeScript compiler must pass type checking; a negative fixture proves neither
gate silently disables diagnostics. The full behavioral suite runs compiled
output on Windows/Linux and Node 22/24, with synthetic browser acceptance.

This first migration checks every runtime module with `noEmitOnError`; it does
not claim strict typing of the entire legacy implementation. `strict` remains
false, and version-dependent native/persisted record shapes retain dynamic
fields. Policy and tool boundaries retain their runtime Zod validation, with
policy types inferred from that schema. There are no file-wide compiler
suppressions or unchecked production builds. Tightening the dynamic record
registry and implicit parameter types is remaining type-safety work, not a reason
to weaken runtime checks. `tsrs` is currently a beta toolchain dependency; retain
the reference compiler gate and qualify upgrades through this repository's CI.
