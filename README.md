# Kadenco

## Development checks

After `npm ci --ignore-scripts`, run `npm exec -- vp run check` and
`npm exec -- vp run test`. Vite+ uses native Oxlint/Oxfmt for formatting and
static analysis; warnings fail CI. Runtime source is TypeScript ESM, built with
pinned `tsrs` to JavaScript and declaration files in `dist`. Both `tsrs` and
Microsoft TypeScript must pass type checking. Tests retain Node's built-in runner
and run the compiled output. See [CONTRIBUTING.md](CONTRIBUTING.md) for synthetic
browser validation and [the sidecar contract](docs/t3-sidecar.md) for lifecycle,
integration boundaries and remaining dynamic types.

Experimental standalone release candidate, 0.1.0-alpha.2. No T3 source edits.

MCP tools for native T3 inventory/results, persistent signed events, explicit bounded delegation and durable receipts. Not a replacement agent, orchestrator, queue or memory system. Existing Eddie tool/environment names are retained as compatibility identifiers; they do not require an OpenAI dot. A persistent agent needs an MCP client plus a compatible wake-up runtime. OpenAI MCP Events is the implemented event protocol; other runtimes need compatible webhook ingress or explicit read-only polling. Basic MCP tool support alone is insufficient.

## Local setup

Use Node 22.18+ or 24.11+. Run npm ci, then npm exec -- vp run test (which builds first). For a build without tests use npm exec -- vp run build. Vite+ 1.4.0 runs the existing node:test suite; vp test is the separate Vitest command and is not used here. Start the compiled artifact with npm exec -- vp run start. Copy examples/read-only.json to config.local.json, set your own absolute T3 database path, and create private-state with owner-only permissions (chmod 700 on POSIX; an owner-only ACL on Windows). Do not use the example zero hash for a real principal: generate your own random bearer and store only its SHA-256 in policy. Supply EDDIE_T3_CONFIG as the absolute policy path and EDDIE_T3_STATE_KEY as your own securely provisioned base64 32-byte key, then npm exec -- vp run start. Keep key and bearer out of shell history/logs.

The listener binds loopback on port 41880. Connect an MCP client to /mcp using its owner-provisioned bearer. The minimal example has no enrolled sessions, event destinations, execution grants or guest access; configure exact sessions and read scopes for your own T3 instance before use. Nothing is auto-enrolled or discovered across trust boundaries.

Public startup uses read-only local durable projections and optional configured read routes. It does not load a private fleet helper. Legacy fixed verify_result/helper-backed startup profiles are not supported by this public entrypoint. Native commands are separate opt-in policy, not enabled by the example. The broker uses explicitly configured native CLI authorization; never treat subscriptions as execution authority. Secure HTTPS/private connectivity and external identity enrollment are operator responsibilities; no MTG/Keeper deployment is required or bundled.

## Limits

Read COMPATIBILITY.md and SECURITY.md. Native APIs/schema can change. Strict active-run steering is disabled: installed native behavior can start/queue a turn in races. continue_thread explicitly authorizes a new turn. Stored, native accepted, observed, agent-acknowledged and completed are distinct. Reconcile a stable UUID after uncertainty; never automatically resend. HTTP 200 webhook delivery does not prove agent execution. Aggregate monitoring currently requires live command scope as well as read scope. Diagnostics retain seven days or 25,000 records globally. Native completion observation retains 20 recent runs; this is not lossless telemetry.

Collaboration remains opt-in and disabled by default. The current identity verifier requires a configured Entra/Access identity boundary. Do not assume arbitrary external guest admission. Sharing links grant no authority.

## Release status

Experimental GitHub source release. The private package flag deliberately prevents npm publication; install from source. Project code is AGPL-3.0-or-later, selected by the owner. Project: https://github.com/Midtown-Technology-Group/kadenco . No real fleet credentials, runtime files, private Git history or deployment evidence are included. EXPORT-MANIFEST.json is a historical record of the initial extraction, not a manifest for later revisions. Use the exact Git commit and lockfile for current source provenance.
