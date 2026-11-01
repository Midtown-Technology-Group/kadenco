# Agent Cloudflare CLI routing

Use the existing authenticated `cf` CLI for supported control-plane operations.
Wrangler's login is separate. Do not alias `wrangler=cf`, export tokens between tools,
start login on a denial, or assume one machine's identity exists on another machine.

Before attempted Wrangler usage, run this **plan-only** helper from this checkout:

```sh
node scripts/cloudflare-route.mjs whoami
node scripts/cloudflare-route.mjs deployments list --name WORKER
node scripts/cloudflare-route.mjs deploy --dry-run --outdir LOCAL_OUTPUT
```

| Attempted Wrangler operation                                | Explicit plan                                            |
| ----------------------------------------------------------- | -------------------------------------------------------- |
| `whoami` without flags                                      | `cf auth whoami`                                         |
| `deployments list --name NAME` only                         | `cf workers deployments list --worker NAME`              |
| `deploy --dry-run` with supported local flags               | Preserve Wrangler argv for local build                   |
| `types [OUTPUT]` with supported flags                       | Preserve Wrangler argv for local types                   |
| `dev --local` with supported flags                          | Preserve Wrangler argv; review bindings before local dev |
| Other operation/flag, implicit dev, login or cloud mutation | Exit2 with actionable refusal                            |

Check `allowed` first. When true, the JSON result contains `executable` and an **argument array** (`argv`), never a shell command. When false, it contains only `allowed`, `reason` and `next`; do not read or execute plan fields.
Do not concatenate or evaluate its values as shell text. No command executes automatically,
no PATH/shim/hook is installed, and no credential is read by the router. Do not pass secrets
to the planner; its output is intended for review. Duplicate/unknown flags and unsupported
config/env/profile selection on mapped reads are rejected rather than silently discarded.
Inherited tool account selection is unchanged, not independently verified by the plan.
Before executing an approved control-plane read, confirm `cf auth whoami` and the exact
account/profile. Existing denials stay denied; never switch callers to make a retry succeed.

This helper is guidance, not a sandbox. Local config/build plugins can run code; local dev
can use remote bindings. Review config and retain normal permission checks. Existing CI
`wrangler deploy --dry-run` and types commands remain unchanged and need no cloud login.

For unsupported operations, use anonymous `cf cli search "operation resource type"`, then
the returned command's help/schema. Never include private names/IDs in discovery queries.
Real deployment requires reviewed configuration or compatible Build Output, normal source
CI/review and migration authorization. `cf deploy` on an unconverted Wrangler project can
ignore its entrypoint/bindings through automatic configuration; do not run it blindly.
Use the supported migration/prebuilt procedure after review, never a raw argument substitution.

References checked 2026-11-01 with cf1.0.0-beta.22:
[Cloudflare project/deployment guidance](https://developers.cloudflare.com/cf/projects/).
The two read mappings were verified using installed command discovery/help. No write was
attempted to prove scope. Management OAuth does not imply R2 S3 credentials; that is a separate
data-plane authorization boundary.

## Applicability and rollback

The planner uses Node's standard library and is covered by the normal Linux/Windows source CI matrix.
Only agents reading this checkout's AGENTS.md are instructed to use it. This does not
intercept arbitrary shell commands, global Wrangler, npm exec, or another repository's CI.
Fleet remotes, their installed cf versions/auth and other owners' instructions are unverified;
no fleet-wide rollout is claimed. Inventory each host/owner before any separately authorized
installation. No shared skills/profile or machine-local launcher was changed.

Rollback is reverting this source change through normal review; existing binaries, credential
stores, cloud services and local build scripts were never replaced. No runtime release/version
change or production rollout accompanies this agent guidance.
