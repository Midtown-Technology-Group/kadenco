# Linux edge host

The central edge (`run-edge.mjs`) can run as a systemd service on a small Linux
host instead of an operator workstation. The files are in
[`operator/linux/`](../operator/linux/). This document describes the layout, the
access each fleet host grants it, and the routine operations: release
promotion, policy renewal and restart. It changes no authorization: the edge
keeps the executor, owner and native grants of the central policy, and every
host route is projected into that policy as before.

## Layout

| Path                                                               | Owner, mode        | Contents                                                                                                                                                 |
| ------------------------------------------------------------------ | ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `/opt/kadenco/kadenco-edge-supervisor.mjs`                         | root, 0644         | supervisor (systemd `ExecStart`)                                                                                                                         |
| `/opt/kadenco/releases/kadenco-<version>-<sha7>/`                  | root, read-only    | qualified releases, one directory each                                                                                                                   |
| `/opt/kadenco/bin/kadenco-edge-ctl.mjs`                            | root, 0750         | operator control (status, stop, start, release, files)                                                                                                   |
| `/opt/kadenco/tools/…/tunnel-client`                               | root               | tunnel client binary for the MCP tunnel profile                                                                                                          |
| `/etc/kadenco/edge.json`                                           | root:kadenco, 0640 | supervisor configuration (no secrets)                                                                                                                    |
| `/etc/kadenco/config.json`, `/etc/kadenco/central-supervisor.json` | root:kadenco, 0640 | edge policy and supervisor bootstrap, operator-managed and read-only to the service; `edge.json` points to them with `configPath` and `supervisorConfig` |
| `/etc/kadenco/keeper-api-key`                                      | kadenco, 0400      | read-only secret-store API key                                                                                                                           |
| `/var/lib/kadenco/eddie-t3/`                                       | kadenco, 0700      | `state/`, `state-central/`, `service-status.json`, tunnel profile, fleet helper                                                                          |
| `/var/lib/kadenco/.ssh/`                                           | kadenco, 0700      | edge SSH key, pinned `known_hosts`, one alias per fleet host                                                                                             |
| `/var/lib/kadenco/.config/mtg-t3-fleet/`                           | kadenco, 0700      | fleet helper `hosts.json` and session cache `tokens.json` (`{}` is valid; the helper refuses to run without it)                                          |

`kadenco` is a system account with no login shell. The unit runs with
`ProtectSystem=strict` and may only write `/var/lib/kadenco`.

## Secrets

The supervisor reads three values (state key, executor bearer, owner MCP bearer)
and the tunnel API key from a secret-store REST endpoint at every start, with a
read-only API key. The endpoint must be HTTPS, or plain HTTP to a literal
private or mesh address (for example over an encrypted overlay network), and
redirects are refused, so the key cannot be forwarded elsewhere. The edge's
values reach `run-edge.mjs` once on private stdin and are never written to disk,
argv or logs. The tunnel client receives its API key and the MCP authorization
in its environment (as on Windows); any process it starts would inherit them.
`edge.json` names the endpoint, key file, record identifiers and field labels.

## Fleet host access

The edge's SSH key is authorized on every fleet host with
`restrict,port-forwarding`, a `from=` list, `permitopen` (the T3 port only where
possible) and `permitlisten="127.0.0.1:<caller port>"` for the reverse caller
forward, and a forced command:

Both wrappers compare the whole request string with the exact argument vectors
the edge sends (`src/native-session.mts`) and never evaluate it, and refuse any
request containing a newline or other control character.

- **Linux hosts**: `forced-command/kadenco-edge-ssh LAUNCHER TOKEN_FILE BASE_DIR`.
  Allows reading T3's runtime metadata, the existing fleet-read token, issuing a
  2-minute `eddie-t3-delivery` session with exactly the read or read+operate
  scopes the edge requests, and revoking a session only after `auth session
  list` shows it is an `eddie-t3-delivery` session. Everything else is refused.
- **Windows hosts** (OpenSSH Server with Git Bash as `DefaultShell`): Windows
  OpenSSH cannot open key-based sessions for Entra ID (AzureAD) accounts, so the
  key is authorized for a local service account with
  `forced-command/kadenco-edge-windows.sh`, and the owner runs
  `forced-command/kadenco-edge-mint.ps1` every 5 minutes as a user-level
  scheduled task. The task mints a read-only and a read+operate session; the
  wrapper answers each of the edge's two delivery requests with the session of
  the same scope and treats revocation as a no-op. Trade-off: such a session
  cannot be revoked per command and lives up to 15 minutes. Fill in only the
  configuration block of each template.

If the edge host cannot reach a fleet host directly over the mesh, route that
alias through another enrolled host with `ProxyJump`: add the jump target's
`host:22` to the key's `permitopen` on the jump host and the jump host's address
to the target key's `from=` list. Do not NAT around a network policy.

## Operations

`kadenco-edge-ctl.mjs` runs as root on the edge host and prints one JSON object:

```sh
node /opt/kadenco/bin/kadenco-edge-ctl.mjs status
node /opt/kadenco/bin/kadenco-edge-ctl.mjs stop      # verified: no kadenco processes, no listener
node /opt/kadenco/bin/kadenco-edge-ctl.mjs start     # waits out the old lease, then for ready
node /opt/kadenco/bin/kadenco-edge-ctl.mjs install-release TGZ NAME MANIFEST_SHA256
node /opt/kadenco/bin/kadenco-edge-ctl.mjs set-release NAME
node /opt/kadenco/bin/kadenco-edge-ctl.mjs install-file SRC config|supervisor
node /opt/kadenco/bin/kadenco-edge-ctl.mjs set-executor-expiry MS
```

Every command except `status`, `manifest` and `get` holds a lock, so changes are
serialized, and exits nonzero on refusal (including a `start` that does not reach
ready). `status` counts the supervisor's `ready` only for systemd's current main
process. Files root writes live in root-owned directories (`/etc/kadenco`, the
backup directory), never in the service-writable runtime directory, and
reads refuse symbolic links; writes go to a file root created exclusively and
are renamed into place, and backups go to the root-only `/var/backups/kadenco`.
Transfers are taken only from `/root/kadenco-xfer/kadenco-<32 hex>`.
`install-release` accepts only regular files and directories under `NAME/`,
extracts into a private staging directory, and verifies the manifest before
publishing.

`set-executor-expiry` is a startup gate: the supervisor refuses to start the
edge after it. The running edge's executor expiry is `serviceExpiresAt` in
`central-supervisor.json`, which renewal installs with `install-file`.

**Restarts.** The edge does not release its central lease on exit; the lease
expires 120 s later, and a successor started sooner retries inside its claim
window. `stop` records the time and `start` waits until 130 s have passed, and
the unit's `RestartSec=130` does the same for crash restarts, so every start
claims on its first attempt. A planned restart therefore takes about 2.5 minutes.

**Release promotion.** `scripts/release.mjs` hands deployment to the operator's
private promotion script. For a Linux edge it must, in order: verify the
qualified installation; refuse native binaries (`.node`, `.exe`, `.dll`, `.so`,
`.dylib`), because releases are qualified on another platform; archive it and
compute the manifest (SHA-256 over sorted `path\0sha256` lines, as `ctl
manifest`); `install-release` (extracts to a staging directory, verifies the
manifest, then moves into place, with no service impact); deploy the Worker; `stop`;
`set-release`; `start`. If the start does not reach ready, restore the previous
release with `set-release` and `start` again.

**Policy renewal.** Follow [policy-renewal.md](policy-renewal.md). On a Linux
edge, install the renewed `config.json` and `central-supervisor.json` with
`install-file` and the new startup gate with `set-executor-expiry` while the
edge is stopped, after `committed: true`. Host-caller credentials enforce their
own `expiresAt` locally and must be extended to the new ceiling as well.

**Rollback.** Every `set-release`, `install-file` and `set-executor-expiry`
keeps a timestamped backup in `/var/backups/kadenco`. Old release
directories stay until removed by the operator.
