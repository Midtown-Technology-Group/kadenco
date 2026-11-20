# Fleet member automatic updates

Each T3 host in the fleet runs the Eddie caller (the `ask_eddie` MCP server, the
`ask-eddie` CLI and the Pi extension) from the Kadenco release package.
`scripts/fleet-update.mjs` keeps that caller on the newest published release
without an operator: an hourly timer installs a new release, checks it against
the live Eddie server and only then switches to it.

Scope: the caller on fleet members. The central edge and its Worker are not
updated by this; promote them with the existing release procedure
([RELEASE.md](../RELEASE.md), [linux-edge.md](../packages/control-plane/deployment/linux-edge.md)).

## What a member accepts

A run installs a release only when all of these hold:

1. It is a published (non-draft) GitHub release of this repository, tagged
   `v<version>`, and its version is strictly newer (SemVer precedence) than the
   installed one. Prereleases count: the alpha series is the channel.
2. `SHA256SUMS` from the release lists the package digest, and the GitHub asset
   digest (when reported) agrees.
3. GitHub holds a Sigstore-signed SLSA provenance attestation for exactly that
   digest, issued to `.github/workflows/release.yml@refs/heads/main` of this
   repository by the GitHub Actions OIDC issuer, built on a GitHub-hosted runner,
   from the commit that `BUILD.json` names. The `attest` job of the release
   workflow creates it; it runs only for dispatches on main, so PR builds and
   other branches never produce an installable release.
4. The archive holds only regular files and directories under `package/`, its
   `package.json` and `BUILD.json` match the release, `npm ci --omit=dev
   --ignore-scripts` succeeds against the shipped shrinkwrap, and the new
   release's own updater loads (`self-test`).
5. The new caller, started exactly as a provider starts it, lists every caller
   tool (including `acknowledge_thread_delivery`) and the live server reports an
   authenticated binding to this member's configured host, with delivery
   acknowledgement available.

Candidates are tried newest first (all published releases, paginated), at most
five per run. A release whose publication fails a check (missing asset,
checksum, provenance, archive, identity) is skipped and not retried for 24
hours, so one bad release cannot hold back an older good one. A failed health
check skips to the next candidate without condemning the release (the server
may be down); its installed copy is reused on a later run. Network or tool
failures end the run. Nothing is switched unless every check passed; each run
logs a static reason.

Releases published before the attestation job existed (up to 0.1.0-alpha.25)
are never installed automatically.

## Layout

|          | Linux                                                                           | Windows                                         |
| -------- | ------------------------------------------------------------------------------- | ----------------------------------------------- |
| Base     | `~/.local/share/eddie-t3`                                                       | `%USERPROFILE%\.t3\runtime\eddie-t3`            |
| Releases | `<base>/releases/kadenco-<version>-<first 16 hex of package digest>`            | same                                            |
| Active   | `<base>/current` (symlink, replaced atomically)                                 | `<base>\current` (junction, via `current.next`) |
| Schedule | systemd user timer `kadenco-update.timer` (hourly, 10 min jitter; needs linger) | scheduled task `kadenco-fleet-update` (hourly)  |

`update.json` holds the host name, launcher type, node path and the path of the
existing caller credential; the updater never reads the credential, only the
launcher does. Each installed release carries `.fleet-update.json`, binding its
directory to the verified package digest; only such directories are reused,
activated or deleted. `update-state.json` records the current and previous
release and recent rejections; `update.log` has one JSON line per run. Every
run first reconciles state with the filesystem under the lock: it adopts a
switch that completed before a crash, finishes an interrupted Windows switch
(`current.next`) and restores a missing link. The schedule runs
`<base>/fleet-update-entry.mjs`, which loads the active release named in
`update-state.json` rather than going through `current`, so a broken link
cannot stop updates. Provider catalogs launch through `current`, so an update
needs no catalog edit; running provider sessions keep their already-started
caller until their next session. The updater keeps the current, previous and
newest installed releases.

## Adopt a member (once)

Bootstrapping runs the release's own updater, so verify the package with an
independent verifier before extracting or running anything from it. On a
trusted machine with GitHub CLI 2.49 or later:

```sh
gh release download v<version> --repo Midtown-Technology-Group/kadenco \
  --pattern 'kadenco-<version>.tgz' --pattern BUILD.json
gh attestation verify kadenco-<version>.tgz --repo Midtown-Technology-Group/kadenco \
  --signer-workflow Midtown-Technology-Group/kadenco/.github/workflows/release.yml \
  --source-ref refs/heads/main --source-digest <source from BUILD.json> \
  --deny-self-hosted-runners
sha256sum kadenco-<version>.tgz
```

Copy that verified tarball to the member; do not download it again there.
Extract it, run `npm ci --omit=dev --ignore-scripts` in `package/`, then, as the
user that owns the member's provider catalogs and caller credential, with the
same Node the catalogs use (Node 22.22.2+, 24.15+ or 26+, which the verifier
requires):

```sh
node package/scripts/fleet-update.mjs install <version> \
  --expect-digest <sha256 of the verified tarball> \
  --host <host name the Eddie server reports for this caller> \
  --credential ~/.config/eddie-t3/host-caller.json
```

On Windows pass the caller's `.clixml` credential file. `--host` must equal the
`host` that `get_eddie_capabilities` returns for this member's credential (the
health check refuses any other binding). `install` downloads the release,
refuses it unless its digest is the one you verified and it passes every check
above, installs it under `releases`, health-checks it, points `current` at it,
writes the stable entry point, rewrites the owned catalog entries through the
existing `install-agent-tools.mjs` (it refuses entries it does not own;
`--opencode-major 2` and `--legacy-opencode-manifest <path>` are passed
through) and installs the schedule, all under the update lock.
`--no-catalogs` and `--no-schedule` skip those steps. Delete the extracted
bootstrap copy afterwards.

## Operate

- `node <base>/fleet-update-entry.mjs status`: current, previous,
  last check, hold.
- `... run`: one update check now (what the timer runs).
- Pause: create `<base>/update.hold`; delete it to resume.
- `... rollback`: switch `current` back to the previous release and create the
  hold so the next run does not reinstall the release you rolled back from.
  Fix forward with a new release, then delete the hold.
- Logs: `<base>/update.log`; on Linux also `journalctl --user -u kadenco-update`.

A release can change the caller only to code that went through protected main
and the release workflow; it never changes the credential, the endpoint or the
SSH forward. A member whose credential or forward is broken fails the health
check and stays on its current release.
