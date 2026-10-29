# Repository security baseline

Verified through GitHub REST on 2026-10-29:

- Public repository; AGPL-3.0-or-later project metadata and notice remain intact.
- Secret scanning, push protection, private vulnerability reporting, Dependabot
  vulnerability alerts and automatic security-update PRs enabled.
- GitHub-managed default CodeQL configured with extended queries and a weekly
  schedule for JavaScript/TypeScript. Do not add a competing producer.
- Main ruleset active, no bypass actors: PR required, one independent approval,
  stale approvals dismissed, approval after last push, all discussions resolved,
  strict/current-base required checks `gate` and `Analyze (javascript-typescript)`
  from GitHub Actions plus the `CodeQL` findings check from GitHub Advanced Security. Deletion/force-push blocked and linear history required.
- Only squash merges permitted by repository merge settings; merged branches
  automatically deleted.
- Workflow token default is read-only; Actions cannot approve pull requests.

CI runs Oxlint/Oxfmt with warnings denied, all Node tests on Windows/Linux and
Node 22/24, synthetic browser acceptance on Linux/22, and an all-dependency audit
at every severity. It supports PRs, main pushes, merge groups,
weekly scheduled runs and manual dispatch. Every job has a timeout; checkout
credentials are not persisted. No secrets, deployment environments or workflow
write tokens are used. Dependency/action updates are proposed weekly through
Dependabot; updates still require review and checks.

Direct dependencies and actions are pinned, with a lockfile for transitive
versions. Project npm settings reject unsupported Node versions and disable
install scripts. Vite+ already supplies native Oxlint/Oxfmt, so no redundant
ESLint/Prettier stack or speculative runtime-utility replacement was added.
Formatting the initial dense source creates a large mechanical diff; security
changes are the response cap, redirect refusal, timeouts and event-schema fix.

Limitations: GitHub readback still reports non-provider secret patterns and
secret validity checks disabled after an enable request; those optional features
are not claimed as active. Standard scanning/push protection remain enabled.
No npm package/release publishing, deployment or live T3 configuration was
changed. Main protection deliberately applies to maintainers too: this PR needs
an independent approval; neither its author nor an agent may self-approve it.
