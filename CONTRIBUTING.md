# Contributing

Use a supported Node 22 or 24 release, then `npm ci --ignore-scripts`.
Run `npm exec -- vp run check`, `npm exec -- vp run test`, and `npm audit`.
The check runs both pinned compilers; the test command first builds with `tsrs`.
Edit `src/*.mts`, not generated `dist/*.mjs`. Production startup uses compiled
output and needs no compiler. The sidecar's independent CI/release and typed
embedding API are described in [docs/t3-sidecar.md](docs/t3-sidecar.md).
`npm exec -- vp run format` applies Oxfmt formatting; Oxlint treats warnings as
failures. These are JavaScript static checks, not a claim of complete TypeScript
type safety. Keep the native Node test runner; `vp test` selects Vitest instead.

For UI changes, set `T3_TEST_BROWSER_PATH` to a local Chromium executable and run
`npm exec -- vp run test:browser`. This uses synthetic identities and a recording
native boundary, never real grants or tasks. Never use live fleet access to
create test fixtures or paste real thread data into issues.

Open a focused PR. Protected main requires the CI gate, CodeQL, a current base
and resolution of review findings. No second-maintainer approval is required; do not bypass protection or fabricate approvals.
Keep dependency/action versions pinned and lockfile changes reviewable. Do not
run third-party install scripts or use privileged pull-request workflows.

Security reports belong in private vulnerability reporting linked in SECURITY.md.
Contributions are under AGPL-3.0-or-later; retain third-party notices. No CLA or
copyright transfer is requested.

Release cadence, version identity, artifact qualification and rollback evidence
are defined in [RELEASE.md](RELEASE.md). Run `npm run release:check` before
publishing a version change; source merge and runtime deployment remain distinct.
