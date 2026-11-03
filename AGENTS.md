# Kadenco agent guidance

For Cloudflare work, consult [the CLI routing guide](docs/cloudflare-cli-routing.md)
before invoking Wrangler. Route attempted commands through `npm run agent:wrangler -- <wrangler argv>`
(or `node /path/to/kadenco/scripts/agent-wrangler.mjs <wrangler argv>` from a reviewed local build directory).
This executes allowlisted reads with the existing cf installation and keeps allowlisted local builds/types on Wrangler.
For plan-only inspection use `node scripts/cloudflare-route.mjs <wrangler argv>`. A refused mapping requires native `cf` discovery
and review, not an alias or credential transfer. The planner never executes commands;
the executor uses only the existing tool identity and does not retry denials. Neither grants authority.
Preserve existing identity/account, approvals and denied outcomes.

Keep Wrangler for qualified local builds/types/dev. Never automatically initiate login
because Wrangler authentication expired; inspect the existing `cf auth whoami` identity.
Follow CONTRIBUTING.md, RELEASE.md and the repository CI/security gates. Production
activation remains disabled until the separately reviewed migration requirements hold.

## Secret gate before publication

Before publishing the current PR branch, commit the complete candidate and run
`python3 scripts/secret_gate.py` (native Windows: `python`). Require exit 0;
missing tooling/authentication, scan errors and skipped scans block publication.
Then run the existing repository gates. Repeat after changing outgoing commits.
Push exactly the scanned HEAD. This PR scan covers the current branch against its
fetched intended base; other refs, multi-ref pushes and rewritten history require
`--pre-push` with Git's complete ref-update stream. Stop if any pushed ref is
uncovered. See [secret scanning](SECRET-SCANNING.md) for base selection, new branches,
pre-push input and prerequisites. Preserve GitGuardian App, CI and Gitleaks checks.

Local tooling: `npm run pre-pr`.
