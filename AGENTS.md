# Kadenco agent guidance

For Cloudflare work, consult [the CLI routing guide](docs/cloudflare-cli-routing.md)
before invoking Wrangler. Use `node scripts/cloudflare-route.mjs <wrangler argv>`
to obtain an explicit argv plan. A refused mapping requires native `cf` discovery
and review, not an alias or credential transfer. The router does not execute commands
or grant authority. Preserve existing identity/account, approvals and denied outcomes.

Keep Wrangler for qualified local builds/types/dev. Never automatically initiate login
because Wrangler authentication expired; inspect the existing `cf auth whoami` identity.
Follow CONTRIBUTING.md, RELEASE.md and the repository CI/security gates. Production
activation remains disabled until the separately reviewed migration requirements hold.
