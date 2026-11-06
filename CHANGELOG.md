# Changelog

Entries describe source candidates. A heading alone does not mean a tag,
GitHub Release, artifact or fleet rollout exists; consult release evidence.

## 0.1.0-alpha.16

- Return the public subscription identity in central delivery history while
  retaining the internal host/thread key for authorization and receipt lookup.
  Fixes fail-closed history reads discovered during alpha.15 live verification.

## 0.1.0-alpha.15

- Expose exact-event delivery history from retained central/edge audit and current
  receipts, with owner/scope checks, bounded pagination and explicit evidence gaps.
- Attribute central HTTP diagnostics to bound principals and originating MCP
  requests without storing URLs, tokens, payloads or arbitrary errors. The scoped
  read-only view does not claim fleet-wide GitHub quota accounting.
- Record the six public-repository scout dispositions and the observability goal.
  No upstream runtime, event store, scheduler or code is imported.

## 0.1.0-alpha.14

- Add a resumable maintainer release command that binds one build request to an
  immutable source, qualifies extracted artifacts, and reconciles publication
  before retry. Keep the existing account and private promotion boundary.
- Report the deployed package version from the Durable Object and sanitize
  supervisor startup failures into explicit reasons and fingerprints.
- Prepare the existing Windows-edge / Cloudflare deployment scope for beta;
  always-on PVE, guest sharing acceptance and automatic goalkeeper remain excluded.

## 0.1.0-alpha.13

- Add an owner-only operator path to reauthorize an existing expired migration
  principal once for at most one hour. Preserve token, hosts, recovery-only role
  and all other policy fields, with transactional drift checks and a durable receipt.

## 0.1.0-alpha.12

- Reactivate the exact current frozen recovery state with current authority,
  snapshot digest, audit watermark and fresh managed-writer retirement evidence.
  Preserve receipts and fence stale epochs without reimporting local history.

## 0.1.0-alpha.11

- Reconcile central callback outcomes into existing local delivery views without
  resending events. Keep centralized passive requests pending until a receipt
  proves acknowledgement or stopped delivery; never imply agent execution.

## 0.1.0-alpha.10

- Read central callback receipts without claiming agent execution or exposing event
  payloads and signing details. Recheck current owner/executor scope and revocation.

## 0.1.0-alpha.9

- Bound and encode authorization policy transport to fit Cloudflare's per-binding
  limit without removing principals, scopes or expiry. Expanded policy validation
  and persisted authorization remain unchanged; plain JSON stays compatible.

## 0.1.0-alpha.8

- Restrict temporary migration credentials to explicit import, recovery and
  activation operations. Deny native execution, general administration and
  future unlisted operations; preserve ordinary owner/executor behavior.

## 0.1.0-alpha.7

- Cloudflare SQLite coordination and encrypted operational replication with
  durable request reconciliation, exact grant bindings and no uncertain replay.
- Protected operational adoption, local history retention, managed-writer
  retirement checks and challenge-bound activation receipts.
- Compiled central supervisor and read-only transfer entry points; matching
  central Worker/edge artifacts now ship through the immutable release lane.
- Source and package qualification do not establish production cutover or HA.

## 0.1.0-alpha.6

- Match native guest join and conversation screens: name/Join form, compact title
  and expiry, conversation bubbles and bottom composer. Display names remain
  separate from verified identity and authorization.

## 0.1.0-alpha.5

- Forward negotiated sharing request/receipt tools through the stdio caller, with
  a full terminal-to-MCP regression. Alpha.4 backend/UI shipped without this path.

## 0.1.0-alpha.4

- Durable exact-thread sharing requests with owner scope review, explicit approval,
  decline, duplicate suppression and uncertain-outcome reconciliation.

- T3-inspired sharing and access-review dialogs with explicit scope, cancellation,
  keyboard focus management and no authorization changes.

## 0.1.0-alpha.3

- Qualify immutable release packages in clean CI with production-only installation,
  sidecar lifecycle smoke tests, source/build identity, SBOM and checksums.

Next consolidated candidate after the source-only alpha.2 deployments:

- Email-bound first-time guest invitations, explicit join, in-conversation proposal review and revocation.

- Host-bound delivery acknowledgement and exact native-message evidence recovery.
- Worker timing diagnostics, fewer repeated grant checks and bounded I/O yields.
- Coalesced fleet observations and replaceable pending coverage notices.
- Owner sharing onboarding with a colleague sign-in link and exact-thread grant guidance.
- Version/changelog consistency checks and documented release/rollback cadence.

Protocol compatibility identifier remains 0.11.0. Event-loop stalls remain an
open limitation; no exactly-once agent execution guarantee. Current-run live
acknowledgement success still requires fresh organic delivery evidence.

## 0.1.0-alpha.2

Historical experimental source baseline: TypeScript sidecar, typed build and
separate CI. Multiple later deployments reused this package version and were
identified by exact source SHA. They are not retrospectively retagged or
claimed as published release artifacts.
