# Read-only cadence oversight (draft)

This source change is stacked on TypeScript PR #4, exact base
`93ab38685063bdc1f9fee670a9fac053aafbb40f`. It does not modify that branch or
deploy the oversight feature. Kadenco retains its independent repository, CI,
release and first-class T3 sidecar lifecycle.

## Interfaces

`get_cadence_overview` returns compact goal summaries grouped as moving, blocked,
decision needed, verified done, or visibility gap. It uses cached authorized
observations and starts no native reads or scanner. Use `after_change` for
material changes, `limit` (1–20) and `cursor`. Finish every cursor page before
advancing to `high_water_change`; restart the listing when `definition_key`
changes. Cursors are signed and bound to the owner, visible definitions and
watermarks. Native reads/scan heartbeats and changing age counters do not create
new changed-goal rows. The overview decrypts the retained delivery window once
per request, not once per goal.

`get_cadence_goal({goal_id})` reconciles the exact configured host/project/thread
bindings with existing native read handles. It reports current pinned run state,
finish criteria, artifact revision, handoff receipts, coverage, event backlog
and recovery limits. It never calls command receipt reconciliation that could
open a native operation session, and never sends, resumes, answers, nudges,
renews a grant or creates a subscription. Both tools advertise `readOnlyHint`.

The existing collaboration UI gains a manual read-only panel for its existing
authenticated owners only. Guests do not inherit broker-wide goal visibility.
Owner identity and read scope are checked again after asynchronous detail reads.
The panel has no polling, execution or delegation control. Disabled cadence adds
no tools/panel and changes no enrollment.

## Goal definitions and trust

Native T3 still owns tasks, runs, prompts, approvals and execution. The current
read adapter exposes run state and linked PR state, but no authoritative goal
finish criteria or activation proof. The manifest is an operator-maintained
annotation overlay, not a second task queue or memory/orchestration system.
See [the synthetic manifest](../examples/cadence-goals.json).
After building, `node scripts/validate-cadence.mjs /absolute/path/to/manifest.json`
validates its bounded file/schema without printing goal contents. This does not
validate native authorization or perform any native access.

Each goal has an existing MCP principal as owner, an immutable identity and
monotonic revision, explicit finish criteria/artifact references, an execution
owner, next-action owner (nullable), wait reason and exact targets. Each target
pins host, project, thread and run. Work targets drive lifecycle; targets marked
`watcher` contribute activity/coverage only. Watcher completions and unchanged
checks cannot finish, verify or advance a work goal. At least one work target is
required. Watcher artifacts cannot satisfy work finish criteria. Changes to a
goal definition require a revision increase; regressions/conflicts fail closed.

The phase distinguishes planned, accepted, running, completed and independently
verified. Missing or contradictory observations report unknown with the last
known phase, rather than regressing to planned or calling the goal stalled.
Native completion is execution evidence; it does not satisfy merge, activation
or independent content-review criteria. For example, green checks with a draft
PR/inactive delivery remain incomplete finish criteria. Agent message text is
never parsed as a verification, next-step assignment or authority.

Independent verification is explicitly **operator-attested**, not fetched or
cryptographically proved by Kadenco. A trusted operator record must name the
independent verifier, execution owner, goal revision, exact artifact revision,
bound work run, assertion, timestamp and stable evidence reference. The verifier
must differ from the execution owner. Every finish criterion must match, and the
pinned work completion must be visible and current. The response preserves this
provenance. An agent's claim, a watcher result or an HTTP acknowledgement cannot
produce such a record. There is no automatic external CI/deployment verifier in
this slice; adding one needs its own source/authorization qualification.

The trusted manifest must be operator-managed; do not use agent output as its
source. Keep it under the same private operator control as policy. The loader
uses a bounded regular-file descriptor read, refuses mutable reads and POSIX
group/world-writable files, and reports sanitized errors. HTTPS references may
not embed credentials or query tokens. Remote tools cannot select a path or edit
records. The manifest itself grants no host, project, thread or execution access;
every target must pass existing live read authorization. Another owner's goals
do not affect a reader's visible definition digest.

## Activity, progress and handoffs

`last_activity` reflects observed native thread/run activity and retained native
events. `last_meaningful_progress` advances only for a bound work outcome,
independent criterion evidence or explicit work ownership acceptance/acknowledgement.
Refreshing a watch, listing unchanged checks, rereading a result or restarting
the sidecar does not reset it. First observation preserves native evidence time
instead of treating polling time as progress.

Distinct native activity without such progress can flag a no-progress loop
after the configured duration/repetition threshold. The flag is diagnostic only.
Missing visibility, expired monitoring grants or a truncated delivery window
disable that conclusion. An unowned next step requests a decision; it starts no
work. Stale completion predating a goal cannot complete it. Concurrent runs are
not substituted for the pinned work run.

Handoff ownership proposed/accepted/acknowledged is an explicit owner record,
separate from stored/uncertain/native-submitted delivery and the agent's native
delivery acknowledgement. Preserve request UUID, native command/message IDs,
projected message placement and run identity. A cancelled queued run can still
have a message observed in another containing run. The overview never interprets
cancelled as undelivered, and every handoff reports `safe_to_resend: false`.
No acknowledgement or duplicate send is issued by the monitor.

## Coverage and recovery limits

Passive hooks reuse existing authorized native reads and failures; no new
aggregate monitor, subscription or worker is installed. The existing encrypted
Store holds only small cadence snapshots/checkpoints alongside its native
receipts, diagnostics and scan records. Message text/results are not copied.
Existing delivery producers add local `observedAt` metadata outside the signed
event object; event IDs, payload/signatures, callbacks and subscription identities
are unchanged. Old records keep observation lag unknown.

Cross-subscription events deduplicate on host/thread/run/kind/native_request_id.
Replays and out-of-order projections cannot manufacture progress. Contradictory
states at the same native version become a visibility gap until a newer native
projection reconciles them.

Detail exposes read freshness, scan state/completeness, scan failures, subscription
expiry and existing monitoring grant expiry. Observation lag is shown only where
recorded. Pending-event age and stopped/revoked deliveries are backlog diagnostics;
HTTP delivery acknowledgement is never agent execution. Recovery reports current
projection reconciliation without claiming historical recovery. Native readback
retains at most 20 recent runs. Delivery dedup examines at most 2,000 newest local
records and reports truncation. Historical completeness is always false. Invisible
work is not stalled work.

## Rollout requirements (not performed)

First land/qualify the TypeScript dependency, then review this draft and its own
exact-head CI. This request authorizes source/testing only: no production rollout
or policy mutation is included. A future rollout needs an operator-reviewed
manifest for existing authorized targets and an explicit `cadence` stanza in the
private policy, for example:

```json
{
  "cadence": {
    "manifestPath": "/private/operator/cadence-goals.json",
    "freshForMs": 120000,
    "noProgressMs": 900000,
    "repetitionThreshold": 3
  }
}
```

Use an absolute private path with protected operator access. These settings are
observability thresholds, not new grants. Enabling cadence must preserve existing
subscriptions/passive inbox, native providers/models/runtime, credentials,
signing/callback identities, grants/expiry, approval controls and canary budgets.
Warm the projection using existing observations or explicit read-only detail
calls; do not replay historical work or launch a canary. Disabling the optional
stanza disables the interface; keep existing encrypted state/receipts for audit.

## Synthetic validation

Regressions cover unchanged reads/watch restarts, cross-subscription replay and
out-of-order events, contradictory/stale projections, concurrent and bound watcher
runs, stale completion, native-accepted but unacknowledged ownership, uncertain
delivery, expired grants, source/reconnect gaps, missing retained runs, unowned
steps, partial verification, wrong artifact/run/revision or self-verification,
bounded windows, cursor tampering, read revocation and definition races. HTTP/MCP
tests verify read-only discovery, existing subscription/command preservation and
owner-only UI access. Browser acceptance renders an injection-shaped title as
text and records one exact native read with zero native writes.
