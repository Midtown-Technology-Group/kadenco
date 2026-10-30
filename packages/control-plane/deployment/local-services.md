# Local central/edge service coverage

This branch composes a central coordinator with one policy-enforcing edge. It
is not a production replacement or an active-active edge implementation.
`deployment/coverage.json` is the machine-readable ledger; `replacement_ready`
remains false and production activation remains unconditionally refused.

## Implemented central paths

`services.ts` executes within the existing DO synchronous transaction:

- Subscription identities and lifetimes are retained; same-ID changed bindings
  conflict, expired/revoked principals/subscriptions cannot observe or deliver.
- Cursor compare-and-set and exact native host/thread/run/kind/request identity
  suppress replayed observations; outbox delivery identity includes the source
  subscription. Original callback eventId and subscription ID are preserved.
- Claimed outbox generation/lease, begin-before-I/O accounting, six-attempt retry
  ceiling and existing exponential backoff. HTTP408/429/server/unavailable
  retries retain event identity; terminal4xx/redirects stop. HTTP2xx acknowledges
  delivery only. Pending-question/source authorization denials stop without
  inventing an HTTP response from the callback receiver.
- Bounded pending-outbox pagination supports recovery after edge restart.
  Unauthorized records are excluded; storage faults propagate rather than being
  reported as a complete empty scan.
- Host/UTC-day budgets and configured thread/provider caps reserve atomically
  with the command, shared across continue/create/answer/settings/follow-up.
  Stable UUID replay does not spend again. Uncertain attempts remain spent.
  Missing budget policy denies; null is explicit unlimited, never inferred.
- A cooperating-edge lease denies another executor/stale generation. It is NOT
  enforcement against alpha6, an already-running native effect, or a lost host
  retaining signing/native credentials.

## Existing logic retained on the edge

`edge-services.ts` runs one bounded handoff pass with the original Bridge/fleet
observers. Native source cursors and encrypted projection state stay on that
single edge. Central observation cursors describe handoff completeness, not
historical native completeness. A fleet subscription can have internal
host/thread children while retaining its original external ID and callback ID.
No additional fleet monitor or automatic task execution is created.

Callback credentials, callback allowlist/network defenses, original signing
rotation behavior, native pending-question checks and source deliverability
remain in the original edge services. `existingCallback` verifies the claimed
owner/host/thread/name against the exact encrypted subscription reference and
rechecks after source I/O. An event is evidence, never task authority.

`edge-routes.ts` reuses the existing authenticated owner/caller MCP and
Access/Entra collaboration HTTP surfaces. Caller scope, request read-before-reply,
passive inbox, guest grants/proposals/review, JWT verification and safe UI remain
in those implementations. Credentials are not replaced by a central bearer.
Those synchronous exchange/collaboration transactions remain on the edge's
single encrypted Store; they are not falsely presented as DO-authoritative.
Native routes are intercepted by `mutation-gate.ts` and `coordinator.ts` so MCP
and collaboration writes cannot bypass central budgets. With no coordinator,
native calls deny. Input schemas and signed payloads must match exactly before
reservation; current grant checks precede begin and execute. Original enforcing
services still check model/provider/runtime, pending questions and approval
controls. The fixed follow-up calls the existing dedicated-session implementation
only; it cannot become an arbitrary prompt, recursive task or Codex workaround.

Operator binding/current-grant callbacks are trusted startup composition, not
agent-callable RPC. They must derive exact targets from existing grants/native
projection and deny missing mappings. No production mapping/credential was
invented. Decryption/signing keys never move into this Worker implementation.

## Qualification and remaining boundaries

Tests cover central SQL concurrency/restart/budgets, exact mock service execution,
real MCP default-denial, claimed callback handoff with original signer, and
pending-question/revocation/expiry/duplicate cases. `npm run test:parity` runs52
existing sidecar cases from their required repository cwd, covering caller role,
passive questions/replies, collaboration isolation and settings. These are
regression evidence for reused services, not proof of every central route in a
live account. No native/cloud side effect occurred.

Concrete non-replacement boundaries:

- Subscription lifetime synchronization uses exact expected-expiry CAS and
  retains the source's immutable temporary lease ceiling. It cannot revive a
  centrally revoked subscription, change a binding/callback reference, or turn a
  standing subscription into a temporary lane. Transport epoch is not identity.
  Binding/principal changes require an explicit reviewed current-policy mapping,
  not automatic monitor renewal. Tests cover expiry CAS and temporary extension
  refusal; callback challenge verification remains the existing edge operation.
- Imported historical subscriptions/deliveries are still opaque staging records;
  they are not automatically turned into active observer/outbox rows. A verified
  schema conversion must reconcile retained cursors/unknown receipts and current
  policy before activation. Treating imported bytes as initialized authority is
  explicitly refused. Existing current-day budget usage also needs that verified
  conversion, or a new deployment could reset allowances.
- Collaboration/exchange state and live SSE remain single-edge owned. Moving them
  into DO requires an asynchronous transaction contract replacing the synchronous
  Store API across proposal, acknowledgement and revocation paths; returning
  cached writes would break approval isolation. This branch uses the tested
  narrow edge boundary instead, and needs approved durable-host custody to remove
  the laptop dependency. A lease check on HTTP admission alone is not a
  cross-system atomic revocation or active-stream fencing guarantee.
- Diagnostics retain the existing edge retention/timing behavior; no performance
  fix or central profiling claim is made. Actual-volume extraction/retention and
  failure recovery must be qualified before migration.
- Production route/host/trust setup, old-writer enforcement, current-state rollback
  export and independent live acceptance remain blocked by the decision packet.
  A current central-state rollback must include new service tables and counters;
  the fixture-only old records exporter is not sufficient after central writes.

These boundaries keep production disabled. The package neither silently drops
legacy behavior nor claims the entire relay moved to Cloudflare. Source paths
that are not yet authoritative have explicit dependencies and refusal behavior.

## Additional local acceptance and precise limitations

Mutation proxies retain every original argument, including collaboration's final
`authorize`, `currentSelectionOnly` and `collaborator` restrictions. A regression
case revokes that callback immediately before execution and observes no native
write. A real HTTP MCP call without a central coordinator is denied before the
mock native service. Dedicated fixed follow-ups also cross the coordinator and
then reuse the original dedicated-session/runtime/budget checks; no new
follow-up authority is inferred from a generic host grant.

The central quota is a conservative operation reservation: it holds capacity
once stored, including preflight failures/no-op operations that subsequently
reach the edge. It does not refund based on agent-supplied outcome text. This is
stricter than the original settings service's submitted-only accounting, not
full budget-behavior parity. Safe release semantics require trusted pre-dispatch
cancellation/fencing or independently proven no-effect evidence; unknown native
outcomes must never release capacity. Until that policy/implementation is
qualified, replacement_ready stays false. Existing production budgets are
unchanged, and the native service still enforces its own original allowance.

No owner decision is being invented to label engineering gaps complete:
historical encrypted subscription/outbox/counter adoption, exact production
policy/grant translation, complete current-state central rollback, active-stream
fencing and volume/retention qualification remain implementation/qualification
work. Their blocking dependencies are described above. External gates remain
account/host selection, approved cost cap, trust custody, enforceable old-writer
retirement and explicit applicable cutover approval. Each has a local refusal or
negative test; none has been satisfied by a fixture certificate.
