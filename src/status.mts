// SPDX-License-Identifier: AGPL-3.0-or-later
// Truthful, read-only operational status for one authenticated owner. It reports
// evidence the process actually holds (build identity, runtime/lease state and
// the last completed journey round trips) and says "unverified" or "unknown"
// otherwise. It never creates subscriptions, contacts T3, sends events or
// extends any grant, so it stays safe to serve while the edge lease is lost.
import { readFileSync } from "node:fs";
import type { Bridge } from "./bridge.mjs";
import { subscriptionState } from "./subscription-state.mjs";

export const STATUS_SCHEMA = 1;
/** A journey is "verified" only when its last full round trip is this recent. */
export const JOURNEY_FRESH_MS = 24 * 3600000;
/** An unfinished attempt older than this, with no later success, is "failing". */
export const JOURNEY_STUCK_MS = 15 * 60000;
/** Repeated polls within this window reuse one report (bounds event-loop work). */
export const STATUS_CACHE_MS = 5000;
/** Evidence timestamped further than this in the future is not trusted as fresh. */
const CLOCK_SKEW_MS = 60000;

export type RuntimeStatus = {
  mode: "standalone" | "central_edge";
  lease:
    | { state: "not_applicable" }
    | {
        state: "held" | "renewal_failing" | "lost" | "unknown";
        generation: number | null;
        last_renewed_at: string | null;
        expires_at: string | null;
        last_failure: { reason: string; at: string } | null;
      };
  /** Central Worker/DO identity observed at edge startup (central edge only). */
  central?: { release_version: string | null; epoch: number | null; observed_at: string };
};

type BuildIdentity = {
  package_version: string | null;
  protocol_version: string;
  source_commit: string | null;
  build_run: string | null;
};

const iso = (ms: number | null | undefined) =>
  typeof ms === "number" && Number.isFinite(ms) ? new Date(ms).toISOString() : null;

function readJson(url: URL) {
  try {
    return JSON.parse(readFileSync(url, "utf8"));
  } catch {
    return undefined;
  }
}

let cachedBuild: BuildIdentity | undefined;
/** Package root is the parent of the compiled `dist` directory, in both a source
 * checkout and an extracted release. BUILD.json exists only in release artifacts. */
export function buildIdentity(root = new URL("../", import.meta.url)): BuildIdentity {
  if (cachedBuild && root.href === new URL("../", import.meta.url).href) return cachedBuild;
  const pkg = readJson(new URL("package.json", root)),
    build = readJson(new URL("BUILD.json", root));
  const identity = {
    package_version: typeof pkg?.version === "string" ? pkg.version : null,
    protocol_version: "0.11.0",
    source_commit:
      typeof build?.source === "string" && /^[0-9a-f]{40}$/.test(build.source)
        ? build.source
        : null,
    build_run:
      typeof build?.run_id === "string" && build.run_id
        ? `${build.run_id}/${build.run_attempt ?? "?"}`
        : null,
  };
  if (root.href === new URL("../", import.meta.url).href) cachedBuild = identity;
  return identity;
}

type Stage = "asked" | "delivered" | "read" | "replied" | "acknowledged";

/** A status reader is an operator-like principal: thread callers authenticate
 * for one exact exchange binding and never see aggregate deployment state. */
export function statusPrincipal(policy, owner: string) {
  const p = policy.principals.find((x) => x.id === owner && x.enabled !== false);
  return p && !p.eddieCaller && !p.eddieHostCaller ? p : undefined;
}

const fresh = (now: number, at: number | null) =>
  at !== null && at - now <= CLOCK_SKEW_MS && now - at <= JOURNEY_FRESH_MS;

function exchangeStage(r, wakeDelivered: boolean): Stage {
  if (r.acknowledgedAt !== undefined) return "acknowledged";
  if (r.reply !== null) return "replied";
  if (r.readAt !== null) return "read";
  if (wakeDelivered) return "delivered";
  return "asked";
}

function askEddieJourney(bridge: Bridge, principal, now: number) {
  // Only the principal's current inbox scope: a former inbox sees nothing.
  const mine = principal.eddieInbox
    ? bridge.store
        .all("exchange")
        .filter((r) => r.reviewer === principal.id)
        .sort((a, b) => a.createdAt - b.createdAt || (a.sequence ?? 0) - (b.sequence ?? 0))
    : [];
  const deliveries = mine.length ? bridge.store.all("delivery") : [];
  const wakeDelivered = (r) =>
    deliveries.some(
      (d) =>
        d.status === "acknowledged" &&
        d.event?.name === "t3.eddie.requested" &&
        d.event.data?.request_id === r.request_id,
    );
  // The last completion is the newest acknowledgement, not the newest question.
  const last = mine
    .filter((r) => r.acknowledgedAt !== undefined)
    .reduce((m, r) => (!m || r.acknowledgedAt > m.acknowledgedAt ? r : m), undefined);
  const latest = mine.at(-1);
  // Any unfinished request (including one that expired unanswered) older than
  // the stuck window, with no completion acknowledged after it was asked, keeps
  // the journey failing even when newer requests arrive.
  const stuck = mine.some(
    (r) =>
      r.acknowledgedAt === undefined &&
      now - r.createdAt > JOURNEY_STUCK_MS &&
      (!last || last.acknowledgedAt <= r.createdAt),
  );
  const lastAt = last ? last.acknowledgedAt : null;
  return {
    state: !mine.length
      ? "unverified"
      : stuck
        ? "failing"
        : fresh(now, lastAt)
          ? "verified"
          : last
            ? "stale"
            : "unverified",
    // Verifies the question/answer loop. Whether the wake webhook reached Eddie
    // is reported per exchange (`wake_delivered`) and by `event_delivery`; Eddie
    // may also have found the request by polling its inbox.
    stages: ["asked", "delivered", "read", "replied", "acknowledged"],
    last_verified: last
      ? {
          request_id: last.request_id,
          asked_at: iso(last.createdAt),
          replied_at: iso(last.repliedAt),
          acknowledged_at: iso(last.acknowledgedAt),
          wake_delivered: wakeDelivered(last),
        }
      : null,
    latest: latest
      ? {
          request_id: latest.request_id,
          asked_at: iso(latest.createdAt),
          stage_reached: exchangeStage(latest, wakeDelivered(latest)),
          wake_delivered: wakeDelivered(latest),
          expired: latest.reply === null && latest.expiresAt <= now,
        }
      : null,
  };
}

function deliveryJourney(bridge: Bridge, owner: string, now: number) {
  // Only the owner's currently active subscriptions; revoked or expired
  // subscriptions stop contributing evidence.
  const subs = new Set(
    bridge.store
      .all("subscription")
      .filter((s) => s.owner === owner && subscriptionState(s, now) === "active")
      .map((s) => s.id),
  );
  const mine = subs.size ? bridge.store.all("delivery").filter((d) => subs.has(d.subId)) : [];
  // Delivery records keep only their latest state; the audit log timestamps each
  // attempt (`webhook.delivery`) or central reconciliation (`.central`, stamped
  // when the receipt is observed). Ownership filtering precedes the limit, and
  // audit sequence breaks same-millisecond ties.
  let lastAck: { at: string; seq: number } | null = null;
  let lastFailure: { at: string; seq: number; outcome: string } | null = null;
  for (const row of bridge.store.recentDeliveryOutcomes(
    mine.map((d) => d.id),
    new Date(now - 7 * 86400000).toISOString(),
  )) {
    if (String(row.outcome).startsWith("acknowledged:")) lastAck ??= { at: row.at, seq: row.seq };
    else lastFailure ??= { at: row.at, seq: row.seq, outcome: String(row.outcome) };
    if (lastAck && lastFailure) break;
  }
  const pending = mine.filter((d) =>
    ["pending", "claimed", "sending", "centralized"].includes(d.status),
  );
  const oldestPending = pending.reduce(
    (m, d) => Math.min(m, Date.parse(d.event?.timestamp) || Infinity),
    Infinity,
  );
  const ackMs = lastAck ? Date.parse(lastAck.at) : null;
  const stuck =
    Number.isFinite(oldestPending) &&
    now - oldestPending > JOURNEY_STUCK_MS &&
    (ackMs === null || ackMs <= oldestPending);
  return {
    state: !mine.length
      ? "unverified"
      : stuck || (lastFailure && (!lastAck || lastFailure.seq > lastAck.seq) && !pending.length)
        ? "failing"
        : fresh(now, ackMs)
          ? "verified"
          : ackMs !== null
            ? "stale"
            : "unverified",
    last_acknowledged_at: lastAck?.at ?? null,
    last_failure: lastFailure ? { at: lastFailure.at, outcome: lastFailure.outcome } : null,
    pending: pending.length,
    stopped: mine.filter((d) => d.status === "stopped").length,
    note: "A 2xx webhook response proves receipt by the callback endpoint, not agent execution.",
  };
}

function hostStatus(bridge: Bridge, principal) {
  const hosts = [...new Set((principal.readHosts ?? []).map((h) => h.host))].sort();
  return hosts.map((host) => {
    let latest;
    try {
      latest = bridge.store.latestDiagnostic(host);
    } catch {
      latest = undefined;
    }
    return {
      host,
      last_observed_at: typeof latest?.at === "string" ? latest.at : null,
      last_stage: typeof latest?.stage === "string" ? latest.stage : null,
      last_outcome:
        latest?.outcome === "ok" || latest?.outcome === "failed" ? latest.outcome : "unknown",
      last_reason: typeof latest?.reason === "string" ? latest.reason : null,
    };
  });
}

type Evidence = {
  at: number;
  journeys: {
    ask_eddie: ReturnType<typeof askEddieJourney>;
    event_delivery: ReturnType<typeof deliveryJourney>;
  };
  hosts: ReturnType<typeof hostStatus>;
};
const cache = new WeakMap<Bridge, Map<string, Evidence>>();

/** Returns undefined when `owner` may not read aggregate status. Pass the policy
 * snapshot already used to authenticate so one request reads it once. */
export function statusReport(bridge: Bridge, owner: string, policy = bridge.policy()) {
  const principal = statusPrincipal(policy, owner);
  if (!principal) return undefined;
  const now = bridge.now();
  const perBridge = cache.get(bridge) ?? new Map<string, Evidence>();
  cache.set(bridge, perBridge);
  const hit = perBridge.get(owner);
  // Store-derived evidence is reused briefly so polling cannot monopolise the
  // event loop; lease state is cheap and always current.
  const evidence: Evidence =
    hit && now >= hit.at && now - hit.at < STATUS_CACHE_MS
      ? hit
      : {
          at: now,
          journeys: {
            ask_eddie: askEddieJourney(bridge, principal, now),
            event_delivery: deliveryJourney(bridge, owner, now),
          },
          hosts: hostStatus(bridge, principal),
        };
  perBridge.set(owner, evidence);
  const runtime: RuntimeStatus = bridge.runtimeStatus?.() ?? {
    mode: "standalone",
    lease: { state: "not_applicable" },
  };
  const leaseState = runtime.lease.state;
  const states = [evidence.journeys.ask_eddie.state, evidence.journeys.event_delivery.state];
  const overall =
    leaseState === "lost"
      ? "down"
      : leaseState === "unknown" || leaseState === "renewal_failing" || states.includes("failing")
        ? "degraded"
        : states.every((s) => s === "verified")
          ? "ok"
          : "unverified";
  return {
    schema: STATUS_SCHEMA,
    observed_at: iso(now),
    evidence_observed_at: iso(evidence.at),
    overall,
    build: buildIdentity(),
    runtime,
    // Not observed yet: native build identity arrives with adapter negotiation (#62).
    native: { t3_build: null },
    state_authority:
      runtime.mode === "central_edge" && leaseState !== "held"
        ? "local_cache_without_lease"
        : "local",
    journeys: evidence.journeys,
    hosts: evidence.hosts,
    freshness_ms: { verified_within: JOURNEY_FRESH_MS, stuck_after: JOURNEY_STUCK_MS },
  };
}
