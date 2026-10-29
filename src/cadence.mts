// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { Policy } from "./config.mjs";
import type { Store } from "./store.mjs";
import type { FleetReader } from "./fleet-read.mjs";
import type { NativeRecord } from "./contracts.mjs";
import { cadenceManifest, type CadenceGoal, type CadenceTarget } from "./cadence-manifest.mjs";
import { subscriptionActive, subscriptionExpiry } from "./subscription-state.mjs";
import { readReason } from "./read-errors.mjs";
import { z } from "zod";

export const cadenceOverviewArgs = z
  .object({
    after_change: z.number().int().min(0).optional(),
    cursor: z.string().max(4096).optional(),
    limit: z.number().int().min(1).max(20).optional(),
  })
  .strict();

const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const fail = (reason: string) => Object.assign(Error(reason), { reason });
const terminal = new Set(["completed", "failed", "cancelled", "interrupted", "rolled_back"]);
const running = new Set(["preparing", "starting", "running", "waiting"]);
const time = (value: unknown): number | null => {
  const result =
    typeof value === "number" ? value : typeof value === "string" ? Date.parse(value) : NaN;
  return Number.isFinite(result) && result >= 0 && result <= 8640000000000000 ? result : null;
};
const iso = (value: number | null) => (value === null ? null : new Date(value).toISOString());
const targetKey = (
  owner: string,
  target: Pick<CadenceTarget, "host" | "project_id" | "thread_id">,
) => hash([owner, target.host, target.project_id, target.thread_id]);
export const cadenceEventKey = (value: {
  host: string;
  thread_id: string;
  run_id: string;
  kind: string;
  native_request_id?: string;
}) =>
  hash([value.host, value.thread_id, value.run_id, value.kind, value.native_request_id ?? null]);
interface Run {
  id: string;
  status: string;
  at: number | null;
  activity: number | null;
}
interface Snapshot {
  host: string;
  project: string;
  thread: string;
  version: number | null;
  observed: number;
  runs: Run[];
  activity: number | null;
  ambiguous: boolean;
}
interface Checkpoint {
  definition?: string;
  revision?: number;
  material?: string;
  change?: number;
  progress?: number | null;
  progressEvidence?: string[];
  activity?: number | null;
  visibility?: boolean;
  gap?: number | null;
  reconciled?: number | null;
  phase?: string;
}
interface ReadContext {
  subscriptions: NativeRecord[];
  deliveries: NativeRecord[];
  truncated: boolean;
}
interface Dependencies {
  policy(): Policy;
  store: Store;
  reader: FleetReader;
  manifest(): unknown;
  now?: () => number;
}
export class Cadence {
  readonly now: () => number;
  constructor(readonly dependencies: Dependencies) {
    this.now = dependencies.now ?? Date.now;
  }
  definitions() {
    try {
      return cadenceManifest.parse(this.dependencies.manifest());
    } catch {
      throw fail("cadence_manifest_unavailable");
    }
  }
  principal(owner: string) {
    const p = this.dependencies
      .policy()
      .principals.find((p) => p.id === owner && p.enabled !== false);
    if (!p || p.eddieCaller || p.eddieHostCaller) throw fail("forbidden");
    return p;
  }
  access(owner: string, goal: CadenceGoal) {
    this.principal(owner);
    if (goal.owner !== owner) throw fail("forbidden");
    for (const target of goal.targets)
      this.dependencies.reader.grant(owner, target.host, target.project_id);
  }
  // Only existing authorized native readers call this hook. No new scanner,
  // subscription or native operation is started here. No agent text is stored.
  observe(owner: string, input: { host: string; thread_id: string }, data: unknown) {
    const goals = this.definitions().goals.filter(
      (g) =>
        g.owner === owner &&
        g.targets.some((t) => t.host === input.host && t.thread_id === input.thread_id),
    );
    if (!goals.length) return;
    const raw = data as {
      thread?: { threadId?: string; projectId?: string; updatedAt?: unknown };
      runs?: unknown[];
      recentRuns?: unknown[];
      items?: unknown[];
    };
    if (raw?.thread?.threadId !== input.thread_id || typeof raw.thread.projectId !== "string")
      throw fail("identity_mismatch");
    const project = raw.thread.projectId;
    this.dependencies.reader.grant(owner, input.host, project);
    if (
      !goals.some((g) =>
        g.targets.some(
          (t) =>
            t.host === input.host && t.thread_id === input.thread_id && t.project_id === project,
        ),
      )
    )
      return;
    const now = this.now(),
      validTime = (value: unknown) => {
        const t = time(value);
        return t !== null && t <= now + 60000 ? t : null;
      };
    const rows = raw.runs ?? raw.recentRuns;
    if (!Array.isArray(rows) || rows.length > 20) throw fail("source_protocol_error");
    const runs: Run[] = rows.map((value) => {
      const r = value as {
        runId?: string;
        id?: string;
        status?: string;
        requestedAt?: unknown;
        startedAt?: unknown;
        completedAt?: unknown;
      };
      const id = r?.runId ?? r?.id;
      if (typeof id !== "string" || typeof r.status !== "string")
        throw fail("source_protocol_error");
      const activity = [r.requestedAt, r.startedAt, r.completedAt]
        .map(validTime)
        .filter((t) => t !== null);
      return {
        id,
        status: r.status,
        at: validTime(r.completedAt),
        activity: activity.length ? Math.max(...activity) : null,
      };
    });
    runs.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    if (new Set(runs.map((r) => r.id)).size !== runs.length) throw fail("identity_mismatch");
    const activity = [validTime(raw.thread.updatedAt), ...runs.map((r) => r.activity)].filter(
      (t) => t !== null,
    );
    const snapshot: Snapshot = {
      host: input.host,
      project,
      thread: input.thread_id,
      observed: now,
      version: validTime(raw.thread.updatedAt),
      runs,
      activity: activity.length ? Math.max(...activity) : null,
      ambiguous: false,
    };
    const key = targetKey(owner, {
      host: input.host,
      project_id: project,
      thread_id: input.thread_id,
    });
    const old = this.dependencies.store.get("cadence.snapshot", key) as Snapshot | undefined;
    if (old) {
      if (old.version !== null && (snapshot.version === null || snapshot.version < old.version))
        return;
      // Same native version with contradictory state cannot be promoted by
      // response arrival order. A strictly newer projection reconciles it.
      if (snapshot.version === old.version && hash(snapshot.runs) !== hash(old.runs))
        snapshot.ambiguous = true;
      if (old.ambiguous && snapshot.version === old.version) snapshot.ambiguous = true;
      for (const run of snapshot.runs) {
        const previous = old.runs.find((r) => r.id === run.id);
        if (
          previous &&
          terminal.has(previous.status) &&
          !terminal.has(run.status) &&
          (snapshot.version === null || snapshot.version === old.version)
        )
          snapshot.ambiguous = true;
      }
    }
    this.dependencies.store.put("cadence.snapshot", key, snapshot);
    this.dependencies.store.put("cadence.source", key, { failed: false });
  }
  context(owner: string): ReadContext {
    const subscriptions = this.dependencies.store
      .all("subscription")
      .filter((s) => s.owner === owner);
    const index = new Map(subscriptions.map((s) => [s.id, s]));
    const window = this.dependencies.store.recent("delivery", 2000);
    return {
      subscriptions,
      deliveries: window.records
        .filter((r) => index.has(r.subId))
        .map((r) => ({ ...r, subscription: index.get(r.subId) })),
      truncated: window.truncated,
    };
  }
  sourceFailure(owner: string, input: { host: string; thread_id: string }, error: unknown) {
    for (const goal of this.definitions().goals.filter((g) => g.owner === owner)) {
      try {
        this.access(owner, goal);
      } catch {
        continue;
      }
      for (const target of goal.targets.filter(
        (t) => t.host === input.host && t.thread_id === input.thread_id,
      ))
        this.dependencies.store.put("cadence.source", targetKey(owner, target), {
          failed: true,
          reason: readReason(error),
        });
    }
  }
  coverage(
    owner: string,
    target: CadenceTarget,
    snapshot: Snapshot | undefined,
    context: ReadContext,
  ) {
    const { store, policy } = this.dependencies,
      now = this.now(),
      p = this.principal(owner);
    const subscriptions = context.subscriptions.filter(
      (s) =>
        s.owner === owner &&
        (s.name === "t3.fleet.activity" ||
          (s.name === "t3.thread.activity" &&
            s.host === target.host &&
            s.threadId === target.thread_id &&
            s.projectId === target.project_id)),
    );
    const active = subscriptions.filter((s) => subscriptionActive(s, now));
    const scans = active
      .filter((s) => s.name === "t3.fleet.activity")
      .map((s) => store.get("fleet_scan", hash([s.id, target.host])))
      .filter(Boolean);
    const scan = scans.sort(
      (a, b) => (time(b.lastCompleteAt) ?? 0) - (time(a.lastCompleteAt) ?? 0),
    )[0];
    const settings = policy().cadence;
    const freshness = settings?.freshForMs ?? 120000;
    const source = store.get("cadence.source", targetKey(owner, target));
    const nativeFresh =
      !!snapshot &&
      snapshot.observed <= now &&
      now - snapshot.observed <= freshness &&
      !snapshot.ambiguous &&
      !source?.failed;
    const grant = p.commandHosts?.find((g) => g.host === target.host);
    const commandLive =
      !!grant &&
      grant.expiresAt > now &&
      (!grant.projectIds || grant.projectIds.includes(target.project_id));
    const completeAt = time(scan?.lastCompleteAt);
    const scanFresh =
      completeAt !== null &&
      completeAt <= now &&
      now - completeAt <= freshness &&
      scan?.state === "available";
    // Exact lanes have no fleet scan completeness claim. Current exact native
    // reconciliation remains distinct from continuous aggregate coverage.
    const monitored = active.length > 0 && commandLive;
    return {
      native_fresh: nativeFresh,
      last_native_observation: iso(snapshot?.observed ?? null),
      source_failure: source?.failed ? source.reason : null,
      ambiguous_native_version: snapshot?.ambiguous ?? false,
      monitoring_active: monitored,
      command_grant_expires_at: iso(grant?.expiresAt ?? null),
      command_grant_expired: !!grant && grant.expiresAt <= now,
      subscription_records_truncated: subscriptions.length > 32,
      subscriptions: subscriptions.slice(0, 32).map((s) => ({
        id: s.id,
        active: subscriptionActive(s, now),
        expires_at:
          s.expires === null || (typeof s.expires === "number" && Number.isFinite(s.expires))
            ? subscriptionExpiry(s)
            : null,
      })),
      scan_complete: scan ? !scan.cursor && scan.state === "available" : null,
      scan_state: scan?.state ?? "not_observed",
      scan_reason: scan?.reason ?? null,
      scan_in_progress: !!scan?.cursor,
      last_complete_scan: iso(completeAt),
      scan_fresh: scanFresh,
      historical_completeness: false,
      retained_native_runs: 20,
      visibility: nativeFresh ? "visible" : snapshot?.ambiguous ? "inconsistent" : "unknown",
      no_progress_assessable: nativeFresh && monitored && (scans.length === 0 || scanFresh),
    };
  }
  handoffs(owner: string, goal: CadenceGoal) {
    return goal.handoffs.map((h) => {
      const t = goal.targets[h.target],
        record = this.dependencies.store.get("command", h.request_id),
        now = this.now();
      const r =
        record?.owner === owner &&
        record.host === t.host &&
        record.projectId === t.project_id &&
        record.thread_id === t.thread_id &&
        (record.runId === t.run_id || record.sourceRunId === t.run_id)
          ? record
          : undefined;
      const proposed = time(h.proposed_at)!;
      const accepted =
        h.acceptance?.by === h.to &&
        time(h.acceptance.at)! >= proposed &&
        time(h.acceptance.at)! <= now;
      const acknowledged =
        accepted &&
        h.acknowledgement?.by === h.to &&
        time(h.acknowledgement.at)! >= time(h.acceptance.at)! &&
        time(h.acknowledgement.at)! <= now;
      return {
        id: h.id,
        from: h.from,
        to: h.to,
        request_id: h.request_id,
        target: t,
        ownership: acknowledged ? "acknowledged" : accepted ? "accepted" : "proposed",
        ownership_source: "owner_record",
        accepted_at: accepted ? h.acceptance.at : null,
        acknowledged_at: acknowledged ? h.acknowledgement.at : null,
        delivery: !r
          ? "not_observed"
          : r.submission === "accepted"
            ? "native_submitted"
            : r.submission === "outcome_unknown"
              ? "uncertain"
              : "stored",
        native_receipt_id: r?.commandId ?? null,
        native_message_id: r?.messageId ?? null,
        native_run_id: r?.runId ?? null,
        native_run_status: r?.runStatus ?? null,
        native_message_observation: r?.messageObservation
          ? {
              message_id: r.messageObservation.message_id ?? null,
              run_id: r.messageObservation.run_id ?? null,
              run_status: r.messageObservation.run_status ?? null,
              input_intent: r.messageObservation.input_intent ?? null,
              observed_at: r.messageObservation.observed_at ?? null,
            }
          : null,
        agent_delivery_acknowledged_at: iso(time(r?.ackAt)),
        delivery_acknowledgement_is_ownership_acceptance: false,
        safe_to_resend: false,
      };
    });
  }
  events(owner: string, goal: CadenceGoal, context: ReadContext) {
    const window = { records: context.deliveries, truncated: context.truncated },
      unique = new Map<
        string,
        {
          key: string;
          at: number;
          kind: string;
          run_id: string;
          target: CadenceTarget;
          status?: string;
          deliveryStates: string[];
          observedAt: number | null;
        }
      >();
    for (const record of window.records) {
      const sub = record.subscription;
      if (sub?.owner !== owner || !record.event?.data) continue;
      const d = record.event.data,
        session = this.dependencies.policy().sessions.find((s) => s.id === d.session_id);
      const host = d.host ?? sub.host ?? session?.host,
        thread_id = d.thread_id ?? sub.threadId ?? session?.threadId;
      const target = goal.targets.find((t) => t.host === host && t.thread_id === thread_id);
      const kind = d.kind ?? (record.event.name === "t3.task.finished" ? "task_finished" : null),
        at = time(record.event.timestamp);
      if (
        !target ||
        !["task_finished", "input_requested"].includes(kind) ||
        (kind === "input_requested" && typeof d.native_request_id !== "string") ||
        typeof d.run_id !== "string" ||
        at === null ||
        at < time(goal.created_at)! ||
        at > this.now() + 60000 ||
        (d.project_id && d.project_id !== target.project_id)
      )
        continue;
      const key = cadenceEventKey({
        host,
        thread_id,
        run_id: d.run_id,
        kind,
        ...(typeof d.native_request_id === "string"
          ? { native_request_id: d.native_request_id }
          : {}),
      });
      const old = unique.get(key);
      // Earliest delivery observation wins across aggregate/exact subscriptions;
      // replays with newer arrival timestamps cannot manufacture new activity.
      const observed = time(record.observedAt);
      const observations = [old?.observedAt, observed].filter((v) => typeof v === "number");
      unique.set(key, {
        key,
        at: Math.min(old?.at ?? at, at),
        kind,
        run_id: d.run_id,
        target,
        status: d.status,
        deliveryStates: [...new Set([...(old?.deliveryStates ?? []), record.status])].sort(),
        observedAt: observations.length ? Math.min(...observations) : null,
      });
    }
    return {
      events: [...unique.values()].sort((a, b) => a.at - b.at || a.key.localeCompare(b.key)),
      truncated: window.truncated,
    };
  }
  project(owner: string, goal: CadenceGoal, context = this.context(owner)) {
    this.access(owner, goal);
    const { store } = this.dependencies,
      now = this.now(),
      created = time(goal.created_at)!;
    const key = hash([owner, goal.id]),
      old = (store.get("cadence.goal", key) ?? {}) as Checkpoint;
    if ((old.revision ?? 0) > goal.revision) throw fail("cadence_definition_regressed");
    const definition = hash(goal),
      snapshots = goal.targets.map(
        (t) => store.get("cadence.snapshot", targetKey(owner, t)) as Snapshot | undefined,
      );
    if (
      old.revision === goal.revision &&
      old.definition !== undefined &&
      old.definition !== definition
    )
      throw fail("cadence_definition_conflict");
    const coverage = goal.targets.map((t, i) => ({
      target: t,
      ...this.coverage(owner, t, snapshots[i], context),
    }));
    const runs = goal.targets.map((t, i) => ({
      target: t,
      run: snapshots[i]?.runs.find((r) => r.id === t.run_id),
    }));
    const workRuns = runs.filter((r) => r.target.role === "work");
    const workSnapshots = snapshots.filter((_, i) => goal.targets[i].role === "work");
    const staleCompletion = workRuns.some(
      (r) => r.run?.status === "completed" && (r.run.at === null || r.run.at < created),
    );
    const complete =
      !staleCompletion &&
      workRuns.every(
        (r) => r.run?.status === "completed" && r.run.at !== null && r.run.at >= created,
      );
    const failed = workRuns.some(
      (r) => r.run && terminal.has(r.run.status) && r.run.status !== "completed",
    );
    const visible =
      coverage.filter((c) => c.target.role === "work").every((c) => c.native_fresh) &&
      workRuns.every(
        (r) =>
          !!r.run &&
          (terminal.has(r.run.status) || running.has(r.run.status) || r.run.status === "queued"),
      );
    const handoffs = this.handoffs(owner, goal),
      events = this.events(owner, goal, context);
    const criteria = goal.finish_criteria.map((c) => {
      const artifact = goal.artifacts.find((a) => a.id === c.artifact_id)!;
      const t = goal.targets[artifact.target];
      const verification = goal.verifications.find(
        (v) =>
          v.criterion_id === c.id &&
          v.goal_revision === goal.revision &&
          v.artifact_id === artifact.id &&
          v.artifact_revision === artifact.revision &&
          v.target_run_id === t.run_id &&
          v.assertion === c.assertion &&
          v.independent_of === goal.execution_owner &&
          v.verifier !== goal.execution_owner &&
          time(v.verified_at)! >= created &&
          time(v.verified_at)! <= now,
      );
      return { ...c, artifact, verified: !!verification, verification: verification ?? null };
    });
    const verified = visible && complete && criteria.every((c) => c.verified);
    const phase = verified
      ? "independently_verified"
      : complete
        ? "completed"
        : workRuns.some((r) => r.run && running.has(r.run.status))
          ? "running"
          : workRuns.some((r) => r.run?.status === "queued") ||
              handoffs.some(
                (h) =>
                  h.target.role === "work" &&
                  (h.ownership !== "proposed" || h.delivery === "native_submitted"),
              )
            ? "accepted"
            : "planned";
    const evidence = [
      ...workRuns
        .filter(
          (r) => r.run && terminal.has(r.run.status) && r.run.at !== null && r.run.at >= created,
        )
        .map((r) => ({ key: hash([r.target, r.run.status]), at: r.run.at! })),
      ...criteria
        .filter((c) => c.verified)
        .map((c) => ({ key: hash([c.id, c.verification]), at: time(c.verification.verified_at)! })),
      ...handoffs
        .filter((h) => h.target.role === "work" && h.ownership !== "proposed")
        .map((h) => ({
          key: hash([h.id, h.ownership]),
          at: time(h.acknowledged_at ?? h.accepted_at)!,
        })),
    ];
    const sameDefinition = old.definition === definition;
    const previousEvidence = sameDefinition ? (old.progressEvidence ?? []) : [];
    // Definition edits, read times, scan times, checks and watcher activity are
    // never progress. Only explicitly bound, independently identified facts are.
    const newEvidence = evidence.filter((e) => !previousEvidence.includes(e.key));
    const progress = visible
      ? Math.max(old.progress ?? 0, ...newEvidence.map((e) => e.at)) || null
      : (old.progress ?? null);
    const activity =
      Math.max(
        old.activity ?? 0,
        ...snapshots.map((s) => s?.activity ?? 0),
        ...events.events.map((e) => e.at),
      ) || null;
    const gap = !visible ? (old.visibility === false ? (old.gap ?? now) : now) : (old.gap ?? null);
    const reconciled =
      visible &&
      gap !== null &&
      (old.reconciled ?? -1) < gap &&
      workSnapshots.every((s) => s.observed >= gap)
        ? Math.min(...workSnapshots.map((s) => s.observed))
        : (old.reconciled ?? null);
    const repetition = events.events.filter(
      (e) =>
        e.at > (progress ?? created) &&
        !(
          e.kind === "task_finished" &&
          workRuns.some((r) => r.target.run_id === e.run_id && r.run && terminal.has(r.run.status))
        ),
    ).length;
    const assessable =
      visible &&
      !staleCompletion &&
      coverage.every((c) => c.no_progress_assessable) &&
      !events.truncated &&
      (gap === null || (reconciled !== null && reconciled >= gap));
    const noProgress = Math.max(0, now - (progress ?? created));
    const settings = this.dependencies.policy().cadence;
    const pending = events.events.filter((e) => e.deliveryStates.includes("pending"));
    const oldestPending = pending.length ? Math.min(...pending.map((e) => e.at)) : null;
    const recordedLags = events.events
      .filter((e) => e.observedAt !== null)
      .map((e) => Math.max(0, e.observedAt! - e.at));
    const eventLag = {
      oldest_pending_event_at: iso(oldestPending),
      oldest_pending_age_ms: oldestPending === null ? null : Math.max(0, now - oldestPending),
      pending_events: pending.length,
      acknowledged_events: events.events.filter((e) => e.deliveryStates.includes("acknowledged"))
        .length,
      stopped_events: events.events.filter(
        (e) => e.deliveryStates.includes("stopped") || e.deliveryStates.includes("revoked"),
      ).length,
      max_recorded_observation_lag_ms: recordedLags.length ? Math.max(...recordedLags) : null,
      lagging: oldestPending !== null && now - oldestPending > (settings?.freshForMs ?? 120000),
      historical_completeness: false,
      delivery_acknowledgement_is_agent_execution: false,
    };
    const loop =
      assessable &&
      noProgress >= (settings?.noProgressMs ?? 900000) &&
      repetition >= (settings?.repetitionThreshold ?? 3);
    const unowned = goal.next_action.owner === null;
    const bucket = !visible
      ? "visibility_gap"
      : verified
        ? "verified_done"
        : unowned || staleCompletion || goal.next_action.decision_needed || (complete && !verified)
          ? "decision_needed"
          : failed || !!goal.next_action.waiting_reason || loop
            ? "blocked"
            : "moving";
    const view = {
      goal_id: goal.id,
      title: goal.title,
      owner,
      definition_revision: goal.revision,
      execution_owner: goal.execution_owner,
      targets: runs.map((r) => ({
        ...r.target,
        native_status: r.run?.status ?? "not_in_retained_window",
      })),
      artifacts: goal.artifacts,
      finish_criteria: criteria,
      next_action: goal.next_action,
      unowned_next_step: unowned,
      phase: visible ? phase : "unknown",
      last_known_phase: visible ? phase : (old.phase ?? null),
      bucket,
      last_activity: iso(activity),
      last_meaningful_progress: iso(progress),
      handoffs,
      coverage,
      stale_completion: staleCompletion,
      no_progress_loop: loop,
      no_progress_assessable: assessable,
      repetitive_activity_count: repetition,
      recovery: {
        gap_observed_at: iso(gap),
        reconciled_at: iso(reconciled),
        status: !visible
          ? "visibility_gap"
          : gap !== null && (reconciled === null || reconciled < gap)
            ? "reconciliation_required"
            : "current_projection_only",
        historical_completeness: false,
      },
      event_window_truncated: events.truncated,
      event_lag: eventLag,
      verification_provenance:
        "owner_supplied_independent_attestation; never inferred from agent text or checks",
      execution_authority: "none",
      automatic_nudges: false,
      safe_to_resend: false,
    };
    const { oldest_pending_age_ms: _age, ...stableLag } = eventLag;
    const material = hash({
      ...view,
      event_lag: stableLag,
      coverage: coverage.map(
        ({ last_native_observation: _observation, last_complete_scan: _scan, ...stable }) => stable,
      ),
    });
    let change = old.change ?? 0;
    store.transaction(() => {
      if (old.material !== material) {
        const sequence = store.get("cadence.sequence", owner)?.value ?? 0;
        change = sequence + 1;
        store.put("cadence.sequence", owner, { value: change });
      }
      const checkpoint = {
        definition,
        revision: goal.revision,
        material,
        change,
        progress,
        progressEvidence: visible ? evidence.map((e) => e.key) : (old.progressEvidence ?? []),
        activity,
        visibility: visible,
        gap,
        reconciled,
        phase: visible ? phase : old.phase,
      };
      if (hash(checkpoint) !== hash(old)) store.put("cadence.goal", key, checkpoint);
    });
    this.access(owner, goal);
    return {
      ...view,
      change_sequence: change,
      change_key: material,
      observed_at: iso(now),
      no_progress_for_ms: noProgress,
    };
  }
  async detail(owner: string, goalId: string) {
    const goal = this.definitions().goals.find((g) => g.owner === owner && g.id === goalId);
    if (!goal) throw fail("forbidden");
    this.access(owner, goal);
    const before = hash(goal),
      failures: { target: CadenceTarget; reason: string }[] = [];
    for (const target of goal.targets) {
      try {
        const snapshot = await this.dependencies.reader.read(owner, {
          host: target.host,
          thread_id: target.thread_id,
        });
        if (snapshot.thread.projectId !== target.project_id) throw fail("identity_mismatch");
        this.observe(owner, target, snapshot);
      } catch (e) {
        if (["forbidden", "identity_mismatch"].includes(e.reason)) throw e;
        failures.push({ target, reason: readReason(e) });
        this.dependencies.store.put("cadence.source", targetKey(owner, target), {
          failed: true,
          reason: readReason(e),
        });
      }
    }
    const current = this.definitions().goals.find((g) => g.owner === owner && g.id === goalId);
    if (!current || hash(current) !== before) throw fail("cadence_definition_changed");
    return { ...this.project(owner, current), native_read_failures: failures };
  }
  signature(value: string) {
    return createHmac("sha256", this.dependencies.store.key)
      .update("kadenco:cadence:v1:" + value)
      .digest();
  }
  overview(owner: string, input: { after_change?: number; cursor?: string; limit?: number } = {}) {
    this.principal(owner);
    input = cadenceOverviewArgs.parse(input);
    const manifest = this.definitions(),
      after = input.after_change ?? 0;
    const visible = manifest.goals
      .filter((g) => g.owner === owner)
      .filter((g) => {
        try {
          this.access(owner, g);
          return true;
        } catch {
          return false;
        }
      });
    const definition = hash(visible);
    let last = "",
      upper: number | undefined;
    if (input.cursor) {
      try {
        const [body, signature] = input.cursor.split("."),
          actual = Buffer.from(signature, "base64url"),
          expected = this.signature(body);
        if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) throw Error();
        const cursor = JSON.parse(Buffer.from(body, "base64url").toString());
        if (cursor.owner !== owner || cursor.definition !== definition || cursor.after !== after)
          throw Error();
        last = cursor.last;
        upper = cursor.upper;
      } catch {
        throw fail("invalid_cadence_cursor");
      }
    }
    const context = this.context(owner);
    const rows = visible
      .map((g) => this.project(owner, g, context))
      .sort((a, b) => (a.goal_id < b.goal_id ? -1 : a.goal_id > b.goal_id ? 1 : 0));
    upper ??= this.dependencies.store.get("cadence.sequence", owner)?.value ?? 0;
    const candidates = rows.filter(
      (r) => r.change_sequence > after && r.change_sequence <= upper && r.goal_id > last,
    );
    const limit = Math.min(20, Math.max(1, input.limit ?? 10)),
      page = candidates.slice(0, limit);
    for (const row of page)
      this.access(
        owner,
        visible.find((g) => g.id === row.goal_id)!,
      );
    const payload = Buffer.from(
      JSON.stringify({ owner, definition, after, upper, last: page.at(-1)?.goal_id }),
    ).toString("base64url");
    return {
      goals: page.map((row) => ({
        goal_id: row.goal_id,
        title: row.title,
        owner: row.owner,
        definition_revision: row.definition_revision,
        targets: row.targets,
        phase: row.phase,
        last_known_phase: row.last_known_phase,
        bucket: row.bucket,
        next_action: row.next_action,
        unowned_next_step: row.unowned_next_step,
        last_activity: row.last_activity,
        last_meaningful_progress: row.last_meaningful_progress,
        no_progress_loop: row.no_progress_loop,
        no_progress_assessable: row.no_progress_assessable,
        criteria_verified: row.finish_criteria.filter((c) => c.verified).length,
        criteria_total: row.finish_criteria.length,
        coverage: row.coverage.map(({ subscriptions: _subscriptions, ...summary }) => summary),
        recovery: row.recovery,
        event_lag: row.event_lag,
        change_sequence: row.change_sequence,
        change_key: row.change_key,
      })),
      next_cursor:
        candidates.length > limit
          ? payload + "." + this.signature(payload).toString("base64url")
          : null,
      high_water_change: upper,
      definition_key: definition,
      total_visible_goals: rows.length,
      buckets: Object.fromEntries(
        ["moving", "blocked", "decision_needed", "verified_done", "visibility_gap"].map(
          (bucket) => [bucket, rows.filter((r) => r.bucket === bucket).length],
        ),
      ),
      consistency:
        "Cached authorized observations; detail performs exact native reconciliation. Finish all cursor pages before advancing after_change. Rebuild on definition_key change. Ages/read times do not produce material changes. Invisible is not stalled; retained windows are not complete history.",
      execution_authority: "none",
      new_monitors: 0,
    };
  }
}
