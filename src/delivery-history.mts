// SPDX-License-Identifier: AGPL-3.0-or-later
import { z } from "zod";
import type { Bridge } from "./bridge.mjs";
import { subscriptionActive } from "./subscription-state.mjs";

const sequence = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const timestamp = z.number().int().min(0).max(8640000000000000);
const sources = z.enum(["central_audit", "edge_audit"]);
export const deliveryHistoryArgs = z
  .object({
    subscription_id: z.string().min(1).max(2048),
    event_id: z.string().regex(/^evt_[a-f0-9]{64}$/),
    cursor: z
      .object({ source: sources, delivery_id: z.string().max(2200), after_sequence: sequence })
      .strict()
      .optional(),
    limit: z.number().int().min(1).max(100).default(50),
  })
  .strict();
export const relayDiagnosticArgs = z
  .object({
    after_sequence: sequence.default(0),
    limit: z.number().int().min(1).max(100).default(50),
  })
  .strict();
const relayRecord = z.object({
  sequence,
  at: z.string().datetime(),
  host: z.literal("@central_http"),
  kind: z.literal("central_http"),
  principal_id: z.string().max(200),
  initiator_id: z.string().max(200).nullable(),
  parent_correlation_id: z.string().uuid().nullable(),
  correlation_id: z.string().uuid(),
  operation: z.string().regex(/^[a-z][a-z_]{0,63}$/),
  duration_ms: z.number().min(0),
  outcome: z.enum(["ok", "refused", "uncertain"]),
  http_status: z.number().int().min(100).max(599).nullable(),
  rate_limit_remaining: sequence.optional(),
});
export async function relayDiagnostics(bridge: Bridge, owner: string, input: unknown) {
  const p = relayDiagnosticArgs.parse(input);
  const authorize = () => {
    const principal = bridge.policy().principals.find((x) => x.id === owner && x.enabled !== false);
    if (
      !principal ||
      principal.eddieCaller ||
      principal.eddieHostCaller ||
      !bridge.deliveryHistory ||
      !bridge.relayDiagnosticAccess
    )
      throw denied();
  };
  authorize();
  await bridge.relayDiagnosticAccess(owner);
  authorize();
  const rows = bridge.store.diagnostics("@central_http", p.after_sequence, p.limit),
    page = rows.slice(0, p.limit);
  const items = page.flatMap((row) => {
    const parsed = relayRecord.safeParse(row);
    return parsed.success &&
      (parsed.data.principal_id === owner || parsed.data.initiator_id === owner)
      ? [parsed.data]
      : [];
  });
  authorize();
  return {
    items,
    next_cursor: rows.length > p.limit ? page.at(-1)!.sequence : null,
    coverage:
      "Seven days or 25,000 diagnostic rows globally. Only this principal's central HTTP calls or calls carrying its request context are returned. Empty pages can advance. Edge-local diagnostics are not a fleet-wide GitHub usage ledger and may be absent after cache replacement.",
    quota_delta: "not_inferred",
  };
}
const centralHistory = z.object({
  id: z.string(),
  subscription_id: z.string(),
  event_id: z.string(),
  state: z.enum(["pending", "claimed", "sending", "acknowledged", "stopped", "revoked"]),
  attempts: sequence,
  http_status: z.number().int().min(0).max(599).nullable(),
  next_at: timestamp.nullable(),
  items: z
    .array(
      z.object({
        sequence,
        at: timestamp,
        operation: z.enum(["outbox_claim", "outbox_begin", "outbox_result", "outbox_stop"]),
        principal_id: z.string().min(1).max(200),
      }),
    )
    .max(100),
  next_sequence: sequence.nullable(),
  delivery_acknowledged: z.boolean(),
  agent_completed: z.literal(false),
});
const localCurrent = z.object({
  state: z.enum(["pending", "acknowledged", "stopped", "superseded", "revoked", "quarantined"]),
  attempts: sequence,
  http_status: z.number().int().min(0).max(599).nullable(),
  next_at: timestamp.nullable(),
});
const denied = () => Object.assign(Error("forbidden"), { reason: "forbidden" });
const unavailable = () =>
  Object.assign(Error("source_unavailable"), { reason: "source_unavailable" });

/** Exact owned event only. Never reads a native thread, reconciles commands,
 * refreshes credentials, claims an outbox item or posts a webhook. */
export async function deliveryHistory(bridge: Bridge, owner: string, input: unknown) {
  const p = deliveryHistoryArgs.parse(input),
    id = p.subscription_id + ":" + p.event_id;
  const authorize = () => {
    const principal = bridge.policy().principals.find((x) => x.id === owner && x.enabled !== false);
    const sub = bridge.store.get("subscription", p.subscription_id),
      d = bridge.store.get("delivery", id);
    if (
      !principal ||
      principal.eddieCaller ||
      principal.eddieHostCaller ||
      !sub ||
      sub.owner !== owner ||
      !subscriptionActive(sub, bridge.now()) ||
      !d ||
      d.id !== id ||
      d.subId !== sub.id ||
      d.event?.eventId !== p.event_id ||
      d.event?.name !== sub.name
    )
      throw denied();
    if (sub.name === "t3.task.finished") bridge.grant(owner, sub.sessionId);
    else {
      const host = sub.host ?? d.event.data?.host,
        project = sub.projectId ?? d.event.data?.project_id;
      if (typeof host !== "string" || !bridge.fleetReads) throw denied();
      const { grant } = bridge.fleetReads.grant(owner, host, project);
      if (grant.projectIds && typeof project !== "string") throw denied();
      if (sub.name === "t3.fleet.activity")
        bridge.fleetEvents.grant(owner, host, project, d.event.data?.provider_instance_id);
    }
    return { sub, d };
  };
  const { sub, d } = authorize(),
    source = typeof d.central_id === "string" ? "central_audit" : "edge_audit";
  if (p.cursor && (p.cursor.source !== source || p.cursor.delivery_id !== id))
    throw Object.assign(Error("history_source_changed"), { reason: "history_source_changed" });
  const after = p.cursor?.after_sequence ?? 0;
  let items: {
      sequence: number;
      at: string;
      evidence: string;
      http_status?: number;
      principal_id?: string;
    }[],
    next: number | null;
  let current: {
    state: string;
    attempts: number;
    http_status: number | null;
    next_at: number | null;
  };
  if (source === "central_audit") {
    if (!bridge.deliveryHistory) throw unavailable();
    const raw = await bridge.deliveryHistory(owner, d.central_id, after, p.limit);
    if (raw?.reason === "forbidden") throw denied();
    const parsed = centralHistory.safeParse(raw);
    if (
      !parsed.success ||
      parsed.data.id !== d.central_id ||
      parsed.data.subscription_id !== p.subscription_id ||
      parsed.data.event_id !== p.event_id ||
      parsed.data.items.some(
        (row, i, rows) => row.sequence <= after || (i > 0 && row.sequence <= rows[i - 1].sequence),
      ) ||
      (parsed.success &&
        parsed.data.next_sequence !== null &&
        parsed.data.next_sequence !== parsed.data.items.at(-1)?.sequence) ||
      (parsed.success &&
        parsed.data.delivery_acknowledged !== (parsed.data.state === "acknowledged"))
    )
      throw unavailable();
    const r = parsed.data;
    const labels = {
      outbox_claim: "claim_processed",
      outbox_begin: "dispatch_permitted",
      outbox_result: "result_recorded",
      outbox_stop: "source_stop_recorded",
    };
    items = r.items.map((row) => ({
      sequence: row.sequence,
      at: new Date(row.at).toISOString(),
      evidence: labels[row.operation],
      principal_id: row.principal_id,
    }));
    next = r.next_sequence;
    current = {
      state: r.state,
      attempts: r.attempts,
      http_status: r.http_status,
      next_at: r.next_at,
    };
  } else {
    if (d.status === "centralized") throw unavailable();
    const rows = bridge.store.deliveryHistory(
      id,
      after,
      p.limit,
      new Date(bridge.now() - 7 * 86400000).toISOString(),
    );
    items = rows.slice(0, p.limit).map((row) => {
      const match = /^(acknowledged|pending|stopped):(\d{1,3})$/.exec(String(row.outcome));
      if (
        !match ||
        Number(match[2]) > 599 ||
        !Number.isSafeInteger(row.seq) ||
        !Number.isFinite(Date.parse(String(row.at)))
      )
        throw unavailable();
      return {
        sequence: Number(row.seq),
        at: String(row.at),
        evidence: "http_result_recorded",
        http_status: Number(match[2]),
      };
    });
    next = rows.length > p.limit ? items.at(-1)!.sequence : null;
    current = {
      state: d.status,
      attempts: d.attempts,
      http_status: d.httpStatus ?? null,
      next_at: d.status === "pending" ? d.nextAt : null,
    };
    const checked = localCurrent.safeParse(current);
    if (!checked.success) throw unavailable();
    current = {
      state: checked.data.state,
      attempts: checked.data.attempts,
      http_status: checked.data.http_status ?? null,
      next_at: checked.data.next_at ?? null,
    };
  }
  if (
    current.state === "acknowledged" &&
    !(current.http_status >= 200 && current.http_status < 300)
  )
    throw unavailable();
  const final = authorize();
  if (JSON.stringify(final.sub) !== JSON.stringify(sub) || final.d.central_id !== d.central_id)
    throw denied();
  return {
    subscription_id: p.subscription_id,
    event_id: p.event_id,
    source,
    current,
    items,
    next_cursor: next === null ? null : { source, delivery_id: id, after_sequence: next },
    delivery_acknowledged: current.state === "acknowledged",
    agent_acknowledgement: "not_checked",
    agent_execution: "not_checked",
    coverage: {
      query_window_days: 7,
      historical_completeness: "not_asserted",
      explanation:
        "Retained operation audit only. A permit does not prove an HTTP effect. Historical per-attempt HTTP codes may be absent; current receipt is separate. Empty history does not prove no delivery.",
    },
  };
}
