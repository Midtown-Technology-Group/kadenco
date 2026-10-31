// SPDX-License-Identifier: AGPL-3.0-or-later
import { operationBinding, type OperationBinding } from "./binding.ts";
import type { Snapshot } from "./snapshot.ts";
import { serviceSchema } from "./services.ts";
export type LegacyTarget = {
  owner: string;
  host: string;
  thread: string;
  binding: OperationBinding;
};
/** Called only inside a SQL transaction after authenticated snapshot verification.
 * decode is the existing Store.decode using approved edge custody; never a DO key.
 * resolve must map existing native/session/read grants, never infer new authority. */
function adoptLegacyRows(
  sql: SqlStorage,
  snapshot: Snapshot,
  decode: (ciphertext: string) => unknown,
  resolve: (kind: string, value: Record<string, unknown>) => LegacyTarget[],
) {
  serviceSchema(sql);
  if (sql.exec<{ mode: string }>("SELECT mode FROM control WHERE id=1").one().mode !== "staging")
    throw Error("not_staging");
  if (snapshot.records.length > 10000) throw Error("legacy_snapshot_too_large");
  const known = new Set([
    "command",
    "settings_mutation",
    "subscription",
    "delivery",
    "followup",
    "exchange",
    "fleet_scan",
    "fleet_thread",
    "run",
    "verification",
    "collaboration.access-request",
    "collaboration.grant",
    "collaboration.identity",
    "collaboration.invitation",
    "collaboration.message",
    "$audit",
    "$diagnostics",
  ]);
  for (const r of snapshot.records) {
    if (!known.has(r.kind)) throw Error("unsupported_legacy_kind");
    if (!r.kind.startsWith("$")) decode(r.ciphertext);
  }
  for (const table of ["commands", "budget_reservations", "subscriptions", "outbox"])
    if (sql.exec<{ n: number }>(`SELECT COUNT(*) n FROM ${table}`).one().n)
      throw Error("adoption_destination_not_empty");
  const values = snapshot.records
    .filter((r) =>
      ["command", "settings_mutation", "subscription", "delivery", "followup"].includes(r.kind),
    )
    .map((r) => {
      const value = decode(r.ciphertext);
      if (!value || typeof value !== "object" || Array.isArray(value))
        throw Error("invalid_legacy_record");
      return { record: r, value: value as Record<string, unknown> };
    });
  const targets = new Map<string, LegacyTarget[]>();
  const text = (v: unknown) =>
    typeof v === "string" && v.length > 0 && v.length <= 2048
      ? v
      : (() => {
          throw Error("legacy_binding_required");
        })();
  for (const { record, value } of values) {
    if (record.kind === "delivery") continue;
    const bound = resolve(record.kind, value);
    if (!bound.length || bound.length > 100) throw Error("legacy_binding_required");
    for (const t of bound) {
      text(t.owner);
      text(t.host);
      text(t.thread);
      operationBinding(t.binding);
      if (t.owner !== value.owner) throw Error("legacy_owner_mismatch");
    }
    targets.set(record.kind + ":" + record.id, bound);
  }
  let commands = 0,
    budgets = 0,
    subscriptions = 0,
    deliveries = 0;
  for (const { record, value: v } of values) {
    if (!["command", "settings_mutation", "followup"].includes(record.kind)) continue;
    const t = targets.get(record.kind + ":" + record.id)![0];
    if (targets.get(record.kind + ":" + record.id)!.length !== 1)
      throw Error("legacy_binding_required");
    const id = text(v.request_id ?? v.requestId),
      kind =
        record.kind === "settings_mutation"
          ? "settings_standard"
          : record.kind === "followup"
            ? "verify_result"
            : text(v.kind);
    if (!["continue", "answer", "create", "settings_standard", "verify_result"].includes(kind))
      throw Error("unknown_legacy_command");
    const at = Number(v.at ?? v.createdAt);
    if (!Number.isSafeInteger(at) || at < 0) throw Error("legacy_timestamp_required");
    // Every adopted native UUID is forever non-dispatchable, including old partially
    // created threads and interrupted settings. Evidence is retained verbatim.
    const binding = { ...t.binding, grant: "legacy:" + t.binding.grant };
    sql.exec(
      "INSERT INTO commands(id,host,thread,kind,digest,originator,binding,state,generation,receipt) VALUES(?,?,?,?,?,?,?,'uncertain',0,?)",
      id,
      t.host,
      t.thread,
      kind,
      typeof v.digest === "string" ? v.digest : "legacy-opaque",
      t.owner,
      JSON.stringify(binding),
      JSON.stringify(v),
    );
    commands++;
    if (record.kind !== "settings_mutation" || v.submitted_at) {
      sql.exec(
        "INSERT INTO budget_reservations VALUES(?,?,?,?,?)",
        id,
        t.owner,
        t.host,
        t.thread,
        new Date(at).toISOString().slice(0, 10),
      );
      budgets++;
    }
  }
  const subscriptionById = new Map<
    string,
    { value: Record<string, unknown>; targets: LegacyTarget[] }
  >();
  for (const { record, value: v } of values) {
    if (record.kind !== "subscription") continue;
    const bound = targets.get(record.kind + ":" + record.id)!;
    subscriptionById.set(record.id, { value: v, targets: bound });
    const expires = v.expires;
    if (expires !== null && (!Number.isSafeInteger(expires) || Number(expires) < 0))
      throw Error("invalid_legacy_lifetime");
    if (expires === null && v.nonExpiring !== true) throw Error("invalid_legacy_lifetime");
    if (
      v.leaseExpires !== undefined &&
      (!Number.isSafeInteger(v.leaseExpires) ||
        expires === null ||
        Number(expires) > Number(v.leaseExpires))
    )
      throw Error("invalid_legacy_lifetime");
    for (const t of bound) {
      const id = JSON.stringify([record.id, t.host, t.thread]),
        entry = {
          id,
          external_id: record.id,
          host: t.host,
          thread_id: t.thread,
          binding: t.binding,
          expires,
          name: text(v.name),
          callback_reference: record.id,
          ...(v.leaseExpires === undefined ? {} : { lease_expires: v.leaseExpires }),
        };
      sql.exec(
        "INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)",
        id,
        t.owner,
        t.host,
        t.thread,
        JSON.stringify(t.binding),
        expires as number | null,
        v.active === true ? 1 : 0,
        JSON.stringify(entry),
      );
      subscriptions++;
    }
  }
  for (const { record, value: v } of values) {
    if (record.kind !== "delivery") continue;
    const source = subscriptionById.get(text(v.subId));
    if (!source) throw Error("legacy_subscription_missing");
    const event = v.event as { eventId: string; name: string; data: Record<string, unknown> };
    if (!event?.eventId || event.name !== source.value.name) throw Error("invalid_legacy_event");
    const bound = resolve("delivery", v);
    if (bound.length !== 1) throw Error("legacy_binding_required");
    const t = bound[0];
    if (
      t.owner !== source.value.owner ||
      !source.targets.some((s) => s.host === t.host && s.thread === t.thread)
    )
      throw Error("legacy_owner_mismatch");
    const subscription = JSON.stringify([String(v.subId), t.host, t.thread]),
      data = event.data ?? {};
    const identity = JSON.stringify([
        t.host,
        t.thread,
        data.run_id ?? "coverage",
        data.kind ?? event.name,
        data.native_request_id ?? data.request_id ?? event.eventId,
      ]),
      id = JSON.stringify([subscription, identity]);
    const attempts = Number(v.attempts),
      next = Number(v.nextAt);
    if (!Number.isSafeInteger(attempts) || attempts < 0 || !Number.isFinite(next) || next < 0)
      throw Error("invalid_legacy_delivery");
    const state =
      v.status === "pending"
        ? attempts >= 6
          ? "stopped"
          : "pending"
        : ["acknowledged", "stopped", "revoked", "superseded"].includes(String(v.status))
          ? String(v.status)
          : (() => {
              throw Error("unknown_legacy_delivery");
            })();
    sql.exec(
      "INSERT INTO outbox(id,subscription,event,state,attempts,next) VALUES(?,?,?,?,?,?)",
      id,
      subscription,
      JSON.stringify({ event_id: event.eventId, data: event }),
      state,
      attempts,
      next,
    );
    deliveries++;
  }
  return { commands, budgets, subscriptions, deliveries, activation_permitted: false };
}

export function adoptLegacy(
  storage: { sql: SqlStorage; transactionSync<T>(callback: () => T): T },
  snapshot: Snapshot,
  decode: (ciphertext: string) => unknown,
  resolve: (kind: string, value: Record<string, unknown>) => LegacyTarget[],
) {
  return storage.transactionSync(() => adoptLegacyRows(storage.sql, snapshot, decode, resolve));
}
