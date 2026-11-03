// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { Store } from "../../../dist/store.mjs";
import type { Policy } from "../../../dist/config.mjs";
import type { NativeRecord } from "../../../dist/contracts.mjs";
import { subscriptionActive } from "../../../dist/subscription-state.mjs";
import { verifySegments } from "./import-service.ts";
import { type manifestOf } from "./snapshot.ts";
import { coreSchema } from "./core-schema.ts";
import { serviceSchema } from "./services.ts";
import { adoptLegacy, type LegacyTarget } from "./legacy-adoption.ts";
import { projectNativeGrant } from "./grant-projection.ts";
import { authorizeBinding } from "./binding.ts";
import { packRecovery } from "./recovery-archive.ts";
import { recoveryTables, recoveryPage, type RecoveryRow } from "./recovery.ts";
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const text = (v: unknown) =>
  typeof v === "string" && v.length > 0 && v.length <= 2048
    ? v
    : (() => {
        throw Error("legacy_target_unbound");
      })();

/** Initial operational adoption only. It reads authenticated encrypted packets
 * into a disposable in-memory database, never opens/mutates the historical DB,
 * contacts a native host or activates a service. Later rollback MUST use current
 * central captureRecovery, never this original snapshot. */
export function prepareLegacyRecovery(
  packets: { body: string; mac: string }[],
  key: Buffer,
  expected: ReturnType<typeof manifestOf>,
  policy: Policy,
  centralPolicy: unknown,
  serviceExpiresAt: number,
  now = Date.now(),
) {
  if (key.length !== 32 || !Number.isSafeInteger(now) || serviceExpiresAt <= now)
    throw Error("legacy_configuration_required");
  const snapshot = verifySegments(packets, key, expected);
  const values = snapshot.records
    .filter((r) => !r.kind.startsWith("$"))
    .map((r) => ({
      ...r,
      value: Store.prototype.decode.call({ key }, r.ciphertext) as NativeRecord,
    }));
  const subscriptions = values.filter((r) => r.kind === "subscription");
  const active = subscriptions.filter((r) => subscriptionActive(r.value, now));
  const pending = values.filter((r) => r.kind === "delivery" && r.value.status === "pending");
  const target = (owner: string, host: string, thread: string, project?: string): LegacyTarget => {
    const s = projectNativeGrant(policy, owner, host, "observation", serviceExpiresAt, now);
    const binding = {
      project:
        project ?? (s.projects === null ? "__authorized_host_observation__" : text(undefined)),
      provider: "__observation__",
      run: null,
      grant: s.grant,
      revision: s.revision,
      expires: s.expires,
    };
    authorizeBinding(binding, [], now, { host, purpose: "observation", grants: [s] });
    return { owner, host, thread, binding };
  };
  const deliveryTarget = (v: NativeRecord) => {
    const sub = active.find((s) => s.id === v.subId)?.value;
    if (!sub) throw Error("legacy_subscription_missing");
    const data = v.event?.data;
    if (!data || v.event.name !== sub.name) throw Error("invalid_legacy_event");
    let host = sub.host ?? data.host,
      thread = sub.threadId ?? data.thread_id ?? "aggregate";
    if (sub.name === "t3.task.finished") {
      const session = policy.sessions.find((s) => s.id === sub.sessionId);
      if (!session || data.session_id !== session.id) throw Error("legacy_target_unbound");
      host = session.host;
      thread = session.threadId;
    }
    if (
      (data.host !== undefined && data.host !== host) ||
      (data.thread_id !== undefined && data.thread_id !== thread)
    )
      throw Error("legacy_target_unbound");
    return target(text(sub.owner), text(host), text(thread), data.project_id ?? sub.projectId);
  };
  const resolve = (kind: string, v: NativeRecord): LegacyTarget[] => {
    if (kind === "delivery") return [deliveryTarget(v)];
    if (kind === "subscription") {
      const owner = text(v.owner),
        p = policy.principals.find((p) => p.id === owner && p.enabled !== false);
      if (!p || p.eddieCaller || p.eddieHostCaller) throw Error("legacy_owner_unmapped");
      let targets: LegacyTarget[];
      if (v.name === "t3.thread.activity") {
        const host = text(v.host),
          thread = text(v.threadId),
          project = text(v.projectId);
        const command = projectNativeGrant(policy, owner, host, "command", undefined, now);
        const identity = hash([owner, host, thread]);
        if (
          (command.projects !== null && !command.projects.includes(project)) ||
          v.laneId !== "lane_" + identity ||
          v.sessionId !== "thread_" + identity.slice(0, 32)
        )
          throw Error("legacy_target_unbound");
        targets = [target(owner, host, thread, project)];
      } else if (v.name === "t3.task.finished") {
        const session = policy.sessions.find(
          (s) => s.id === v.sessionId && p.sessions.includes(s.id),
        );
        if (!session) throw Error("legacy_target_unbound");
        targets = [target(owner, session.host, session.threadId)];
      } else if (v.name === "t3.fleet.activity" || v.name === "t3.eddie.requested") {
        if (v.name === "t3.eddie.requested" && (!p.eddieInbox || v.inboxId !== owner))
          throw Error("legacy_target_unbound");
        if (v.name === "t3.fleet.activity" && v.scope !== "authorized_fleet")
          throw Error("legacy_target_unbound");
        const hosts = (p.readHosts ?? []).filter((g) => {
          if (v.name !== "t3.fleet.activity") return true;
          try {
            projectNativeGrant(policy, owner, g.host, "command", undefined, now);
            return true;
          } catch {
            return false;
          }
        });
        targets = hosts.map((g) => target(owner, g.host, "aggregate"));
      } else throw Error("unsupported_legacy_subscription");
      for (const d of pending.filter((d) => d.value.subId === v.id))
        targets.push(deliveryTarget(d.value));
      return [...new Map(targets.map((t) => [JSON.stringify([t.host, t.thread]), t])).values()];
    }
    const owner = text(v.owner),
      session = kind === "followup" ? policy.sessions.find((s) => s.id === v.sessionId) : undefined;
    // Historical command bindings are evidence-only, always expired and prefixed
    // legacy by adoption. Unknown old fields are explicit, never inferred grants.
    return [
      {
        owner,
        host: text(v.host ?? session?.host),
        thread: text(v.thread_id ?? session?.threadId),
        binding: {
          project:
            v.projectId ?? v.project_id ?? v.before?.project_id ?? "__unbound_legacy_project__",
          provider:
            v.executionAuthorization?.providerInstanceId ??
            v.provider_instance_id ??
            v.before?.model_selection?.instanceId ??
            "__unbound_legacy_provider__",
          run: v.sourceRunId ?? v.source_run_id ?? (kind === "followup" ? v.runId : null),
          grant: hash([kind, owner, v.request_id ?? v.requestId]),
          revision: 1,
          expires: 0,
        },
      },
    ];
  };
  const db = new DatabaseSync(":memory:");
  const sql = {
    exec(statement: string, ...args: (string | number | null)[]) {
      if (!args.length && statement.includes(";")) {
        db.exec(statement);
        return { toArray: () => [] };
      }
      const prepared = db.prepare(statement);
      if (prepared.columns().length) {
        const rows = prepared.all(...args);
        return {
          toArray: () => rows,
          one: () => {
            if (rows.length !== 1) throw Error("legacy_sql_cardinality");
            return rows[0];
          },
        };
      }
      prepared.run(...args);
      return { toArray: () => [] };
    },
  } as unknown as SqlStorage;
  try {
    db.exec(coreSchema);
    serviceSchema(sql);
    db.prepare("INSERT INTO auth_policy VALUES(1,?)").run(JSON.stringify(centralPolicy));
    for (const r of snapshot.records)
      db.prepare("INSERT INTO imported VALUES(?,?,?)").run(r.kind, r.id, r.ciphertext);
    const adopted = adoptLegacy(
      {
        sql,
        transactionSync<T>(fn: () => T): T {
          db.exec("BEGIN IMMEDIATE");
          try {
            const result = fn();
            db.exec("COMMIT");
            return result;
          } catch (error) {
            db.exec("ROLLBACK");
            throw error;
          }
        },
      },
      snapshot,
      (raw) => Store.prototype.decode.call({ key }, raw),
      resolve,
      now,
    );
    db.prepare("UPDATE control SET mode='quiesced',migration=? WHERE id=1").run(
      snapshot.migration_id,
    );
    const rows: RecoveryRow[] = [],
      counts: Record<string, number> = {};
    for (let table = 0; table < recoveryTables.length; table++) {
      counts[recoveryTables[table]] = Number(
        db.prepare(`SELECT COUNT(*) n FROM ${recoveryTables[table]}`).get()!.n,
      );
      let after = 0;
      for (;;) {
        const page = recoveryPage(sql, table, after);
        rows.push(...page.rows);
        if (page.next === null || page.next.table !== table) break;
        after = page.next.after;
      }
    }
    const header = { epoch: 0, watermark: 0, counts, activation_permitted: false as const };
    if (rows.length > 100000 || Buffer.byteLength(JSON.stringify(rows)) > 32 * 1024 * 1024)
      throw Error("legacy_recovery_volume_limit");
    return {
      archive: packRecovery(header, rows, key),
      expected: { epoch: 0, watermark: 0 },
      ledger: {
        ...adopted,
        encrypted_records: snapshot.records.length,
        subscription_identity_sha256: hash(subscriptions.map((s) => s.id).sort()),
        retained_inert_subscriptions: subscriptions.length - active.length,
        retirement_proven: false,
        production_ready: false,
      },
    };
  } finally {
    db.close();
  }
}
