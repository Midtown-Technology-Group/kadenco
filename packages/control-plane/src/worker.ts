// SPDX-License-Identifier: AGPL-3.0-or-later
import { coreSchema } from "./core-schema";
import { DurableObject } from "cloudflare:workers";
import { operationBinding, authorizeBinding, type OperationBinding } from "./binding";
import { recoveryPage, recoveryTables, assertRecoverySchema } from "./recovery";
import { serviceSchema, serviceOperation } from "./services";
type Principal = {
  id: string;
  tokenSha256: string;
  role: "owner" | "executor";
  hosts: string[];
  scopes?: OperationBinding[];
  migrationAuthority?: boolean;
  maxPerDay?: number | null;
  threadBudgets?: { thread: string; provider: string; maxPerDay: number; expiresAt: number }[];
  expiresAt: number;
};
type Policy = { revision: number; fleet: string; principals: Principal[] };
type Env = Cloudflare.Env & { AUTH_POLICY?: string };
const fail = (reason: string): never => {
  throw new Error(reason);
};
const str = (v: unknown, max = 200): string =>
  typeof v === "string" && v.length > 0 && v.length <= max ? v : fail("invalid_request");
const number = (v: unknown): number =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0 ? v : fail("invalid_request");
function policy(raw: string | undefined): Policy {
  if (!raw || raw.length > 65536) fail("configuration_required");
  const p = JSON.parse(raw!) as Policy;
  str(p.fleet);
  if (number(p.revision) < 1) fail("configuration_required");
  if (!Array.isArray(p.principals) || p.principals.length > 100) fail("configuration_required");
  const ids = new Set(),
    tokens = new Set();
  for (const a of p.principals) {
    str(a.id);
    if (
      !/^[a-f0-9]{64}$/.test(a.tokenSha256) ||
      ids.has(a.id) ||
      tokens.has(a.tokenSha256) ||
      !["owner", "executor"].includes(a.role) ||
      !Array.isArray(a.hosts) ||
      a.hosts.length > 20
    )
      fail("configuration_required");
    ids.add(a.id);
    tokens.add(a.tokenSha256);
    a.hosts.forEach((h) => str(h));
    if (a.scopes && (!Array.isArray(a.scopes) || a.scopes.length > 100))
      fail("configuration_required");
    a.scopes?.forEach(operationBinding);
    number(a.expiresAt);
    if (
      a.maxPerDay !== undefined &&
      a.maxPerDay !== null &&
      (!Number.isSafeInteger(a.maxPerDay) || a.maxPerDay < 0 || a.maxPerDay > 100)
    )
      fail("configuration_required");
    if (a.threadBudgets && (!Array.isArray(a.threadBudgets) || a.threadBudgets.length > 100))
      fail("configuration_required");
    for (const cap of a.threadBudgets ?? []) {
      str(cap.thread);
      str(cap.provider);
      number(cap.expiresAt);
      if (!Number.isSafeInteger(cap.maxPerDay) || cap.maxPerDay < 0 || cap.maxPerDay > 100)
        fail("configuration_required");
    }
  }
  return p;
}
async function bounded(request: Request) {
  if (request.headers.get("content-type") !== "application/json") fail("invalid_request");
  const reader = request.body?.getReader() ?? fail("invalid_request");
  let size = 0;
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) {
        await reader.cancel();
        fail("body_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const part of chunks) {
    bytes.set(part, offset);
    offset += part.length;
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    fail("invalid_request");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) fail("invalid_request");
  return value as Record<string, unknown>;
}
function keys(p: Record<string, unknown>, names: string[]) {
  if (!p || typeof p !== "object" || Array.isArray(p)) fail("invalid_request");
  if (Object.keys(p).some((k) => !names.includes(k))) fail("invalid_request");
}
const json = (value: unknown, status = 200) =>
  Response.json(value, { status, headers: { "cache-control": "no-store" } });
export class FleetState extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.storage.sql.exec(coreSchema);
    if (
      !ctx.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(commands)")
        .toArray()
        .some((c) => c.name === "originator")
    )
      ctx.storage.sql.exec("ALTER TABLE commands ADD COLUMN originator TEXT");
    if (
      !ctx.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(commands)")
        .toArray()
        .some((c) => c.name === "binding")
    )
      ctx.storage.sql.exec("ALTER TABLE commands ADD COLUMN binding TEXT");
  }
  currentPolicy() {
    return policy(
      this.sql().exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one().value,
    );
  }
  originAuthorized(r: { originator: string | null; host: string; binding: string | null }) {
    const origin =
      this.currentPolicy().principals.find((p) => p.id === r.originator && p.role === "owner") ??
      fail("forbidden");
    this.authorized(origin, r.host);
    authorizeBinding(
      operationBinding(r.binding ? JSON.parse(r.binding) : null),
      origin.scopes,
      Date.now(),
    );
    return origin;
  }
  sql() {
    return this.ctx.storage.sql;
  }
  state() {
    return this.sql()
      .exec<{ epoch: number; mode: string; migration: string | null }>(
        "SELECT * FROM control WHERE id=1",
      )
      .one();
  }
  authorized(a: Pick<Principal, "id" | "expiresAt" | "hosts">, host?: string) {
    if (
      a.expiresAt <= Date.now() ||
      this.sql().exec("SELECT id FROM revoked WHERE id=?", a.id).toArray().length
    )
      fail("forbidden");
    if (host && !a.hosts.includes(host)) fail("forbidden");
  }
  row(id: string) {
    return (
      this.sql()
        .exec<{
          id: string;
          host: string;
          thread: string;
          kind: string;
          digest: string;
          originator: string | null;
          binding: string | null;
          state: string;
          executor: string | null;
          generation: number;
          lease_until: number | null;
          receipt: string | null;
        }>("SELECT * FROM commands WHERE id=?", id)
        .toArray()[0] ?? fail("not_found")
    );
  }
  audit(a: Principal, op: string, id: string) {
    this.sql().exec(
      "INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)",
      a.id,
      op,
      id,
      Date.now(),
    );
  }
  apply(a: Principal, op: string, p: Record<string, unknown>) {
    this.authorized(a);
    serviceSchema(this.sql());
    const state = this.state();
    if (op === "status") {
      keys(p, []);
      return {
        ...state,
        commands: this.sql().exec<{ n: number }>("SELECT COUNT(*) n FROM commands").one().n,
      };
    }
    if (op === "freeze_recovery") {
      assertRecoverySchema(this.sql());
      keys(p, ["expected_epoch"]);
      const freezeId = JSON.stringify([a.id, number(p.expected_epoch)]),
        prior = this.sql()
          .exec<{ epoch: number; watermark: number; counts: string }>(
            "SELECT epoch,watermark,counts FROM recovery_freezes WHERE id=?",
            freezeId,
          )
          .toArray()[0];
      if (a.role !== "owner" || a.migrationAuthority !== true) fail("forbidden");
      if (prior) {
        if (
          state.epoch !== prior.epoch ||
          this.sql().exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one().n !==
            prior.watermark
        )
          fail("fenced");
        return {
          epoch: prior.epoch,
          watermark: prior.watermark,
          counts: JSON.parse(prior.counts),
          activation_permitted: false,
        };
      }
      if (
        a.role !== "owner" ||
        a.migrationAuthority !== true ||
        state.epoch !== number(p.expected_epoch)
      )
        fail("forbidden");
      this.sql().exec("UPDATE control SET mode='quiesced',epoch=epoch+1 WHERE id=1");
      this.audit(a, op, String(state.epoch + 1));
      const watermark = this.sql()
        .exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit")
        .one().n;
      this.sql().exec(
        "INSERT INTO recovery_freezes VALUES(?,?,?,?,?)",
        freezeId,
        a.id,
        state.epoch + 1,
        watermark,
        "{}",
      );
      const counts: Record<string, number> = {};
      for (const table of recoveryTables)
        counts[table] = this.sql().exec<{ n: number }>(`SELECT COUNT(*) n FROM ${table}`).one().n;
      this.sql().exec(
        "UPDATE recovery_freezes SET counts=? WHERE id=?",
        JSON.stringify(counts),
        freezeId,
      );
      return {
        epoch: state.epoch + 1,
        watermark: this.sql().exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one()
          .n,
        counts,
        activation_permitted: false,
      };
    }
    if (op === "export_recovery") {
      keys(p, ["epoch", "watermark", "table", "after"]);
      if (
        a.role !== "owner" ||
        a.migrationAuthority !== true ||
        state.mode !== "quiesced" ||
        state.epoch !== number(p.epoch) ||
        this.sql().exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one().n !==
          number(p.watermark)
      )
        fail("fenced");
      return {
        ...recoveryPage(this.sql(), number(p.table), number(p.after)),
        epoch: state.epoch,
        watermark: p.watermark,
      };
    }
    if (op === "tighten_policy") {
      keys(p, ["expected_revision", "policy"]);
      if (a.role !== "owner") fail("forbidden");
      const old = this.currentPolicy(),
        next = policy(JSON.stringify(p.policy));
      if (number(p.expected_revision) !== old.revision || next.revision !== old.revision + 1)
        fail("fenced");
      if (next.fleet !== old.fleet) fail("forbidden");
      for (const n of next.principals) {
        const prior = old.principals.find((v) => v.id === n.id);
        if (
          !prior ||
          prior.role !== n.role ||
          (n.migrationAuthority === true && prior.migrationAuthority !== true) ||
          (prior.threadBudgets ?? []).some(
            (oldCap) =>
              !(n.threadBudgets ?? []).some(
                (cap) =>
                  cap.thread === oldCap.thread &&
                  cap.provider === oldCap.provider &&
                  cap.maxPerDay <= oldCap.maxPerDay &&
                  cap.expiresAt <= oldCap.expiresAt,
              ),
          ) ||
          (prior.maxPerDay === undefined
            ? n.maxPerDay !== undefined
            : prior.maxPerDay === null
              ? false
              : n.maxPerDay !== undefined &&
                (n.maxPerDay === null || n.maxPerDay > prior.maxPerDay)) ||
          prior.tokenSha256 !== n.tokenSha256 ||
          n.expiresAt > prior.expiresAt ||
          n.hosts.some((h) => !prior.hosts.includes(h)) ||
          (n.scopes ?? []).some(
            (scope) =>
              !(prior.scopes ?? []).some(
                (oldScope) => JSON.stringify(oldScope) === JSON.stringify(scope),
              ),
          )
        )
          fail("forbidden");
      }
      this.sql().exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(next));
      this.audit(a, op, String(next.revision));
      return { revision: next.revision };
    }
    if (op === "revoke") {
      keys(p, ["principal_id"]);
      if (a.role !== "owner") fail("forbidden");
      const id = str(p.principal_id);
      this.sql().exec("INSERT OR IGNORE INTO revoked VALUES(?)", id);
      this.audit(a, op, id);
      return { revoked: true };
    }
    // Imported values remain opaque original AES-GCM envelopes; no decryption key in this slice.
    if (op === "inventory") {
      keys(p, ["after_kind", "after_id"]);
      if (a.role !== "owner" || state.mode !== "staging") fail("forbidden");
      const kind = p.after_kind === undefined ? "" : str(p.after_kind),
        id = p.after_id === undefined ? "" : str(p.after_id, 2048);
      const rows = this.sql()
        .exec<{ kind: string; id: string; ciphertext: string }>(
          "SELECT kind,id,ciphertext FROM imported WHERE kind>? OR (kind=? AND id>?) ORDER BY kind,id LIMIT 101",
          kind,
          kind,
          id,
        )
        .toArray();
      const records: typeof rows = [];
      let bytes = 128;
      for (const row of rows.slice(0, 100)) {
        const size = new TextEncoder().encode(JSON.stringify(row)).byteLength + 1;
        if (bytes + size > 60000) break;
        records.push(row);
        bytes += size;
      }
      const last = records.at(-1);
      if (rows.length && !last) fail("body_too_large");
      return {
        records,
        next: rows.length > records.length ? { after_kind: last!.kind, after_id: last!.id } : null,
        active: false,
      };
    }
    if (op === "import") {
      keys(p, ["migration_id", "records"]);
      if (a.role !== "owner" || state.mode !== "staging") fail("forbidden");
      const id = str(p.migration_id);
      if (state.migration && state.migration !== id) fail("migration_conflict");
      if (!Array.isArray(p.records) || p.records.length > 100) fail("invalid_request");
      for (const raw of p.records as unknown[]) {
        const r = raw as Record<string, unknown>;
        keys(r, ["kind", "id", "ciphertext"]);
        const kind = str(r.kind),
          key = str(r.id, 2048),
          ciphertext = str(r.ciphertext, 32768);
        const old = this.sql()
          .exec<{ ciphertext: string }>(
            "SELECT ciphertext FROM imported WHERE kind=? AND id=?",
            kind,
            key,
          )
          .toArray()[0];
        if (old && old.ciphertext !== ciphertext) fail("idempotency_conflict");
        this.sql().exec("INSERT OR IGNORE INTO imported VALUES(?,?,?)", kind, key, ciphertext);
      }
      this.sql().exec("UPDATE control SET migration=? WHERE id=1", id);
      this.audit(a, op, id);
      return { stored: (p.records as unknown[]).length, active: false };
    }
    if (op === "activate") {
      keys(p, ["expected_epoch", "migration_id"]);
      if (
        a.role !== "owner" ||
        state.mode !== "staging" ||
        state.epoch !== number(p.expected_epoch) ||
        state.migration !== str(p.migration_id)
      )
        fail("fenced");
      // Activation deliberately unavailable until a quiescence certificate + manifest verifier land.
      fail("cutover_not_implemented");
    }
    if (op === "receipt") {
      keys(p, ["request_id"]);
      const r = this.row(str(p.request_id));
      this.authorized(a, r.host);
      if (a.role === "owner" ? r.originator !== a.id : r.executor !== a.id) fail("forbidden");
      if (a.migrationAuthority !== true)
        authorizeBinding(
          operationBinding(r.binding ? JSON.parse(r.binding) : null),
          a.scopes,
          Date.now(),
        );
      return { ...r, receipt: r.receipt ? JSON.parse(r.receipt) : null, safe_to_resend: false };
    }
    if (state.mode !== "active" && !(state.mode === "quiesced" && op === "record_receipt"))
      fail("not_active");
    if (number(p.epoch) !== state.epoch) fail("fenced");
    const service = serviceOperation(
      {
        sql: this.sql(),
        actor: a,
        principal: (id) =>
          this.currentPolicy().principals.find((p) => p.id === id) ?? fail("forbidden"),
        authorize: (actor, host) => this.authorized(actor, host),
        now: Date.now(),
      },
      op,
      p,
    );
    if (service !== undefined) {
      this.audit(a, op, String(p.id ?? p.subscription_id ?? "event"));
      return service;
    }
    if (op === "reserve" || op === "record_preflight") {
      keys(p, [
        "epoch",
        "request_id",
        "host",
        "thread_id",
        "kind",
        "payload_sha256",
        "binding",
        ...(op === "record_preflight" ? ["reason", "receipt"] : []),
      ]);
      if (a.role !== "owner") fail("forbidden");
      const id = str(p.request_id),
        host = str(p.host),
        thread = str(p.thread_id, 2048),
        kind = str(p.kind),
        digest = str(p.payload_sha256);
      this.authorized(a, host);
      const binding = operationBinding(p.binding);
      authorizeBinding(binding, a.scopes, Date.now());
      if (
        !["continue", "create", "settings_standard", "webhook", "answer", "verify_result"].includes(
          kind,
        ) ||
        !/^[a-f0-9]{64}$/.test(digest)
      )
        fail("invalid_request");
      const old = this.sql()
        .exec<{
          host: string;
          thread: string;
          kind: string;
          digest: string;
          originator: string | null;
          binding: string | null;
        }>("SELECT host,thread,kind,digest,originator,binding FROM commands WHERE id=?", id)
        .toArray()[0];
      if (
        old &&
        (old.originator !== a.id ||
          old.host !== host ||
          old.thread !== thread ||
          old.kind !== kind ||
          old.digest !== digest ||
          old.binding !== JSON.stringify(binding))
      )
        fail("idempotency_conflict");
      if (op === "record_preflight") {
        if (kind !== "settings_standard") fail("invalid_request");
        const receipt = JSON.stringify(p.receipt);
        if (
          !receipt ||
          receipt.length > 16384 ||
          !["already_standard", "preflight_denied"].includes(String(p.reason))
        )
          fail("invalid_request");
        if (old) {
          const current = this.row(id);
          if (current.state === "receipted") return { existing: current };
          if (!["pending", "claimed", "cancelled"].includes(current.state)) fail("fenced");
          if (current.state === "cancelled")
            return {
              preflight_recorded: true,
              id,
              receipt: JSON.parse(current.receipt!),
              native_attempted: false,
              safe_to_resend: false,
            };
        }
        const preflight = p.receipt as Record<string, unknown>;
        keys(preflight, [
          "request_id",
          "state",
          "reason",
          "before",
          "after",
          "native_submitted",
          "preflight_only",
        ]);
        if (
          preflight.native_submitted !== false ||
          (p.reason === "already_standard"
            ? preflight.state !== "noop" || preflight.reason !== "already_standard"
            : preflight.state !== "rejected")
        )
          fail("invalid_request");
        this.sql().exec(
          "INSERT OR IGNORE INTO commands(id,host,thread,kind,digest,originator,binding,state,generation,receipt) VALUES(?,?,?,?,?,?,?,'cancelled',0,?)",
          id,
          host,
          thread,
          kind,
          digest,
          a.id,
          JSON.stringify(binding),
          receipt,
        );
        this.sql().exec(
          "UPDATE commands SET state='cancelled',generation=generation+1,lease_until=NULL,receipt=? WHERE id=?",
          receipt,
          id,
        );
        this.sql().exec("DELETE FROM budget_reservations WHERE id=?", id);
        this.audit(a, op, id);
        return {
          preflight_recorded: true,
          id,
          receipt: JSON.parse(receipt),
          native_attempted: false,
          safe_to_resend: false,
        };
      }
      if (!old && kind !== "webhook") {
        if (a.maxPerDay === undefined) fail("forbidden");
        const day = new Date().toISOString().slice(0, 10);
        for (const cap of a.threadBudgets ?? []) {
          if (cap.thread !== thread || cap.provider !== binding.provider) continue;
          if (cap.expiresAt <= Date.now()) fail("forbidden");
          const usedThread = this.sql()
            .exec<{ n: number }>(
              "SELECT COUNT(*) n FROM budget_reservations b JOIN commands c ON c.id=b.id WHERE b.owner=? AND b.host=? AND b.thread=? AND b.day=? AND json_extract(c.binding,'$.provider')=?",
              a.id,
              host,
              thread,
              day,
              binding.provider,
            )
            .one().n;
          if (usedThread >= cap.maxPerDay) fail("command_budget_exhausted");
        }
        const used = this.sql()
          .exec<{ n: number }>(
            "SELECT COUNT(*) n FROM budget_reservations WHERE owner=? AND host=? AND day=?",
            a.id,
            host,
            day,
          )
          .one().n;
        if (a.maxPerDay !== null && used >= a.maxPerDay!) fail("command_budget_exhausted");
        this.sql().exec(
          "INSERT INTO budget_reservations VALUES(?,?,?,?,?)",
          id,
          a.id,
          host,
          thread,
          day,
        );
      }
      this.sql().exec(
        "INSERT OR IGNORE INTO commands(id,host,thread,kind,digest,originator,binding,state) VALUES(?,?,?,?,?,?,?,'pending')",
        id,
        host,
        thread,
        kind,
        digest,
        a.id,
        JSON.stringify(binding),
      );
      this.audit(a, op, id);
      return this.row(id);
    }
    if (op === "cancel_reserved") {
      keys(p, ["epoch", "request_id", "reason", "receipt"]);
      const id = str(p.request_id),
        r = this.row(id);
      if (a.role !== "owner" || r.originator !== a.id) fail("forbidden");
      this.originAuthorized(r);
      const receipt = JSON.stringify(p.receipt);
      if (
        !receipt ||
        receipt.length > 16384 ||
        !["already_standard", "preflight_denied"].includes(String(p.reason))
      )
        fail("invalid_request");
      if (r.state === "cancelled") {
        if (r.receipt !== receipt) fail("immutable_outcome");
        return { cancelled: true, receipt: JSON.parse(receipt), safe_to_resend: false };
      }
      if (!["pending", "claimed"].includes(r.state)) fail("fenced");
      this.sql().exec(
        "UPDATE commands SET state='cancelled',generation=generation+1,lease_until=NULL,receipt=? WHERE id=?",
        receipt,
        id,
      );
      this.sql().exec("DELETE FROM budget_reservations WHERE id=?", id);
      this.audit(a, op, id);
      return { cancelled: true, receipt: JSON.parse(receipt), safe_to_resend: false };
    }
    const id = str(p.request_id),
      r = this.row(id);
    this.authorized(a, r.host);
    if (a.role !== "executor") fail("forbidden");
    authorizeBinding(
      operationBinding(r.binding ? JSON.parse(r.binding) : null),
      a.scopes,
      Date.now(),
    );
    if (op === "claim" || op === "begin") {
      if (this.originAuthorized(r).maxPerDay === undefined) fail("forbidden");
    }
    if (op === "claim") {
      keys(p, ["epoch", "request_id", "lease_ms"]);
      const ttl = number(p.lease_ms);
      if (ttl < 1000 || ttl > 60000) fail("invalid_request");
      if (r.state === "claimed" && r.lease_until! > Date.now()) return { claimed: false };
      if (!["pending", "claimed"].includes(r.state)) return { claimed: false, state: r.state };
      this.sql().exec(
        "UPDATE commands SET state='claimed',executor=?,generation=generation+1,lease_until=? WHERE id=?",
        a.id,
        Date.now() + ttl,
        id,
      );
      this.audit(a, op, id);
      return { claimed: true, ...this.row(id) };
    }
    if (r.executor !== a.id || r.generation !== number(p.generation)) fail("fenced");
    if (op === "begin") {
      keys(p, ["epoch", "request_id", "generation"]);
      if (r.state !== "claimed" || r.lease_until! <= Date.now()) fail("fenced");
      this.sql().exec("UPDATE commands SET state='uncertain' WHERE id=?", id);
      this.audit(a, op, id);
      return { may_attempt: true, request_id: id, generation: r.generation };
    }
    if (op === "record_receipt") {
      keys(p, ["epoch", "request_id", "generation", "receipt"]);
      const receipt = JSON.stringify(p.receipt);
      if (!receipt || receipt.length > 16384) fail("invalid_request");
      if (r.state === "receipted") {
        if (r.receipt !== receipt) fail("immutable_outcome");
        return { receipt_recorded: true, native_execution_verified: false };
      }
      if (r.state !== "uncertain") fail("fenced");
      this.sql().exec("UPDATE commands SET state='receipted',receipt=? WHERE id=?", receipt, id);
      this.audit(a, op, id);
      return { receipt_recorded: true, native_execution_verified: false };
    }
    fail("not_found");
  }
  async fetch(request: Request) {
    try {
      const config = policy(this.env.AUTH_POLICY),
        token = request.headers.get("authorization");
      if (!token?.startsWith("Bearer ") || token.length > 8192) fail("forbidden");
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(token!.slice(7)),
      );
      const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join(
        "",
      );
      if (!config.principals.some((a) => a.tokenSha256 === hex)) fail("forbidden");
      const p = await bounded(request),
        op = new URL(request.url).pathname.slice(1);
      return json(
        this.ctx.storage.transactionSync(() => {
          this.sql().exec("INSERT OR IGNORE INTO auth_policy VALUES(1,?)", JSON.stringify(config));
          const current = policy(
            this.sql().exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
              .value,
          );
          const live = current.principals.find((a) => a.tokenSha256 === hex) ?? fail("forbidden");
          return this.apply(live, op, p);
        }),
      );
    } catch (e) {
      if (request.body && !request.bodyUsed) await request.body.cancel();
      const reason = e instanceof Error ? e.message : "internal_error";
      const allowed = [
        "configuration_required",
        "forbidden",
        "invalid_request",
        "body_too_large",
        "not_found",
        "not_active",
        "fenced",
        "migration_conflict",
        "idempotency_conflict",
        "cutover_not_implemented",
        "immutable_outcome",
        "command_budget_exhausted",
        "schema_mismatch",
      ];
      if (!allowed.includes(reason)) {
        console.error("control-plane unexpected error", typeof e);
        return json({ reason: "internal_error", safe_to_resend: false }, 500);
      }
      return json({ reason }, reason === "forbidden" ? 403 : 409);
    }
  }
}
export default {
  async fetch(request: Request, env: Env) {
    try {
      if (request.method !== "POST") {
        await request.body?.cancel();
        return json({ reason: "method_not_allowed" }, 405);
      }
      const config = policy(env.AUTH_POLICY);
      // Own and finish the bounded incoming stream before handing bytes to another actor.
      // This avoids a forwarded stream outliving the request that produced it.
      const body = await bounded(request);
      const target = env.FLEETS.getByName(config.fleet);
      try {
        return await target.fetch(
          new Request(request.url, {
            method: "POST",
            headers: request.headers,
            body: JSON.stringify(body),
          }),
        );
      } catch {
        return json({ reason: "forwarding_failed", safe_to_resend: false }, 503);
      }
    } catch (e) {
      if (request.body && !request.bodyUsed) await request.body.cancel();
      const reason = e instanceof Error ? e.message : "configuration_required";
      return json(
        {
          reason: ["invalid_request", "body_too_large"].includes(reason)
            ? reason
            : "configuration_required",
        },
        reason === "body_too_large" ? 413 : reason === "invalid_request" ? 400 : 503,
      );
    }
  },
} satisfies ExportedHandler<Env>;
