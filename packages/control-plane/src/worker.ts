// SPDX-License-Identifier: AGPL-3.0-or-later
import { DurableObject } from "cloudflare:workers";
type Principal = {
  id: string;
  tokenSha256: string;
  role: "owner" | "executor";
  hosts: string[];
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
    number(a.expiresAt);
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
    ctx.storage.sql.exec(`
    CREATE TABLE IF NOT EXISTS auth_policy(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS revoked(id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,mode TEXT NOT NULL,migration TEXT);
    INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL);
    CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,host TEXT NOT NULL,thread TEXT NOT NULL,kind TEXT NOT NULL,digest TEXT NOT NULL,originator TEXT,state TEXT NOT NULL,executor TEXT,generation INTEGER NOT NULL DEFAULT 0,lease_until INTEGER,receipt TEXT);
    CREATE TABLE IF NOT EXISTS imported(kind TEXT NOT NULL,id TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(kind,id));
    CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,subject TEXT NOT NULL,at INTEGER NOT NULL);
  `);
    if (
      !ctx.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(commands)")
        .toArray()
        .some((c) => c.name === "originator")
    )
      ctx.storage.sql.exec("ALTER TABLE commands ADD COLUMN originator TEXT");
  }
  currentPolicy() {
    return policy(
      this.sql().exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one().value,
    );
  }
  originAuthorized(r: { originator: string | null; host: string }) {
    const origin =
      this.currentPolicy().principals.find((p) => p.id === r.originator && p.role === "owner") ??
      fail("forbidden");
    this.authorized(origin, r.host);
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
  authorized(a: Principal, host?: string) {
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
    const state = this.state();
    if (op === "status") {
      keys(p, []);
      return {
        ...state,
        commands: this.sql().exec<{ n: number }>("SELECT COUNT(*) n FROM commands").one().n,
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
          prior.tokenSha256 !== n.tokenSha256 ||
          n.expiresAt > prior.expiresAt ||
          n.hosts.some((h) => !prior.hosts.includes(h))
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
      return { ...r, receipt: r.receipt ? JSON.parse(r.receipt) : null, safe_to_resend: false };
    }
    if (state.mode !== "active") fail("not_active");
    if (number(p.epoch) !== state.epoch) fail("fenced");
    if (op === "reserve") {
      keys(p, ["epoch", "request_id", "host", "thread_id", "kind", "payload_sha256"]);
      if (a.role !== "owner") fail("forbidden");
      const id = str(p.request_id),
        host = str(p.host),
        thread = str(p.thread_id, 2048),
        kind = str(p.kind),
        digest = str(p.payload_sha256);
      this.authorized(a, host);
      if (
        !["continue", "create", "settings_standard", "webhook"].includes(kind) ||
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
        }>("SELECT host,thread,kind,digest,originator FROM commands WHERE id=?", id)
        .toArray()[0];
      if (
        old &&
        (old.originator !== a.id ||
          old.host !== host ||
          old.thread !== thread ||
          old.kind !== kind ||
          old.digest !== digest)
      )
        fail("idempotency_conflict");
      this.sql().exec(
        "INSERT OR IGNORE INTO commands(id,host,thread,kind,digest,originator,state) VALUES(?,?,?,?,?,?,'pending')",
        id,
        host,
        thread,
        kind,
        digest,
        a.id,
      );
      this.audit(a, op, id);
      return this.row(id);
    }
    const id = str(p.request_id),
      r = this.row(id);
    this.authorized(a, r.host);
    if (a.role !== "executor") fail("forbidden");
    if (op === "claim" || op === "begin") this.originAuthorized(r);
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
