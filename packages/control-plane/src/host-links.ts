// SPDX-License-Identifier: AGPL-3.0-or-later
import { authorizeBinding, operationBinding, type OperationBinding } from "./binding.ts";
import type { ServicePrincipal } from "./services.ts";

export const hostLinkLimits = Object.freeze({
  leaseMs: 10000,
  page: 32,
  pageBytes: 48000,
  frameBytes: 8192,
  pending: 256,
  history: 4096,
  sessions: 256,
});
export type Reference = {
  request_id: string;
  host: string;
  thread_id: string;
  owner: string;
  binding: OperationBinding;
};
export type LinkFrame = Omit<Reference, "owner"> & { sequence: number };
export type HostLinkContext = {
  sql: SqlStorage;
  now: number;
  // Identity comes from the authenticated server, NEVER the request body.
  actorId: string;
  principal(id: string): ServicePrincipal;
  authorize(actor: ServicePrincipal, host: string): void;
  // Trusted lookup of an existing authoritative command, not client-supplied metadata.
  reference(requestId: string): Reference;
};
const fail = (reason: string): never => {
  throw Error(reason);
};
const text = (v: unknown) =>
  typeof v === "string" && v.length > 0 && v.length <= 200 ? v : fail("invalid_request");
export function linkUuid(v: unknown): string {
  return typeof v === "string" &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(v)
    ? v
    : fail("invalid_request");
}
const integer = (v: unknown) =>
  Number.isSafeInteger(v) && Number(v) >= 0 ? Number(v) : fail("invalid_request");
export function linkFrame(value: unknown): LinkFrame {
  const f = value as LinkFrame;
  if (
    !f ||
    Object.keys(f).some(
      (k) => !["request_id", "host", "thread_id", "binding", "sequence"].includes(k),
    )
  )
    fail("invalid_request");
  const frame = {
    request_id: linkUuid(f.request_id),
    host: text(f.host),
    thread_id: text(f.thread_id),
    binding: operationBinding(f.binding),
    sequence: integer(f.sequence),
  };
  if (
    frame.sequence < 1 ||
    new TextEncoder().encode(JSON.stringify(frame)).length > hostLinkLimits.frameBytes
  )
    fail("invalid_request");
  return frame;
}
/** Separate schema, not installed or called by the production Worker. Call only
 * inside the owning DO transactionSync, with no network IO in the transaction. */
export function hostLinkSchema(sql: SqlStorage) {
  sql.exec(`
    CREATE TABLE IF NOT EXISTS host_links(host TEXT PRIMARY KEY,principal TEXT NOT NULL,connection TEXT NOT NULL,generation INTEGER NOT NULL,expires INTEGER NOT NULL,ack INTEGER NOT NULL DEFAULT 0,sent INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS host_link_sessions(host TEXT NOT NULL,connection TEXT NOT NULL,principal TEXT NOT NULL,generation INTEGER NOT NULL,opened INTEGER NOT NULL,PRIMARY KEY(host,connection));
    CREATE TABLE IF NOT EXISTS host_link_refs(sequence INTEGER PRIMARY KEY AUTOINCREMENT,host TEXT NOT NULL,request TEXT NOT NULL UNIQUE,owner TEXT NOT NULL,thread TEXT NOT NULL,binding TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS host_link_refs_page ON host_link_refs(host,sequence);
  `);
}
type Session = {
  host: string;
  principal: string;
  connection: string;
  generation: number;
  expires: number;
  ack: number;
  sent: number;
};
type Row = {
  sequence: number;
  host: string;
  request: string;
  owner: string;
  thread: string;
  binding: string;
};
export function hostLinkOperation(
  c: HostLinkContext,
  op: string,
  p: Record<string, unknown>,
): unknown {
  const keys =
    op === "link_publish"
      ? ["request_id"]
      : op === "link_status"
        ? ["host", "connection"]
        : [
            "host",
            "connection",
            ...(op === "link_open" ? [] : ["generation"]),
            ...(["link_page", "link_ack"].includes(op) ? ["after"] : []),
          ];
  if (Object.keys(p).some((k) => !keys.includes(k))) fail("invalid_request");
  const actor = c.principal(c.actorId),
    { sql, now } = c;
  const allowed = (a: ServicePrincipal, host: string, binding?: OperationBinding) => {
    if (a.expiresAt <= now) fail("forbidden");
    c.authorize(a, host);
    if (binding)
      authorizeBinding(binding, a.scopes, now, {
        host,
        purpose: "command",
        grants: a.nativeGrants,
      });
  };
  const session = (host: string) =>
    sql.exec<Session>("SELECT * FROM host_links WHERE host=?", host).toArray()[0];
  const count = (table: "host_link_refs" | "host_link_sessions", host: string, after?: number) =>
    sql
      .exec<{ n: number }>(
        `SELECT COUNT(*) AS n FROM ${table} WHERE host=?${after === undefined ? "" : " AND sequence>?"}`,
        host,
        ...(after === undefined ? [] : [after]),
      )
      .one().n;
  if (op === "link_publish") {
    if (actor.role !== "owner") fail("forbidden");
    const id = linkUuid(p.request_id),
      r = c.reference(id),
      b = operationBinding(r.binding);
    if (r.request_id !== id || r.owner !== actor.id) fail("forbidden");
    const host = text(r.host),
      thread = text(r.thread_id);
    allowed(actor, host, b);
    linkFrame({ request_id: id, host, thread_id: thread, binding: b, sequence: 1 });
    const old = sql.exec<Row>("SELECT * FROM host_link_refs WHERE request=?", id).toArray()[0];
    if (old) {
      if (
        old.host !== host ||
        old.thread !== thread ||
        old.owner !== actor.id ||
        old.binding !== JSON.stringify(b)
      )
        fail("idempotency_conflict");
      return { sequence: old.sequence, existing: true };
    }
    if (
      count("host_link_refs", host) >= hostLinkLimits.history ||
      count("host_link_refs", host, session(host)?.ack ?? 0) >= hostLinkLimits.pending
    )
      fail("host_backpressure");
    const row = sql
      .exec<{ sequence: number }>(
        "INSERT INTO host_link_refs(host,request,owner,thread,binding) VALUES(?,?,?,?,?) RETURNING sequence",
        host,
        id,
        actor.id,
        thread,
        JSON.stringify(b),
      )
      .one();
    return { sequence: row.sequence, existing: false };
  }
  const host = text(p.host);
  // A broad fleet executor cannot assert a host identity. A future production
  // adapter must map an existing, explicitly host-bound principal first.
  if (actor.role !== "executor" || actor.hosts.length !== 1 || actor.hosts[0] !== host)
    fail("forbidden");
  allowed(actor, host);
  const old = session(host);
  const connection = linkUuid(p.connection);
  if (op === "link_status")
    return old && old.connection === connection && old.principal === actor.id
      ? { ...old, active: old.expires > now }
      : { host, active: false };
  if (op === "link_open") {
    if (old?.expires > now) {
      if (old.principal !== actor.id || old.connection !== connection) fail("fenced");
      return old; // Lost open response: same connection returns the same permit.
    }
    if (
      sql
        .exec(
          "SELECT connection FROM host_link_sessions WHERE host=? AND connection=?",
          host,
          connection,
        )
        .toArray().length
    )
      fail("fenced");
    if (count("host_link_sessions", host) >= hostLinkLimits.sessions)
      fail("connector_history_full");
    const generation = (old?.generation ?? 0) + 1;
    sql.exec(
      "INSERT INTO host_link_sessions VALUES(?,?,?,?,?)",
      host,
      connection,
      actor.id,
      generation,
      now,
    );
    sql.exec(
      "INSERT INTO host_links(host,principal,connection,generation,expires) VALUES(?,?,?,?,?) ON CONFLICT(host) DO UPDATE SET principal=excluded.principal,connection=excluded.connection,generation=excluded.generation,expires=excluded.expires,sent=0",
      host,
      actor.id,
      connection,
      generation,
      Math.min(now + hostLinkLimits.leaseMs, actor.expiresAt),
    );
    return session(host);
  }
  if (
    !old ||
    old.principal !== actor.id ||
    old.connection !== connection ||
    old.generation !== integer(p.generation) ||
    old.expires <= now
  )
    fail("fenced");
  if (op === "link_renew") {
    sql.exec(
      "UPDATE host_links SET expires=? WHERE host=?",
      Math.min(now + hostLinkLimits.leaseMs, actor.expiresAt),
      host,
    );
    return session(host);
  }
  const after = integer(p.after);
  if (
    after &&
    !sql
      .exec("SELECT sequence FROM host_link_refs WHERE host=? AND sequence=?", host, after)
      .toArray().length
  )
    fail("cursor_mismatch");
  if (op === "link_ack") {
    if (after > old.sent) fail("cursor_mismatch");
    sql.exec("UPDATE host_links SET ack=MAX(ack,?) WHERE host=?", after, host);
    return { host, acknowledged: Math.max(old.ack, after) };
  }
  if (op !== "link_page") fail("invalid_request");
  const rows = sql
    .exec<Row>(
      "SELECT * FROM host_link_refs WHERE host=? AND sequence>? ORDER BY sequence LIMIT 33",
      host,
      after,
    )
    .toArray();
  const items: LinkFrame[] = [];
  let bytes = 256;
  for (const r of rows) {
    if (items.length >= hostLinkLimits.page) break;
    const b = operationBinding(JSON.parse(r.binding));
    const origin = c.principal(r.owner);
    if (origin.role !== "owner") fail("forbidden");
    allowed(origin, host, b);
    allowed(actor, host, b);
    const frame = linkFrame({
      sequence: r.sequence,
      host,
      thread_id: r.thread,
      request_id: r.request,
      binding: b,
    });
    const size = new TextEncoder().encode(JSON.stringify(frame)).length;
    if (bytes + size > hostLinkLimits.pageBytes) break;
    bytes += size;
    items.push(frame);
  }
  const next = items.at(-1)?.sequence ?? after;
  sql.exec("UPDATE host_links SET sent=MAX(sent,?) WHERE host=?", next, host);
  return {
    host,
    connection,
    generation: old.generation,
    items,
    next,
    more: rows.length > items.length,
  };
}
