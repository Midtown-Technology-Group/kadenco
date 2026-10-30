// SPDX-License-Identifier: AGPL-3.0-or-later
import { authorizeBinding, operationBinding, type OperationBinding } from "./binding";
export type ServicePrincipal = {
  id: string;
  role: "owner" | "executor";
  hosts: string[];
  expiresAt: number;
  scopes?: OperationBinding[];
};
type Context = {
  sql: SqlStorage;
  actor: ServicePrincipal;
  principal: (id: string) => ServicePrincipal;
  authorize: (a: ServicePrincipal, host: string) => void;
  now: number;
};
const bad = (reason: string): never => {
  throw Error(reason);
};
const text = (v: unknown) =>
  typeof v === "string" && v.length > 0 && v.length <= 2048 ? v : bad("invalid_request");
export function serviceSchema(sql: SqlStorage) {
  sql.exec(`
CREATE TABLE IF NOT EXISTS edge_lease(id INTEGER PRIMARY KEY CHECK(id=1),holder TEXT,generation INTEGER,expires INTEGER);
CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,owner TEXT NOT NULL,host TEXT NOT NULL,thread TEXT NOT NULL,binding TEXT NOT NULL,expires INTEGER,active INTEGER NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS observations(source TEXT PRIMARY KEY,cursor INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,subscription TEXT NOT NULL,event TEXT NOT NULL,state TEXT NOT NULL,executor TEXT,generation INTEGER NOT NULL DEFAULT 0,lease INTEGER,attempts INTEGER NOT NULL DEFAULT 0,next INTEGER NOT NULL DEFAULT 0,http_status INTEGER);
CREATE INDEX IF NOT EXISTS outbox_due ON outbox(state,next,lease,id);
`);
}
/** Invoked only inside the parent's SQL transaction; network IO stays outside. */
export function serviceOperation(
  c: Context,
  op: string,
  p: Record<string, unknown>,
): unknown | undefined {
  const { sql, actor: a, now } = c;
  const sub = (id: string) =>
    sql
      .exec<{
        id: string;
        owner: string;
        host: string;
        thread: string;
        binding: string;
        expires: number | null;
        active: number;
        value: string;
      }>("SELECT * FROM subscriptions WHERE id=?", id)
      .toArray()[0] ?? bad("not_found");
  const authorized = (s: ReturnType<typeof sub>) => {
    const owner = c.principal(s.owner);
    c.authorize(owner, s.host);
    c.authorize(a, s.host);
    authorizeBinding(operationBinding(JSON.parse(s.binding)), owner.scopes, now);
    if (!s.active || (s.expires !== null && s.expires <= now)) bad("forbidden");
    if (a.role === "owner" && a.id !== s.owner) bad("forbidden");
  };
  if (op === "edge_lease") {
    if (a.role !== "executor") bad("forbidden");
    const old = sql
      .exec<{ holder: string; generation: number; expires: number }>(
        "SELECT * FROM edge_lease WHERE id=1",
      )
      .toArray()[0];
    if (old && old.expires > now && old.holder !== a.id) bad("fenced");
    if (
      p.generation !== undefined &&
      (!old || old.holder !== a.id || old.generation !== p.generation || old.expires <= now)
    )
      bad("fenced");
    const generation = p.generation === undefined ? (old?.generation ?? 0) + 1 : old!.generation;
    sql.exec(
      "INSERT INTO edge_lease VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET holder=excluded.holder,generation=excluded.generation,expires=excluded.expires",
      a.id,
      generation,
      now + 10000,
    );
    return { holder: a.id, generation, expires: now + 10000 };
  }
  if (op === "subscribe_central") {
    if (a.role !== "owner") bad("forbidden");
    const id = text(p.id),
      host = text(p.host),
      thread = text(p.thread_id),
      binding = operationBinding(p.binding);
    c.authorize(a, host);
    authorizeBinding(binding, a.scopes, now);
    if (p.expires !== null && (!Number.isSafeInteger(p.expires) || Number(p.expires) <= now))
      bad("invalid_request");
    if (
      ![
        "t3.task.finished",
        "t3.eddie.requested",
        "t3.thread.activity",
        "t3.fleet.activity",
      ].includes(String(p.name))
    )
      bad("invalid_request");
    text(p.callback_reference);
    const { epoch: _epoch, expected_expires: _expected, ...entry } = p;
    if (
      p.lease_expires !== undefined &&
      (!Number.isSafeInteger(p.lease_expires) ||
        p.expires === null ||
        Number(p.expires) > Number(p.lease_expires))
    )
      bad("invalid_request");
    const value = JSON.stringify(entry),
      old = sql
        .exec<{ value: string; owner: string; expires: number | null; active: number }>(
          "SELECT value,owner,expires,active FROM subscriptions WHERE id=?",
          id,
        )
        .toArray()[0];
    if (old && old.owner !== a.id) bad("forbidden");
    if (old && !old.active) bad("forbidden");
    if (old && old.value !== value) {
      const previous = JSON.parse(old.value),
        priorMeta = { ...previous },
        nextMeta = { ...entry };
      delete priorMeta.expires;
      delete nextMeta.expires;
      if (
        p.expected_expires !== old.expires ||
        JSON.stringify(priorMeta) !== JSON.stringify(nextMeta) ||
        (previous.lease_expires !== undefined &&
          (p.expires === null || Number(p.expires) > previous.lease_expires))
      )
        bad("idempotency_conflict");
      sql.exec(
        "UPDATE subscriptions SET expires=?,value=? WHERE id=?",
        p.expires as number | null,
        value,
        id,
      );
      return { id, stored: true, expires: p.expires };
    }
    sql.exec(
      "INSERT OR IGNORE INTO subscriptions VALUES(?,?,?,?,?,?,1,?)",
      id,
      a.id,
      host,
      thread,
      JSON.stringify(binding),
      p.expires as number | null,
      value,
    );
    return { id, stored: true, expires: p.expires };
  }
  if (op === "unsubscribe_central") {
    const s = sub(text(p.id));
    if (a.role !== "owner" || s.owner !== a.id) bad("forbidden");
    sql.exec("UPDATE subscriptions SET active=0 WHERE id=?", s.id);
    return { revoked: true };
  }
  if (op === "subscription_snapshot") {
    const s = sub(text(p.id));
    if (a.role !== "owner" || s.owner !== a.id) bad("forbidden");
    c.authorize(a, s.host);
    return { expires: s.expires, active: !!s.active };
  }
  if (op === "observation_cursor") {
    if (a.role !== "executor") bad("forbidden");
    const s = sub(text(p.subscription_id));
    authorized(s);
    authorizeBinding(operationBinding(JSON.parse(s.binding)), a.scopes, now);
    const source = JSON.stringify([s.id, s.host, s.thread]);
    return {
      cursor:
        sql
          .exec<{ cursor: number }>("SELECT cursor FROM observations WHERE source=?", source)
          .toArray()[0]?.cursor ?? 0,
    };
  }
  if (op === "observe_central") {
    if (a.role !== "executor") bad("forbidden");
    const s = sub(text(p.subscription_id));
    authorized(s);
    authorizeBinding(operationBinding(JSON.parse(s.binding)), a.scopes, now);
    const scope = operationBinding(JSON.parse(s.binding));
    if (scope.run !== null && scope.run !== p.run) bad("forbidden");
    if (
      !Number.isSafeInteger(p.expected_cursor) ||
      !Number.isSafeInteger(p.cursor) ||
      Number(p.cursor) <= Number(p.expected_cursor)
    )
      bad("invalid_request");
    const source = JSON.stringify([s.id, s.host, s.thread]),
      old =
        sql
          .exec<{ cursor: number }>("SELECT cursor FROM observations WHERE source=?", source)
          .toArray()[0]?.cursor ?? 0;
    // Exact stable event identity is independent of the subscription, delivery identity includes it.
    const identity = JSON.stringify([
        s.host,
        s.thread,
        text(p.run),
        text(p.kind),
        text(p.native_request_id),
      ]),
      id = JSON.stringify([s.id, identity]);
    const nativeEvent = p.event as { eventId: string; name: string };
    if (!nativeEvent || nativeEvent.name !== JSON.parse(s.value).name) bad("invalid_request");
    const event = JSON.stringify({ event_id: text(nativeEvent.eventId), data: p.event });
    const prior = sql
      .exec<{ event: string }>("SELECT event FROM outbox WHERE id=?", id)
      .toArray()[0];
    if (prior) {
      if (prior.event !== event) bad("idempotency_conflict");
      return { stored: true, duplicate: true, id };
    }
    if (old !== p.expected_cursor) bad("fenced");
    sql.exec(
      "INSERT INTO observations VALUES(?,?) ON CONFLICT(source) DO UPDATE SET cursor=excluded.cursor",
      source,
      p.cursor as number,
    );
    sql.exec(
      "INSERT INTO outbox(id,subscription,event,state) VALUES(?,?,?,'pending')",
      id,
      s.id,
      event,
    );
    return { stored: true, duplicate: false, id };
  }
  if (op === "outbox_pending") {
    if (a.role !== "executor") bad("forbidden");
    const after = p.after === undefined ? "" : text(p.after);
    const rows = sql
      .exec<{ id: string; subscription: string }>(
        "SELECT id,subscription FROM outbox WHERE id>? AND state IN ('pending','claimed','sending') AND next<=? AND (lease IS NULL OR lease<=?) ORDER BY id LIMIT 101",
        after,
        now,
        now,
      )
      .toArray();
    const ids: string[] = [];
    for (const row of rows.slice(0, 100)) {
      try {
        const s = sub(row.subscription);
        authorized(s);
        authorizeBinding(operationBinding(JSON.parse(s.binding)), a.scopes, now);
        ids.push(row.id);
      } catch (e) {
        if ((e as Error).message !== "forbidden") throw e;
      }
    }
    return { ids, next: rows.length > 100 ? rows[99].id : null };
  }
  if (
    op === "outbox_claim" ||
    op === "outbox_begin" ||
    op === "outbox_result" ||
    op === "outbox_stop"
  ) {
    if (a.role !== "executor") bad("forbidden");
    const id = text(p.id),
      r =
        sql
          .exec<{
            id: string;
            subscription: string;
            event: string;
            state: string;
            executor: string | null;
            generation: number;
            lease: number;
            attempts: number;
            next: number;
          }>("SELECT * FROM outbox WHERE id=?", id)
          .toArray()[0] ?? bad("not_found");
    const s = sub(r.subscription);
    authorized(s);
    authorizeBinding(operationBinding(JSON.parse(s.binding)), a.scopes, now);
    if (op === "outbox_claim") {
      if (["acknowledged", "stopped", "revoked"].includes(r.state) || r.next > now || r.lease > now)
        return { claimed: false, state: r.state };
      sql.exec(
        "UPDATE outbox SET state='claimed',executor=?,generation=generation+1,lease=? WHERE id=?",
        a.id,
        now + 10000,
        id,
      );
      return {
        claimed: true,
        id,
        generation: r.generation + 1,
        event: JSON.parse(r.event),
        callback_reference: JSON.parse(s.value).callback_reference,
        callback_scope: {
          owner: s.owner,
          host: s.host,
          thread: s.thread,
          name: JSON.parse(s.value).name,
        },
      };
    }
    if (r.executor !== a.id || r.generation !== p.generation || r.lease <= now) bad("fenced");
    if (op === "outbox_stop") {
      if (
        r.state !== "sending" ||
        ![
          "forbidden",
          "input_request_not_pending",
          "provider_not_authorized",
          "thread_unavailable",
          "identity_mismatch",
        ].includes(String(p.source_reason))
      )
        bad("invalid_request");
      sql.exec("UPDATE outbox SET state='revoked',lease=NULL WHERE id=?", id);
      return {
        state: "revoked",
        source_reason: p.source_reason,
        http_status: null,
        agent_completed: false,
      };
    }
    if (op === "outbox_begin") {
      if (r.state !== "claimed") bad("fenced");
      sql.exec(
        "UPDATE outbox SET state='sending',attempts=attempts+1,next=? WHERE id=?",
        now + Math.min(3600000, 1000 * 2 ** (r.attempts + 1)),
        id,
      );
      return { may_attempt: true, event_id: JSON.parse(r.event).event_id };
    }
    if (
      r.state !== "sending" ||
      !Number.isSafeInteger(p.http_status) ||
      Number(p.http_status) < 0 ||
      Number(p.http_status) > 599
    )
      bad("invalid_request");
    const status = Number(p.http_status),
      state =
        status >= 200 && status < 300
          ? "acknowledged"
          : r.attempts >= 6 || (status >= 300 && status < 500 && ![408, 429].includes(status))
            ? "stopped"
            : "pending";
    sql.exec("UPDATE outbox SET state=?,http_status=?,lease=NULL WHERE id=?", state, status, id);
    return { state, delivery_acknowledged: state === "acknowledged", agent_completed: false };
  }
  return undefined;
}
