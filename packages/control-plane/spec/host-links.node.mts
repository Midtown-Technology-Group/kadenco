// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:http";
import { randomUUID, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../../../dist/store.mjs";
import { centralTransport } from "../src/transport.ts";
import {
  hostLinkSchema,
  hostLinkOperation,
  hostLinkLimits,
  type Reference,
} from "../src/host-links.ts";
import { ConnectorInbox, HostConnector } from "../src/host-connector.ts";
import type { ServicePrincipal } from "../src/services.ts";

function fixture(path = ":memory:") {
  const db = new DatabaseSync(path);
  const sql = {
    exec(q: string, ...args: unknown[]) {
      if (q.trimStart().startsWith("CREATE")) {
        db.exec(q);
        return { toArray: () => [] };
      }
      const s = db.prepare(q),
        result = s.columns().length
          ? s.all(...(args as never[]))
          : (s.run(...(args as never[])), []);
      return {
        toArray: () => result,
        one: () => {
          assert.equal(result.length, 1);
          return result[0];
        },
      };
    },
  } as unknown as SqlStorage;
  hostLinkSchema(sql);
  let now = 1000;
  const binding = {
    project: "project",
    provider: "provider",
    run: "run",
    grant: "grant",
    revision: 1,
    expires: 1e12,
  };
  const actors = new Map<string, ServicePrincipal>([
    [
      "owner",
      { id: "owner", role: "owner", hosts: ["a", "b"], scopes: [binding], expiresAt: 1e12 },
    ],
    ...["a", "b"].map(
      (host) =>
        [
          host,
          {
            id: host,
            role: "executor" as const,
            hosts: [host],
            scopes: [binding],
            expiresAt: 1e12,
          },
        ] as [string, ServicePrincipal],
    ),
  ]);
  const revoked = new Set<string>(),
    refs = new Map<string, Reference>(),
    ops: string[] = [];
  function call(actorId: string, op: string, p: Record<string, unknown>): Record<string, unknown> {
    ops.push(op);
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = hostLinkOperation(
        {
          sql,
          now,
          actorId,
          principal: (id) => {
            const a = actors.get(id);
            if (!a) throw Error("forbidden");
            return a;
          },
          authorize: (a, host) => {
            if (revoked.has(a.id) || !a.hosts.includes(host)) throw Error("forbidden");
          },
          reference: (id) => {
            const r = refs.get(id);
            if (!r) throw Error("not_found");
            return r;
          },
        },
        op,
        p,
      ) as Record<string, unknown>;
      db.exec("COMMIT");
      return result;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }
  function publish(host = "a", thread = "thread-a") {
    const id = randomUUID();
    refs.set(id, { request_id: id, host, thread_id: thread, binding, owner: "owner" });
    return { id, sequence: Number(call("owner", "link_publish", { request_id: id }).sequence) };
  }
  return {
    db,
    sql,
    actors,
    revoked,
    refs,
    binding,
    ops,
    call,
    publish,
    now: (n: number) => {
      now = n;
    },
  };
}

test("startup recovers an unsent open and a live predecessor without reviving a retired UUID", async () => {
  const f = fixture(),
    store = new Store(":memory:", randomBytes(32));
  let offline = true;
  const call = async (op: string, p: object) => {
    if (op === "link_open" && offline) {
      offline = false;
      throw Error("offline_before_send");
    }
    try {
      return f.call("a", op, p as Record<string, unknown>);
    } catch (e) {
      return { reason: (e as Error).message };
    }
  };
  try {
    const first = new HostConnector("a", randomUUID(), new ConnectorInbox(store, "a"), call);
    assert.equal((await first.tick()).state, "reconcile");
    assert.equal((await first.tick()).state, "page_committed");
    const next = new HostConnector("a", randomUUID(), new ConnectorInbox(store, "a"), call);
    assert.equal((await next.tick()).state, "reconcile");
    f.now(11001);
    assert.equal((await next.tick()).state, "page_committed");
    assert.equal((await first.tick()).state, "held");
    assert.equal((await first.tick()).state, "held");
    assert.equal(f.db.prepare("SELECT count(*) n FROM host_link_sessions").get()!.n, 2);
  } finally {
    store.close();
    f.db.close();
  }
});

test("revoked reference yields a redacted durable refusal while another owner progresses", () => {
  const f = fixture(),
    store = new Store(":memory:", randomBytes(32));
  try {
    const connection = randomUUID();
    f.call("a", "link_open", { host: "a", connection });
    const old = f.publish();
    f.actors.set("other", { ...f.actors.get("owner")!, id: "other" });
    const id = randomUUID();
    f.refs.set(id, {
      request_id: id,
      host: "a",
      thread_id: "other-thread",
      binding: f.binding,
      owner: "other",
    });
    f.call("other", "link_publish", { request_id: id });
    f.revoked.add("owner");
    const page = f.call("a", "link_page", { host: "a", connection, generation: 1, after: 0 });
    assert.deepEqual(page.refused, [{ sequence: old.sequence, reason: "forbidden" }]);
    assert.equal((page.items as Reference[])[0].request_id, id);
    assert.equal(JSON.stringify(page).includes(old.id), false);
    const inbox = new ConnectorInbox(store, "a");
    inbox.accept(page.items as unknown[], Number(page.next), page.refused as unknown[]);
    assert.equal(inbox.read(old.id), undefined);
    assert.equal(inbox.read(id)!.thread_id, "other-thread");
    assert.equal(store.all("connector_refusal").length, 1);
    f.call("a", "link_ack", { host: "a", connection, generation: 1, after: page.next });
    assert.equal(f.db.prepare("SELECT count(*) n FROM host_link_refs").get()!.n, 2);
    assert.throws(
      () =>
        inbox.accept([], Number(page.next) + 1, [
          { sequence: Number(page.next) + 1, reason: "forbidden", thread_id: "leak" },
        ]),
      /invalid_connector_page/,
    );
    assert.equal(inbox.cursor(), page.next);
  } finally {
    store.close();
    f.db.close();
  }
});

test("two host sessions coexist, renew independently, fence stale processes and keep original target", () => {
  const f = fixture(),
    ca = randomUUID(),
    cb = randomUUID();
  try {
    const a = f.call("a", "link_open", { host: "a", connection: ca });
    const b = f.call("b", "link_open", { host: "b", connection: cb });
    assert.equal(a.generation, 1);
    assert.equal(b.generation, 1);
    assert.deepEqual(f.call("a", "link_open", { host: "a", connection: ca }), a);
    assert.deepEqual(f.call("a", "link_status", { host: "a", connection: randomUUID() }), {
      host: "a",
      active: false,
    });
    assert.throws(
      () => f.call("a", "link_open", { host: "a", connection: randomUUID() }),
      /fenced/,
    );
    f.now(9000);
    f.call("b", "link_renew", { host: "b", connection: cb, generation: 1 });
    f.now(11001);
    assert.throws(
      () => f.call("a", "link_renew", { host: "a", connection: ca, generation: 1 }),
      /fenced/,
    );
    const fresh = f.call("a", "link_open", { host: "a", connection: randomUUID() });
    assert.equal(fresh.generation, 2);
    assert.throws(() => f.call("a", "link_open", { host: "a", connection: ca }), /fenced/);
    f.call("b", "link_renew", { host: "b", connection: cb, generation: 1 });
    assert.throws(() => f.call("a", "link_status", { host: "b" }), /forbidden/);
    f.actors.get("a")!.hosts = ["a", "b"];
    assert.throws(() => f.call("a", "link_status", { host: "a" }), /forbidden/);
    f.actors.get("a")!.hosts = ["a"];
    assert.throws(
      () => f.call("a", "link_status", { host: "a", role: "owner" }),
      /invalid_request/,
    );
  } finally {
    f.db.close();
  }
});

test("central SQL reconstruction retains session tombstones and exact reference cursors", () => {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-link-central-")),
    path = join(dir, "central.db"),
    connection = randomUUID();
  let f = fixture(path);
  try {
    f.call("a", "link_open", { host: "a", connection });
    const published = f.publish();
    f.db.close();
    f = fixture(path);
    assert.equal(f.call("a", "link_open", { host: "a", connection }).generation, 1);
    const p = { host: "a", connection, generation: 1 };
    const page = f.call("a", "link_page", { ...p, after: 0 });
    assert.equal((page.items as { request_id: string }[])[0].request_id, published.id);
    f.call("a", "link_ack", { ...p, after: page.next });
    f.now(11001);
    f.call("a", "link_open", { host: "a", connection: randomUUID() });
    assert.throws(() => f.call("a", "link_open", { host: "a", connection }), /fenced/);
    assert.equal(f.db.prepare("SELECT COUNT(*) AS n FROM host_link_refs").get()!.n, 1);
  } finally {
    f.db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("bounded exact-host replay and immutable UUID references revalidate current origin and executor scope", () => {
  const f = fixture(),
    connection = randomUUID();
  try {
    f.call("a", "link_open", { host: "a", connection });
    const first = f.publish(),
      second = f.publish("b", "thread-b");
    assert.equal(
      f.call("owner", "link_publish", { request_id: first.id }).sequence,
      first.sequence,
    );
    const base = { host: "a", connection, generation: 1 };
    const page = f.call("a", "link_page", { ...base, after: 0 });
    assert.equal((page.items as Reference[]).length, 1);
    assert.equal((page.items as Reference[])[0].thread_id, "thread-a");
    assert.throws(
      () => f.call("a", "link_page", { ...base, after: second.sequence }),
      /cursor_mismatch/,
    );
    f.revoked.add("owner");
    assert.deepEqual(f.call("a", "link_page", { ...base, after: 0 }).refused, [
      { sequence: first.sequence, reason: "forbidden" },
    ]);
    assert.throws(() => f.call("owner", "link_publish", { request_id: first.id }), /forbidden/);
    f.revoked.clear();
    f.actors.get("a")!.scopes = [{ ...f.binding, project: "wrong" }];
    assert.deepEqual(f.call("a", "link_page", { ...base, after: 0 }).refused, [
      { sequence: first.sequence, reason: "forbidden" },
    ]);
    f.actors.get("a")!.scopes = [f.binding];
    f.actors.get("a")!.expiresAt = 1000;
    assert.throws(() => f.call("a", "link_status", { host: "a" }), /forbidden/);
  } finally {
    f.db.close();
  }
});

test("one offline host backpressures at the bound without filling another host", () => {
  const f = fixture();
  try {
    for (let i = 0; i < hostLinkLimits.pending; i++) f.publish();
    assert.throws(() => f.publish(), /host_backpressure/);
    assert.ok(f.publish("b", "thread-b").sequence);
    const c = randomUUID();
    f.call("a", "link_open", { host: "a", connection: c });
    const page = f.call("a", "link_page", { host: "a", connection: c, generation: 1, after: 0 });
    assert.equal((page.items as unknown[]).length, hostLinkLimits.page);
    assert.ok(Buffer.byteLength(JSON.stringify(page)) < 65536);
    assert.throws(
      () => f.call("a", "link_ack", { host: "a", connection: c, generation: 1, after: 256 }),
      /cursor_mismatch/,
    );
    f.call("a", "link_ack", { host: "a", connection: c, generation: 1, after: page.next });
    assert.ok(f.publish().sequence);
  } finally {
    f.db.close();
  }
});

test(
  "actual outbound HTTP transport catches up after partition, lost open/page/ack and process restart without native dispatch",
  { timeout: 5000 },
  async () => {
    const f = fixture(),
      dir = mkdtempSync(join(tmpdir(), "kadenco-links-")),
      key = randomBytes(32);
    let lose = "link_open",
      partitionA = false;
    const server = createServer(async (req, res) => {
      try {
        let text = "";
        for await (const part of req) text += part;
        const token = req.headers.authorization?.replace("Bearer synthetic-", "") ?? "";
        const result = f.call(token, req.url!.slice(1), JSON.parse(text));
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify(result));
      } catch (e) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ reason: e instanceof Error ? e.message : "internal_error" }));
      }
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const transport = (host: string) =>
      centralTransport({
        origin: "https://fixture.invalid",
        token: () => "synthetic-" + host,
        fetch: async (url, init) => {
          if (host === "a" && partitionA) throw Error("fixture_partition");
          const op = new URL(String(url)).pathname.slice(1);
          const response = await fetch(`http://127.0.0.1:${port}/${op}`, init);
          if (host === "a" && op === lose) {
            lose = "";
            await response.arrayBuffer();
            throw Error("lost_response");
          }
          return response;
        },
      });
    let aStore = new Store(join(dir, "a.db"), key),
      bStore = new Store(join(dir, "b.db"), key);
    try {
      const id = f.publish().id,
        bId = f.publish("b", "thread-b").id;
      let ai = new ConnectorInbox(aStore, "a");
      const bi = new ConnectorInbox(bStore, "b");
      let a = new HostConnector("a", randomUUID(), ai, transport("a"));
      const b = new HostConnector("b", randomUUID(), bi, transport("b"));
      const [firstA, firstB] = await Promise.all([a.tick(), b.tick()]);
      assert.equal(firstA.state, "reconcile");
      assert.equal(firstB.state, "page_committed");
      assert.equal((await a.tick()).state, "page_committed");
      assert.equal(
        f.ops.filter((op) => op === "link_open").length,
        2,
        "lost open uses status, never a second open",
      );
      assert.equal(ai.read(id)?.thread_id, "thread-a");
      assert.equal(bi.read(bId)?.host, "b");
      const later = f.publish().id;
      lose = "link_page";
      assert.equal((await a.tick()).state, "reconcile");
      assert.equal(ai.read(later), undefined);
      lose = "link_ack";
      assert.equal((await a.tick()).state, "reconcile");
      assert.equal(ai.read(later)?.host, "a");
      assert.equal((await a.tick()).state, "page_committed");
      aStore.put("command", id, { state: "uncertain", safe_to_resend: false });
      partitionA = true;
      f.now(9000);
      await a.tick();
      assert.equal((await b.tick()).state, "page_committed");
      f.now(11001);
      partitionA = false;
      assert.equal((await a.tick()).state, "held");
      assert.equal((await b.tick()).state, "page_committed");
      aStore.close();
      aStore = new Store(join(dir, "a.db"), key);
      ai = new ConnectorInbox(aStore, "a");
      a = new HostConnector("a", randomUUID(), ai, transport("a"));
      assert.equal((await a.tick()).state, "page_committed");
      assert.equal(aStore.get("command", id).safe_to_resend, false);
      assert.ok(
        f.ops.every((op) => op.startsWith("link_")),
        "connectivity never invokes native claim/begin/execute",
      );
      assert.throws(() => new ConnectorInbox(aStore, "b"), /host_identity_mismatch/);
    } finally {
      aStore.close();
      bStore.close();
      f.db.close();
      await new Promise<void>((r) => server.close(() => r()));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);

test("durable inbox commit failure rolls back cursor/references; unknown command receipt is never rewritten", () => {
  const store = new Store(":memory:", randomBytes(32)),
    inbox = new ConnectorInbox(store, "a"),
    id = randomUUID();
  const frame = {
    request_id: id,
    host: "a",
    thread_id: "exact-thread",
    sequence: 1,
    binding: { project: "p", provider: "v", run: "r", grant: "g", revision: 1, expires: 1e12 },
  };
  store.put("command", id, { state: "uncertain", native_message_id: null, run_id: null });
  const put = store.put.bind(store);
  try {
    store.put = (kind, key, value) => {
      if (kind === "connector_host") throw Error("fixture_write_failure");
      return put(kind, key, value);
    };
    assert.throws(() => inbox.accept([frame], 1), /fixture_write_failure/);
    assert.equal(inbox.cursor(), 0);
    assert.equal(inbox.read(id), undefined);
    store.put = put;
    inbox.accept([frame], 1);
    assert.throws(
      () => inbox.accept([{ ...frame, sequence: 2, thread_id: "wrong-thread" }], 2),
      /immutable_reference/,
    );
    assert.equal(inbox.cursor(), 1);
    assert.equal(store.get("command", id).state, "uncertain");
  } finally {
    store.close();
  }
});

test("large reference pages stay within transport bytes and cannot forge original-host metadata", () => {
  const f = fixture(),
    connection = randomUUID();
  try {
    f.binding.run = "r".repeat(3000);
    f.call("a", "link_open", { host: "a", connection });
    for (let i = 0; i < 40; i++) f.publish();
    const page = f.call("a", "link_page", { host: "a", connection, generation: 1, after: 0 });
    assert.ok((page.items as unknown[]).length < 32);
    assert.equal(page.more, true);
    assert.ok(Buffer.byteLength(JSON.stringify(page)) < hostLinkLimits.pageBytes);
    const id = f.publish().id;
    assert.throws(
      () => f.call("owner", "link_publish", { request_id: id, host: "b", thread_id: "foreign" }),
      /invalid_request/,
    );
    f.refs.get(id)!.host = "b";
    assert.throws(
      () => f.call("owner", "link_publish", { request_id: id }),
      /idempotency_conflict/,
    );
    f.binding.run = "x".repeat(9000);
    assert.throws(() => f.publish(), /invalid_request/);
  } finally {
    f.db.close();
  }
});

test("history/session quotas fail closed instead of discarding deduplication or fencing records", () => {
  const f = fixture();
  try {
    for (let i = 0; i < hostLinkLimits.sessions; i++) {
      f.now(1000 + i * 10001);
      f.call("a", "link_open", { host: "a", connection: randomUUID() });
    }
    f.now(1000 + hostLinkLimits.sessions * 10001);
    assert.throws(
      () => f.call("a", "link_open", { host: "a", connection: randomUUID() }),
      /connector_history_full/,
    );
    const insert = f.db.prepare(
      "INSERT INTO host_link_refs(host,request,owner,thread,binding) VALUES(?,?,?,?,?)",
    );
    for (let i = 0; i < hostLinkLimits.history; i++)
      insert.run("b", randomUUID(), "owner", "t", JSON.stringify(f.binding));
    const last = f.db
      .prepare("SELECT MAX(sequence) AS seq FROM host_link_refs WHERE host='b'")
      .get()!.seq;
    f.call("b", "link_open", { host: "b", connection: randomUUID() });
    f.db.prepare("UPDATE host_links SET ack=?,sent=? WHERE host='b'").run(last, last);
    assert.throws(() => f.publish("b", "t"), /host_backpressure/);
    assert.equal(
      f.db.prepare("SELECT COUNT(*) AS n FROM host_link_refs WHERE host='b'").get()!.n,
      hostLinkLimits.history,
    );
  } finally {
    f.db.close();
  }
});

test(
  "slow host startup does not hold another host or admit concurrent ticks",
  { timeout: 5000 },
  async () => {
    const f = fixture(),
      sa = new Store(":memory:", randomBytes(32)),
      sb = new Store(":memory:", randomBytes(32));
    let release!: () => void, entered!: () => void;
    const gate = new Promise<void>((r) => {
        release = r;
      }),
      ready = new Promise<void>((r) => {
        entered = r;
      });
    const a = new HostConnector("a", randomUUID(), new ConnectorInbox(sa, "a"), async (op, p) => {
      if (op === "link_renew") {
        entered();
        await gate;
      }
      return f.call("a", op, p as Record<string, unknown>);
    });
    const b = new HostConnector("b", randomUUID(), new ConnectorInbox(sb, "b"), async (op, p) =>
      f.call("b", op, p as Record<string, unknown>),
    );
    try {
      const waiting = a.tick();
      await ready;
      assert.equal((await a.tick()).state, "busy");
      assert.equal((await b.tick()).state, "page_committed");
      release();
      assert.equal((await waiting).state, "page_committed");
    } finally {
      release();
      sa.close();
      sb.close();
      f.db.close();
    }
  },
);

test("foreign connection replies hold the connector without attempting a successor or a native send", async () => {
  const store = new Store(":memory:", randomBytes(32));
  let calls = 0;
  try {
    const c = new HostConnector("a", randomUUID(), new ConnectorInbox(store, "a"), async () => {
      calls++;
      return { host: "b", connection: randomUUID(), generation: 1 };
    });
    assert.equal((await c.tick()).state, "held");
    assert.equal((await c.tick()).state, "held");
    assert.equal(calls, 1);
    assert.equal(store.all("connector_reference").length, 0);
  } finally {
    store.close();
  }
});
