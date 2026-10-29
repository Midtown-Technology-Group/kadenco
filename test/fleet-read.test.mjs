// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { FleetReader } from "../src/fleet-read.mjs";
import { configSchema } from "../src/config.mjs";
import { httpServer } from "../src/server.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

function fixture() {
  const policy = {
    fleetRead: { hosts: [{ name: "a" }, { name: "b" }, { name: "c" }] },
    principals: [
      { id: "eddie", sessions: [], readHosts: [{ host: "a", projectIds: ["p"] }, { host: "b" }] },
    ],
    sessions: [],
  };
  const audit = [],
    opens = [],
    reads = [],
    searches = [],
    sends = [];
  let closes = 0;
  const data = {
    thread: {
      threadId: "t",
      projectId: "p",
      title: "Useful thread",
      providerInstanceId: "codex",
      runtimeMode: "full-access",
      activeRunId: "r",
      pendingRequestCount: 1,
      status: "running",
    },
    recentRuns: [{ runId: "r", status: "running" }],
    items: [
      {
        itemId: "i",
        messageId: "m",
        sourceThreadId: "t",
        position: 0,
        text: "Bearer SECRET_TOKEN_123456",
        textTruncated: true,
        nextTextOffset: 4000,
      },
      { itemId: "foreign", sourceThreadId: "other", text: "PRIVATE FOREIGN ITEM" },
    ],
    hasMore: true,
    nextPosition: 2,
  };
  const state = {
    data,
    bFailure: false,
    readHook: () => {},
    searchHook: () => {},
    inventoryProjects: [{ id: "p", title: "Project" }],
    inventoryThreads: {
      p: [{ threadId: "t", title: "Thread", settled: true, relationshipToParent: "subagent" }],
    },
  };
  const reader = new FleetReader({
    policy: () => policy,
    audit: (...a) => audit.push(a),
    transport: () => ({
      async connect(host, scope) {
        opens.push([host, scope]);
        if (host === "b" && state.bFailure)
          throw new Error("MCP authentication denied (HTTP 401) secret");
        return {
          async searchThreads(args) {
            searches.push([host, args]);
            await state.searchHook(host);
            return {
              matches: [
                {
                  threadId: "t",
                  projectId: "p",
                  snippet: "public sk-SECRET_TOKEN_123456",
                  private: "NO",
                },
                { threadId: "secret", projectId: "private", snippet: "OTHER PROJECT" },
              ],
            };
          },
          async readThread(args) {
            reads.push(args);
            await state.readHook();
            return structuredClone(state.data);
          },
          async listProjects({ cursor = 0, limit }) {
            const projects = state.inventoryProjects.slice(cursor, cursor + limit);
            return {
              projects,
              nextCursor: cursor + limit < state.inventoryProjects.length ? cursor + limit : null,
            };
          },
          async listThreads(args) {
            reads.push(args);
            const all = state.inventoryThreads[args.projectId] ?? [];
            const cursor = args.cursor ?? 0;
            return {
              projectId: args.projectId,
              total: all.length,
              threads: all.slice(cursor, cursor + args.limit),
              nextCursor: cursor + args.limit < all.length ? cursor + args.limit : null,
            };
          },
          async sendThreadMessage(...args) {
            sends.push(args);
            throw new Error("must never send");
          },
        };
      },
      async close() {
        closes++;
      },
    }),
  });
  return {
    policy,
    audit,
    opens,
    reads,
    searches,
    sends,
    state,
    reader,
    get closes() {
      return closes;
    },
  };
}

test("host and principal grants fail closed before any transport; reads never enroll execution", async () => {
  const f = fixture();
  assert.deepEqual(
    f.reader.hosts("eddie").hosts.map((h) => h.host),
    ["a", "b"],
  );
  assert.equal(f.reader.hosts("eddie").hosts[0].access, "read-only");
  for (const host of ["c", "unknown", "http://evil.example"])
    await assert.rejects(f.reader.read("eddie", { host, thread_id: "t" }), /forbidden/);
  await assert.rejects(f.reader.search("eddie", { host: "c", query: "x" }), /forbidden/);
  assert.equal(f.opens.length, 0);
  await f.reader.read("eddie", { host: "a", thread_id: "t" });
  assert.deepEqual(f.opens, [["a", "read"]]);
  assert.equal(f.sends.length, 0);
  assert.deepEqual(f.policy.sessions, []);
  assert.equal(f.closes, 1);
  f.policy.principals[0].enabled = false;
  assert.throws(() => f.reader.hosts("eddie"), /forbidden/);
});

test("search preserves partial authentication failure, project filtering and non-exhaustive coverage without secret diagnostics", async () => {
  const f = fixture();
  f.state.bFailure = true;
  const r = await f.reader.search("eddie", { query: "x", limit: 3 });
  assert.equal(r.exhaustive, false);
  assert.equal(r.results.length, 2);
  assert.deepEqual(
    r.results[0].matches.map((m) => m.threadId),
    ["t"],
  );
  assert.equal(r.results[0].available, true);
  assert.equal(r.results[1].available, false);
  assert.equal(r.results[1].reason, "authentication_required");
  assert.equal(f.closes, 2);
  assert.ok(f.opens.every(([, scope]) => scope === "read"));
  assert.equal(JSON.stringify(r).includes("SECRET_TOKEN"), false);
  assert.equal(JSON.stringify(r).includes("OTHER PROJECT"), false);
  assert.equal(JSON.stringify(f.audit).includes("query"), false);
  const denied = await f.reader.search("eddie", { host: "a", project_id: "private", query: "x" });
  assert.equal(denied.results[0].reason, "forbidden");
  assert.equal(f.searches.length, 1);
});

test("thread reads bind exact identity/project, exclude inherited items and forward native timeline/text pagination", async () => {
  const f = fixture();
  f.state.data.nextPosition = 22;
  f.state.data.items[0].position = 21;
  let r = await f.reader.read("eddie", {
    host: "a",
    thread_id: "t",
    view: "activity",
    after_position: 20,
  });
  assert.equal(r.thread.pendingRequestCount, 1);
  assert.equal(r.thread.providerInstanceId, "codex");
  assert.equal(r.items.length, 1);
  assert.equal(r.excludedInheritedItems, 1);
  assert.equal(r.hasMore, true);
  assert.equal(r.nextPosition, 22);
  assert.equal(r.items[0].nextTextOffset, 4000);
  assert.equal(r.items[0].text, "[REDACTED]");
  assert.equal(JSON.stringify(r).includes("PRIVATE FOREIGN"), false);
  assert.equal(f.reads[0].afterPosition, 20);
  assert.equal(f.reads[0].view, "activity");
  f.state.data.items[0] = {
    ...f.state.data.items[0],
    text: "remaining text",
    textTruncated: false,
    nextTextOffset: null,
  };
  r = await f.reader.read("eddie", { host: "a", thread_id: "t", item_id: "i", text_offset: 4000 });
  assert.equal(r.items[0].text, "remaining text");
  assert.equal(r.items[0].nextTextOffset, null);
  assert.equal(f.reads[1].itemId, "i");
  assert.equal(f.reads[1].textOffset, 4000);
  f.state.data.thread.threadId = "other";
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /identity_mismatch/);
  f.state.data.thread.threadId = "t";
  f.state.data.thread.projectId = "private";
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /forbidden/);
  assert.equal(f.closes, 4);
  assert.equal(f.sends.length, 0);
});

test("revocation and project restriction changes while a source read is pending prevent result disclosure", async () => {
  const f = fixture();
  f.state.readHook = () => {
    f.policy.principals[0].readHosts = [];
  };
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /forbidden/);
  assert.equal(f.closes, 1);
  const g = fixture();
  g.state.searchHook = (host) => {
    if (host === "b") g.policy.principals[0].readHosts[0].projectIds = ["different"];
  };
  const r = await g.reader.search("eddie", { query: "x" });
  assert.equal(r.results[0].matches.length, 0);
});

test("parallel reads serialize each configured host and release transport after a source error", async () => {
  const f = fixture();
  let active = 0,
    max = 0;
  f.state.readHook = async () => {
    active++;
    max = Math.max(max, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active--;
  };
  await Promise.all([
    f.reader.read("eddie", { host: "a", thread_id: "t" }),
    f.reader.read("eddie", { host: "a", thread_id: "t" }),
  ]);
  assert.equal(max, 1);
  assert.equal(f.closes, 2);
  f.state.readHook = () => {
    throw new Error("private source error with credential");
  };
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /source_unavailable/);
  assert.equal(f.closes, 3);
  await f.reader.close();
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /source_unavailable/);
});

test("fleet configuration rejects ambiguous hosts, unenrolled grants and unrestricted project-array mistakes", () => {
  const p = {
    stateDirectory: ".",
    fleetHelperPath: "helper.mjs",
    fleetRead: { hosts: [{ name: "a" }] },
    callbackHosts: [],
    principals: [
      { id: "eddie", tokenSha256: "0".repeat(64), sessions: [], readHosts: [{ host: "a" }] },
    ],
    sessions: [],
  };
  assert.equal(configSchema.safeParse(p).success, true);
  for (const change of [
    (q) => q.fleetRead.hosts.push({ name: "a" }),
    (q) => q.principals[0].readHosts.push({ host: "other" }),
    (q) => (q.principals[0].readHosts[0].projectIds = []),
    (q) => (q.fleetRead.hosts[0].name = "https://evil.example"),
  ]) {
    const q = structuredClone(p);
    change(q);
    assert.equal(configSchema.safeParse(q).success, false);
  }
});

test("official MCP client discovers and uses only narrow fleet read tools, rejects write-shaped inputs", async (t) => {
  const f = fixture(),
    token = "test-bearer";
  f.policy.principals[0].tokenSha256 = createHash("sha256").update(token).digest("hex");
  const server = httpServer({
    policy: () => f.policy,
    fleetReads: f.reader,
    store: { audit: () => {} },
    sessions: () => [],
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = new Client(
    { name: "fleet-read-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer " + token } },
    }),
  );
  t.after(() => client.close());
  const names = ["list_fleet_hosts", "inventory_threads", "search_threads", "read_thread"];
  const tools = (await client.listTools()).tools.filter((x) => names.includes(x.name));
  assert.equal(tools.length, 4);
  assert.ok(tools.every((x) => x.annotations.readOnlyHint));
  assert.equal(
    (await client.callTool({ name: "list_fleet_hosts", arguments: {} })).structuredContent.hosts
      .length,
    2,
  );
  const read = await client.callTool({
    name: "read_thread",
    arguments: { host: "a", thread_id: "t" },
  });
  assert.equal(read.isError, undefined);
  const search = await client.callTool({ name: "search_threads", arguments: { query: "x" } });
  assert.equal(search.structuredContent.exhaustive, false);
  const inventory = await client.callTool({ name: "inventory_threads", arguments: { host: "a" } });
  assert.equal(inventory.structuredContent.complete, true);
  assert.equal(inventory.structuredContent.threads[0].settled, true);
  for (const extra of [
    { message: "send me" },
    { view: "shell" },
    { text_offset: 4 },
    { item_id: "i", after_position: 2 },
  ]) {
    assert.equal(
      (
        await client.callTool({
          name: "read_thread",
          arguments: { host: "a", thread_id: "t", ...extra },
        })
      ).isError,
      true,
    );
  }
  const denied = await client.callTool({
    name: "read_thread",
    arguments: { host: "c", thread_id: "t" },
  });
  assert.equal(denied.structuredContent.reason, "forbidden");
  f.state.readHook = () => {
    throw Object.assign(new Error("SECRET"), { reason: "source_internal_error" });
  };
  const failure = await client.callTool({
    name: "read_thread",
    arguments: { host: "a", thread_id: "t", after_position: 1182 },
  });
  assert.equal(failure.isError, true);
  assert.equal(failure.structuredContent.reason, "source_internal_error");
  assert.equal(failure.structuredContent.read_recovery.after_position, 1182);
  assert.equal(failure.structuredContent.retry_read.attempts_used, 2);
  assert.equal(JSON.stringify(failure).includes("SECRET"), false);
  assert.equal(f.sends.length, 0);
});

test("full inventory walks more than 100 projects and all thread pages without a total cap", async () => {
  const f = fixture();
  f.policy.principals[0].readHosts[0] = { host: "a" };
  f.state.inventoryProjects = Array.from({ length: 102 }, (_, i) => ({
    id: "p" + i,
    title: "Project " + i,
  }));
  f.state.inventoryThreads = {
    p0: Array.from({ length: 205 }, (_, i) => ({
      threadId: "t" + i,
      title: "Thread " + i,
      settled: i % 2 === 0,
      relationshipToParent: "subagent",
    })),
    p101: [{ threadId: "last", settled: true }],
  };
  let cursor,
    all = [],
    pages = 0;
  do {
    const r = await f.reader.inventory("eddie", { host: "a", cursor });
    pages++;
    all.push(...r.threads);
    cursor = r.next_cursor;
    assert.equal(r.complete, cursor === null);
  } while (cursor);
  assert.equal(all.length, 206);
  assert.equal(new Set(all.map((t) => t.threadId)).size, 206);
  assert.equal(all.at(-1).threadId, "last");
  assert.ok(pages >= 3);
  assert.ok(
    f.reads.every((r) => r.includeSubagents === true && r.settled === null && r.snoozed === null),
  );
  assert.ok(f.opens.every(([, scope]) => scope === "read"));
  assert.equal(f.sends.length, 0);
});

test("inventory scopes filter projects and bind continuation cursors to host and current grant", async () => {
  const f = fixture();
  f.state.inventoryProjects = [
    { id: "private", title: "PRIVATE PROJECT" },
    { id: "p", title: "Allowed" },
  ];
  f.state.inventoryThreads.p = Array.from({ length: 102 }, (_, i) => ({ threadId: "t" + i }));
  const a = await f.reader.inventory("eddie", { host: "a" });
  assert.equal(a.threads.length, 100);
  assert.equal(a.complete, false);
  assert.equal(JSON.stringify(a).includes("PRIVATE PROJECT"), false);
  await assert.rejects(
    f.reader.inventory("eddie", { host: "b", cursor: a.next_cursor }),
    /invalid_inventory_cursor/,
  );
  const recovered = fixture();
  recovered.reader.cursorKey = Buffer.from(f.reader.cursorKey);
  recovered.state.inventoryThreads.p = f.state.inventoryThreads.p;
  recovered.state.inventoryProjects = f.state.inventoryProjects;
  const continuation = await recovered.reader.inventory("eddie", {
    host: "a",
    cursor: a.next_cursor,
  });
  assert.equal(continuation.threads.length, 2);
  assert.equal(continuation.complete, true);
  const [payload, signature] = a.next_cursor.split("."),
    tampered = JSON.parse(Buffer.from(payload, "base64url"));
  tampered.threadOffset = 1000000;
  await assert.rejects(
    f.reader.inventory("eddie", {
      host: "a",
      cursor: Buffer.from(JSON.stringify(tampered)).toString("base64url") + "." + signature,
    }),
    /invalid_inventory_cursor/,
  );
  f.policy.principals[0].readHosts[0].projectIds = ["different"];
  await assert.rejects(
    f.reader.inventory("eddie", { host: "a", cursor: a.next_cursor }),
    /invalid_inventory_cursor/,
  );
  for (const cursor of [
    "junk",
    Buffer.from(JSON.stringify({ version: 1, host: "a", projectOffset: -1 })).toString("base64url"),
  ])
    await assert.rejects(
      f.reader.inventory("eddie", { host: "a", cursor }),
      /invalid_inventory_cursor/,
    );
});

test("inventory refuses false completion on unavailable host or changed project while resuming", async () => {
  const f = fixture();
  f.state.inventoryThreads.p = Array.from({ length: 102 }, (_, i) => ({ threadId: "t" + i }));
  const a = await f.reader.inventory("eddie", { host: "a" });
  f.state.inventoryProjects = [{ id: "different", title: "Changed" }];
  await assert.rejects(
    f.reader.inventory("eddie", { host: "a", cursor: a.next_cursor }),
    /inventory_changed/,
  );
  f.state.inventoryProjects = [];
  await assert.rejects(
    f.reader.inventory("eddie", { host: "a", cursor: a.next_cursor }),
    /inventory_changed/,
  );
  f.state.bFailure = true;
  await assert.rejects(f.reader.inventory("eddie", { host: "b" }), /authentication_required/);
  assert.ok(f.audit.some((a) => a[0] === "fleet.inventory" && a[2] === "authentication_required"));
});

test("read-only transient recovery retries the exact view/cursor once and records the recovered error", async () => {
  const f = fixture();
  f.state.data.nextPosition = 1207;
  let calls = 0;
  f.state.readHook = () => {
    if (++calls === 1)
      throw Object.assign(new Error("PRIVATE native error"), { reason: "source_internal_error" });
  };
  const r = await f.reader.read("eddie", {
    host: "a",
    thread_id: "t",
    view: "messages",
    after_position: 1182,
  });
  assert.equal(calls, 2);
  assert.deepEqual(f.reads[0], f.reads[1]);
  assert.equal(r.readback.attempts, 2);
  assert.equal(r.readback.recovered_from, "source_internal_error");
  assert.equal(f.audit.filter((a) => a[0] === "fleet.read.retry").length, 1);
  assert.equal(f.sends.length, 0);
  assert.equal(JSON.stringify(r).includes("PRIVATE native"), false);
});

test("read failures distinguish transient exhaustion, invalid request, auth and unknown source errors", async () => {
  for (const reason of [
    "source_timeout",
    "source_internal_error",
    "invalid_source_request",
    "authentication_required",
    "source_unavailable",
  ]) {
    const f = fixture();
    f.state.readHook = () => {
      throw Object.assign(new Error("secret"), { reason });
    };
    await assert.rejects(
      f.reader.read("eddie", { host: "a", thread_id: "t", after_position: 1182 }),
      (e) => {
        assert.equal(e.reason, reason);
        assert.equal(e.readRecovery.after_position, 1182);
        assert.equal(e.retryRead.allowed, reason === "source_timeout");
        assert.equal(e.retryRead.attempts_used, reason === "source_internal_error" ? 2 : 1);
        return true;
      },
    );
    assert.equal(f.reads.length, reason === "source_internal_error" ? 2 : 1);
  }
  const f = fixture();
  f.state.readHook = () => {
    f.policy.principals[0].readHosts = [];
    throw Object.assign(new Error(), { reason: "source_internal_error" });
  };
  await assert.rejects(f.reader.read("eddie", { host: "a", thread_id: "t" }), /forbidden/);
  assert.equal(f.reads.length, 1);
});

test("pagination refuses stalled/backward cursors and missing text offsets, but preserves advancing empty pages", async () => {
  for (const data of [
    { hasMore: true, nextPosition: 1182 },
    { hasMore: true, nextPosition: null },
    { items: [{ sourceThreadId: "t", text: "x", textTruncated: true, nextTextOffset: null }] },
  ]) {
    const f = fixture();
    Object.assign(f.state.data, { nextPosition: 1207 }, data);
    await assert.rejects(
      f.reader.read("eddie", { host: "a", thread_id: "t", after_position: 1182 }),
      /invalid_source_pagination/,
    );
    assert.equal(f.reads.length, 1);
  }
  const f = fixture();
  Object.assign(f.state.data, { items: [], nextPosition: 1207 });
  const r = await f.reader.read("eddie", { host: "a", thread_id: "t", after_position: 1182 });
  assert.equal(r.hasMore, true);
  assert.equal(r.items.length, 0);
  assert.equal(r.nextPosition, 1207);
});

test("redaction never cuts a native UTF-16 chunk or advances over unread source characters", async () => {
  const f = fixture();
  f.state.data.items = [
    {
      sourceThreadId: "t",
      itemId: "long",
      position: 1,
      text: "whsec_a " + "x".repeat(3992),
      textTruncated: true,
      nextTextOffset: 4000,
    },
  ];
  const r = await f.reader.read("eddie", { host: "a", thread_id: "t" });
  assert.equal(r.items[0].nextTextOffset, 4000);
  assert.ok(r.items[0].text.length > 4000);
  assert.ok(r.items[0].text.endsWith("x".repeat(3992)));
  f.state.data.items[0].nextTextOffset = 4000;
  await assert.rejects(
    f.reader.read("eddie", { host: "a", thread_id: "t", item_id: "long", text_offset: 4000 }),
    /invalid_source_pagination/,
  );
});

test("malformed final pages and oversized native arrays fail without losing a resumable cursor", async () => {
  for (const data of [
    { hasMore: false, nextPosition: "1207" },
    { hasMore: false, nextPosition: -1 },
    { hasMore: false, nextPosition: 1181 },
    { hasMore: undefined, nextPosition: null },
  ]) {
    const f = fixture();
    Object.assign(f.state.data, data);
    await assert.rejects(
      f.reader.read("eddie", { host: "a", thread_id: "t", after_position: 1182 }),
      (e) => {
        assert.equal(e.reason, "invalid_source_pagination");
        assert.equal(e.readRecovery.after_position, 1182);
        return true;
      },
    );
    assert.equal(f.reads.length, 1);
  }
  for (const items of [
    Array.from({ length: 26 }, (_, i) => ({ sourceThreadId: "t", position: 1183 + i, text: "x" })),
    [null],
  ]) {
    const f = fixture();
    Object.assign(f.state.data, { items, hasMore: false, nextPosition: 1209 });
    await assert.rejects(
      f.reader.read("eddie", { host: "a", thread_id: "t", after_position: 1182 }),
      (e) => {
        assert.equal(e.reason, "source_protocol_error");
        assert.equal(e.readRecovery.after_position, 1182);
        return true;
      },
    );
    assert.equal(f.reads.length, 1);
  }
});
