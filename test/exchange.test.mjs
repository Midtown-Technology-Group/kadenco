// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { Webhook } from "standardwebhooks";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { Store } from "../src/store.mjs";
import { Bridge } from "../src/bridge.mjs";
import { FleetReader } from "../src/fleet-read.mjs";
import { httpServer } from "../src/server.mjs";
import { configSchema } from "../src/config.mjs";
import { Exchanges } from "../src/exchange.mjs";

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "eddie-exchange-")),
    key = randomBytes(32),
    store = new Store(join(dir, "bridge.db"), key);
  let now = Date.now(),
    code = 204,
    hook = () => {};
  const tokens = Object.fromEntries(
    ["eddie", "other", "caller", "stranger", "reader"].map((id) => [
      id,
      randomBytes(32).toString("base64"),
    ]),
  );
  const principal = (id) => ({
    id,
    tokenSha256: createHash("sha256").update(tokens[id]).digest("hex"),
    sessions: [],
  });
  const policy = {
    stateDirectory: dir,
    source: { type: "local-projection", databasePath: "not-opened" },
    fleetRead: { hosts: [{ name: "local" }] },
    callbackHosts: ["callbacks.example.com"],
    sessions: [],
    principals: [
      {
        ...principal("eddie"),
        eddieInbox: true,
        readHosts: [{ host: "local", projectIds: ["p"] }],
      },
      { ...principal("other"), eddieInbox: true, readHosts: [{ host: "local" }] },
      {
        ...principal("caller"),
        eddieCaller: {
          host: "local",
          threadId: "thread-a",
          reviewer: "eddie",
          expiresAt: now + 86400000,
          maxPerDay: 10,
        },
      },
      {
        ...principal("stranger"),
        eddieCaller: {
          host: "local",
          threadId: "thread-b",
          reviewer: "other",
          expiresAt: now + 86400000,
          maxPerDay: 10,
        },
      },
      { ...principal("reader"), readHosts: [{ host: "local" }] },
    ],
  };
  const posts = [],
    native = [];
  const bridge = new Bridge({
    store,
    backend: {
      read: async () => {
        throw new Error("no session access");
      },
      followup: async () => {
        throw new Error("NO EXECUTION");
      },
    },
    policy: () => policy,
    now: () => now,
    post: async (url, headers, body) => {
      posts.push({ url, headers, body });
      const p = JSON.parse(body);
      return {
        status: p.type === "verification" ? 200 : code,
        body: p.type === "verification" ? JSON.stringify({ challenge: p.challenge }) : "",
      };
    },
  });
  const reader = new FleetReader({
    policy: () => policy,
    audit: (...a) => store.audit(...a),
    transport: () => ({
      connect: async () => ({
        readThread: async ({ threadId }) => {
          native.push(threadId);
          await hook();
          return {
            thread: {
              threadId,
              projectId: "p",
              activeRunId: threadId === "thread-a" ? "run-a" : "run-b",
            },
            recentRuns: [{ runId: threadId === "thread-a" ? "run-a" : "run-b", status: "running" }],
            items: [],
            hasMore: false,
            nextPosition: null,
          };
        },
      }),
      close: async () => {},
    }),
  });
  bridge.fleetReads = reader;
  const p = {
    name: "t3.eddie.requested",
    arguments: { inbox_id: "eddie" },
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/event",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  };
  const input = {
    request_id: randomUUID(),
    run_id: "run-a",
    question: "What does EDDIE_EXCHANGE_TEST mean?",
    ttl_ms: 3600000,
  };
  t.after(async () => {
    await reader.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  return {
    dir,
    key,
    store,
    bridge,
    policy,
    p,
    input,
    posts,
    native,
    tokens,
    advance: (ms) => {
      now += ms;
    },
    code: (n) => {
      code = n;
    },
    hook: (fn) => {
      hook = fn;
    },
  };
}

test("complete signed exchange: acknowledgement, exact read, reply and caller retrieval remain distinct", async (t) => {
  const f = fixture(t),
    sub = await f.bridge.subscribe("eddie", f.p);
  const accepted = await f.bridge.exchanges.ask("caller", f.input);
  assert.equal(accepted.status, "pending");
  assert.equal(accepted.delivery.state, "pending");
  assert.equal(accepted.resumes_t3, false);
  await f.bridge.deliver();
  const post = f.posts.at(-1),
    event = new Webhook(f.p.delivery.secret).verify(post.body, post.headers);
  assert.equal(event.data.request_id, f.input.request_id);
  assert.equal(event.name, "t3.eddie.requested");
  assert.equal(JSON.stringify(event).includes(f.input.question), false);
  const ack = await f.bridge.exchanges.get("caller", { request_id: f.input.request_id });
  assert.equal(ack.delivery.state, "acknowledged");
  assert.equal(ack.delivery.request_read, false);
  assert.equal(ack.reply, null);
  await assert.rejects(
    f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply: "OK" }),
    /request_not_read/,
  );
  assert.equal(
    (await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true }))
      .question,
    f.input.question,
  );
  const replied = await f.bridge.exchanges.reply("eddie", {
    request_id: f.input.request_id,
    reply: "EDDIE_EXCHANGE_OK",
  });
  assert.equal(replied.status, "replied");
  assert.equal(replied.delivery.request_read, true);
  assert.equal(
    (await f.bridge.exchanges.get("caller", { request_id: f.input.request_id })).reply,
    "EDDIE_EXCHANGE_OK",
  );
  f.bridge.unsubscribe("eddie", { ...f.p, delivery: { mode: "webhook", url: f.p.delivery.url } });
  assert.equal(f.store.get("subscription", sub.id).active, false);
  assert.equal(f.store.all("followup").length, 0);
});

test("nonexpiring passive inbox reports null lifetime and still delivers without granting execution", async (t) => {
  const f = fixture(t);
  assert.equal((await f.bridge.subscribe("eddie", { ...f.p, ttlMs: null })).refreshBefore, null);
  const status = f.bridge.inboxSubscriptions("eddie").subscriptions[0];
  assert.equal(status.state, "active");
  assert.equal(status.expires_at, null);
  assert.equal(status.seconds_remaining, null);
  const r = await f.bridge.exchanges.ask("caller", f.input);
  assert.equal(r.resumes_t3, false);
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "acknowledged");
  assert.equal(f.store.all("command").length, 0);
  assert.equal(f.store.all("followup").length, 0);
});

test("reply consumption acknowledgement requires exact reply hash and credential-bound active run", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  const replied = await f.bridge.exchanges.reply("eddie", {
    request_id: f.input.request_id,
    reply: "EXACT_REPLY",
  });
  const p = { request_id: f.input.request_id, run_id: "run-a", reply_sha256: replied.reply_sha256 };
  assert.equal(replied.agent_acknowledged, false);
  await assert.rejects(f.bridge.exchanges.acknowledge("stranger", p), /forbidden/);
  await assert.rejects(
    f.bridge.exchanges.acknowledge("caller", { ...p, run_id: "wrong" }),
    /source_run_not_active/,
  );
  await assert.rejects(
    f.bridge.exchanges.acknowledge("caller", { ...p, reply_sha256: "0".repeat(64) }),
    /reply_mismatch/,
  );
  const ack = await f.bridge.exchanges.acknowledge("caller", p);
  assert.equal(ack.agent_acknowledged, true);
  assert.equal(ack.acknowledged_run_id, "run-a");
  assert.equal(ack.resumes_t3, false);
  assert.deepEqual(await f.bridge.exchanges.acknowledge("caller", p), ack);
  assert.equal(
    f.store.db.prepare("SELECT count(*) AS n FROM audit WHERE action='exchange.agent_ack'").get().n,
    1,
  );
});

test("only enrolled caller and assigned inbox may access a request, independent of fleet read permission", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  for (const owner of ["reader", "eddie", "other", "stranger", "unknown"]) {
    await assert.rejects(
      f.bridge.exchanges.get(owner, { request_id: f.input.request_id }),
      /forbidden/,
    );
  }
  for (const owner of ["reader", "caller", "other", "stranger"]) {
    await assert.rejects(
      f.bridge.exchanges.get(owner, { request_id: f.input.request_id }, { reviewer: true }),
      /forbidden/,
    );
    await assert.rejects(
      f.bridge.exchanges.reply(owner, { request_id: f.input.request_id, reply: "NO" }),
      /forbidden/,
    );
  }
  assert.deepEqual((await f.bridge.exchanges.list("other")).requests, []);
  assert.throws(() => f.bridge.exchanges.inbox("eddie", "other"), /forbidden/);
  await assert.rejects(f.bridge.subscribe("reader", f.p), /forbidden/);
  await assert.rejects(f.bridge.exchanges.ask("reader", f.input), /forbidden/);
  await assert.rejects(f.bridge.exchanges.ask("stranger", f.input), /forbidden/);
});

test("active run attribution cannot be spoofed; revocation while reading does not store a request", async (t) => {
  const f = fixture(t);
  await assert.rejects(
    f.bridge.exchanges.ask("caller", { ...f.input, run_id: "run-b" }),
    /source_run_not_active/,
  );
  f.hook(() => {
    f.policy.principals[2].enabled = false;
  });
  await assert.rejects(f.bridge.exchanges.ask("caller", f.input), /forbidden/);
  assert.equal(f.store.all("exchange").length, 0);
});

test("caller binding changes, source project revocation and inbox revocation stop access and pending delivery", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.exchanges.ask("caller", f.input);
  f.policy.principals[2].eddieCaller.threadId = "thread-b";
  await assert.rejects(
    f.bridge.exchanges.get("caller", { request_id: f.input.request_id }),
    /forbidden/,
  );
  f.policy.principals[2].eddieCaller.threadId = "thread-a";
  f.policy.principals[0].readHosts[0].projectIds = ["other"];
  await assert.rejects(
    f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true }),
    /forbidden/,
  );
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "revoked");
  assert.equal(f.posts.length, 1);
  f.policy.principals[0].enabled = false;
  await assert.rejects(
    f.bridge.exchanges.get("caller", { request_id: f.input.request_id }),
    /forbidden/,
  );
});

test("same request UUID survives concurrent submission and restart, conflicting content never replaces it", async (t) => {
  const f = fixture(t);
  const receipts = await Promise.all([
    f.bridge.exchanges.ask("caller", f.input),
    f.bridge.exchanges.ask("caller", f.input),
  ]);
  assert.equal(receipts[0].request_id, receipts[1].request_id);
  assert.equal(f.store.all("exchange").length, 1);
  await f.bridge.exchanges.ask("caller", {
    ...f.input,
    request_id: f.input.request_id.toUpperCase(),
  });
  assert.equal(f.store.all("exchange").length, 1);
  await assert.rejects(
    f.bridge.exchanges.ask("caller", { ...f.input, question: "DIFFERENT" }),
    /idempotency_conflict/,
  );
  const reopened = new Store(join(f.dir, "bridge.db"), f.key);
  assert.equal(reopened.get("exchange", f.input.request_id).question, f.input.question);
  reopened.close();
  const raw = readFileSync(join(f.dir, "bridge.db-wal"));
  assert.equal(raw.includes(f.input.question), false);
});

test("duplicate replies are idempotent; racing different replies cannot overwrite the first reply", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  const outcomes = await Promise.allSettled(
    ["A", "B"].map((reply) =>
      f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply }),
    ),
  );
  assert.equal(outcomes.filter((o) => o.status === "fulfilled").length, 1);
  assert.equal(outcomes.find((o) => o.status === "rejected").reason.reason, "idempotency_conflict");
  const saved = f.store.get("exchange", f.input.request_id).reply;
  assert.equal(
    (await f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply: saved }))
      .reply,
    saved,
  );
  assert.equal(
    f.store.db.prepare("SELECT count(*) AS n FROM audit WHERE action='exchange.reply'").get().n,
    1,
  );
});

test("late subscription catches up pending requests only; refresh and HTTP retry preserve event identity", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  assert.equal(
    (await f.bridge.exchanges.get("caller", { request_id: f.input.request_id })).delivery.state,
    "awaiting_subscription",
  );
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.subscribe("eddie", f.p);
  assert.equal(f.store.all("delivery").length, 1);
  f.code(503);
  await f.bridge.deliver();
  const first = JSON.parse(f.posts.at(-1).body);
  f.advance(5000);
  f.code(204);
  await f.bridge.deliver();
  assert.equal(JSON.parse(f.posts.at(-1).body).eventId, first.eventId);
  assert.equal(f.store.all("delivery")[0].attempts, 2);
  assert.equal(
    (await f.bridge.exchanges.get("caller", { request_id: f.input.request_id })).status,
    "pending",
  );
});

test("source outages retain pending delivery without blind webhook sends; unsubscribe blocks delivery", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.exchanges.ask("caller", f.input);
  f.hook(() => {
    throw new Error("native source offline PRIVATE SECRET");
  });
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "pending");
  assert.equal(f.store.all("delivery")[0].attempts, 0);
  assert.equal(f.posts.length, 1);
  f.hook(() => {});
  f.advance(30001);
  f.bridge.unsubscribe("eddie", f.p);
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "revoked");
});

test("expiration prevents reply and delivery; finite caller grant denies even saved receipts", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.exchanges.ask("caller", { ...f.input, ttl_ms: 60000 });
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  f.advance(60001);
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "revoked");
  assert.equal(
    (await f.bridge.exchanges.get("caller", { request_id: f.input.request_id })).status,
    "expired",
  );
  await assert.rejects(
    f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply: "LATE" }),
    /exchange_expired/,
  );
  assert.deepEqual((await f.bridge.exchanges.list("eddie")).requests, []);
  f.advance(86400000);
  await assert.rejects(
    f.bridge.exchanges.get("caller", { request_id: f.input.request_id }),
    /forbidden/,
  );
});

test("daily and outstanding limits bound agent work; retry does not spend another allowance", async (t) => {
  const f = fixture(t);
  f.policy.principals[2].eddieCaller.maxPerDay = 1;
  await f.bridge.exchanges.ask("caller", f.input);
  await f.bridge.exchanges.ask("caller", f.input);
  await assert.rejects(
    f.bridge.exchanges.ask("caller", { ...f.input, request_id: randomUUID() }),
    /exchange_budget_exhausted/,
  );
  f.policy.principals[2].eddieCaller.maxPerDay = 10;
  for (let i = 0; i < 4; i++)
    await f.bridge.exchanges.ask("caller", { ...f.input, request_id: randomUUID() });
  await assert.rejects(
    f.bridge.exchanges.ask("caller", { ...f.input, request_id: randomUUID() }),
    /exchange_budget_exhausted/,
  );
  let cursor;
  const ids = [];
  do {
    const page = await f.bridge.exchanges.list("eddie", { limit: 2, cursor });
    ids.push(...page.requests.map((r) => r.request_id));
    cursor = page.next_cursor;
  } while (cursor);
  assert.equal(new Set(ids).size, 5);
});

test("event type and inbox filters cannot leak requests into task subscriptions or another inbox", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("other", { ...f.p, arguments: { inbox_id: "other" } });
  await f.bridge.exchanges.ask("caller", f.input);
  assert.equal(f.store.all("delivery").length, 0);
  await assert.rejects(f.bridge.subscribe("other", f.p), /forbidden/);
  await f.bridge.subscribe("eddie", f.p);
  assert.equal(f.store.all("delivery").length, 1);
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply: "DONE" });
  await f.bridge.deliver();
  assert.equal(f.store.all("delivery")[0].status, "revoked");
  assert.equal(f.posts.filter((p) => JSON.parse(p.body).name).length, 0);
});

test("audit contains attribution and states, never question, reply or signing material", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.exchanges.ask("caller", f.input);
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", {
    request_id: f.input.request_id,
    reply: "PRIVATE ANSWER",
  });
  const audit = JSON.stringify(
    f.store.db.prepare("SELECT action,subject,outcome FROM audit").all(),
  );
  for (const secret of [f.input.question, "PRIVATE ANSWER", f.p.delivery.secret, f.tokens.caller])
    assert.equal(audit.includes(secret), false);
  for (const action of ["exchange.request", "exchange.read", "exchange.reply"])
    assert.ok(audit.includes(action));
});

test("config forbids mixed caller authority, duplicate credentials, and uninventoried targets", (t) => {
  const f = fixture(t);
  assert.ok(configSchema.safeParse(f.policy).success);
  for (const mutate of [
    (p) => p.principals[2].sessions.push("a"),
    (p) => (p.principals[2].eddieInbox = true),
    (p) => (p.principals[2].readHosts = [{ host: "local" }]),
    (p) => (p.principals[2].eddieCaller.host = "other"),
    (p) => (p.principals[2].tokenSha256 = p.principals[0].tokenSha256),
  ]) {
    const p = structuredClone(f.policy);
    mutate(p);
    assert.equal(configSchema.safeParse(p).success, false);
  }
});

test("official SDK exposes caller tools only and refuses role crossover or extra routing arguments", async (t) => {
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const connect = async (owner) => {
    const c = new Client(
      { name: "exchange-test", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    await c.connect(
      new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
        requestInit: { headers: { Authorization: "Bearer " + f.tokens[owner] } },
      }),
    );
    t.after(() => c.close());
    return c;
  };
  const caller = await connect("caller"),
    eddie = await connect("eddie"),
    reader = await connect("reader");
  assert.deepEqual((await caller.listTools()).tools.map((t) => t.name).sort(), [
    "acknowledge_eddie_reply",
    "ask_eddie",
    "get_eddie_capabilities",
    "get_eddie_conversation",
    "get_eddie_reply",
  ]);
  assert.ok((await eddie.listTools()).tools.some((t) => t.name === "reply_to_request"));
  assert.ok(
    (await eddie.listTools()).tools.find((t) => t.name === "get_inbox_subscription_status")
      ?.annotations.readOnlyHint,
  );
  assert.equal(
    (await eddie.callTool({ name: "get_inbox_subscription_status", arguments: {} }))
      .structuredContent.inbox_id,
    "eddie",
  );
  await assert.rejects(
    caller.callTool({ name: "get_inbox_subscription_status", arguments: {} }),
    /not found/,
  );
  await assert.rejects(
    reader.callTool({ name: "get_inbox_subscription_status", arguments: {} }),
    /not found/,
  );
  assert.equal(
    (await reader.listTools()).tools.some((t) => /eddie|reply_to_request/.test(t.name)),
    false,
  );
  await assert.rejects(
    caller.callTool({
      name: "reply_to_request",
      arguments: { request_id: f.input.request_id, reply: "NO" },
    }),
    /not found/,
  );
  assert.equal(
    (await caller.callTool({ name: "ask_eddie", arguments: { ...f.input, thread_id: "thread-b" } }))
      .isError,
    true,
  );
  const asked = await caller.callTool({ name: "ask_eddie", arguments: f.input });
  assert.equal(asked.structuredContent.status, "pending");
  const read = await eddie.callTool({
    name: "read_eddie_request",
    arguments: { request_id: f.input.request_id },
  });
  assert.equal(read.structuredContent.run_id, "run-a");
  const reply = await eddie.callTool({
    name: "reply_to_request",
    arguments: { request_id: f.input.request_id, reply: "OK" },
  });
  assert.equal(reply.structuredContent.resumes_t3, false);
});

test("native stdio caller proxy uses official SDK and exposes only the bound request/reply tools", async (t) => {
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const client = new Client(
    { name: "native-caller-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: ["scripts/caller-mcp.mjs"],
    env: {
      ...process.env,
      EDDIE_T3_CALLER_TOKEN: f.tokens.caller,
      EDDIE_T3_CALLER_ENDPOINT: `http://127.0.0.1:${server.address().port}/mcp`,
    },
    stderr: "pipe",
  });
  t.after(() => client.close());
  await client.connect(transport);
  assert.deepEqual((await client.listTools()).tools.map((t) => t.name).sort(), [
    "acknowledge_eddie_reply",
    "ask_eddie",
    "get_eddie_capabilities",
    "get_eddie_conversation",
    "get_eddie_reply",
  ]);
  const asked = await client.callTool({ name: "ask_eddie", arguments: f.input });
  assert.equal(asked.structuredContent.status, "pending");
  await f.bridge.exchanges.get("eddie", { request_id: f.input.request_id }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", { request_id: f.input.request_id, reply: "STDIO_OK" });
  const reply = await client.callTool({
    name: "get_eddie_reply",
    arguments: { request_id: f.input.request_id },
  });
  assert.equal(reply.structuredContent.reply, "STDIO_OK");
  assert.equal(reply.structuredContent.resumes_t3, false);
});

test("one-call CLI handles receipts, rejects privileged bearer and arbitrary endpoints without exposing credentials", async (t) => {
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const path = join(f.dir, "question.json");
  writeFileSync(path, JSON.stringify(f.input));
  const run = async (token, endpoint) => {
    const child = spawn(process.execPath, ["scripts/caller.mjs", "ask", path], {
      env: { ...process.env, EDDIE_T3_CALLER_TOKEN: token, EDDIE_T3_CALLER_ENDPOINT: endpoint },
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "",
      err = "";
    child.stdout.on("data", (b) => (out += b));
    child.stderr.on("data", (b) => (err += b));
    const code = await new Promise((resolve, reject) => {
      child.once("exit", resolve);
      child.once("error", reject);
    });
    return { code, out, err };
  };
  const endpoint = `http://127.0.0.1:${server.address().port}/mcp`;
  const ok = await run(f.tokens.caller, endpoint);
  assert.equal(ok.code, 0, ok.err);
  assert.equal(JSON.parse(ok.out).status, "pending");
  for (const [token, url] of [
    [f.tokens.eddie, endpoint],
    [f.tokens.caller, "https://evil.example/mcp"],
    [f.tokens.caller, endpoint + "?secret=PRIVATE"],
  ]) {
    const denied = await run(token, url);
    assert.equal(denied.code, 1);
    assert.equal(denied.out, "");
    assert.equal(denied.err.includes(token), false);
    assert.equal(denied.err.includes("PRIVATE"), false);
  }
});

test("binding mutation during read and late per-request revocation within a list page fail closed", async (t) => {
  const f = fixture(t);
  f.hook(() => {
    f.policy.principals[2].eddieCaller.threadId = "thread-b";
  });
  await assert.rejects(f.bridge.exchanges.ask("caller", f.input), /forbidden/);
  assert.equal(f.store.all("exchange").length, 0);
  f.hook(() => {});
  f.policy.principals[2].eddieCaller.threadId = "thread-a";
  await f.bridge.exchanges.ask("caller", {
    ...f.input,
    request_id: "00000000-0000-4000-8000-000000000001",
  });
  await f.bridge.exchanges.ask("caller", {
    ...f.input,
    request_id: "00000000-0000-4000-8000-000000000002",
  });
  let reads = 0;
  f.hook(() => {
    if (++reads === 2) f.policy.principals[2].enabled = false;
  });
  const page = await f.bridge.exchanges.list("eddie");
  assert.deepEqual(page.requests, []);
});

test("MCP 2.0 event discovery and subscriptions expose only the exact authorized inbox schema", async (t) => {
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const rpc = async (owner, method, params = {}) => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/mcp`, {
      method: "POST",
      headers: {
        Authorization: "Bearer " + f.tokens[owner],
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method,
        params: {
          ...params,
          _meta: {
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {},
            "io.modelcontextprotocol/clientInfo": { name: "events-test", version: "1" },
          },
        },
      }),
    });
    return response.json();
  };
  assert.deepEqual((await rpc("caller", "events/list")).result.events, []);
  assert.deepEqual((await rpc("reader", "events/list")).result.events, []);
  const list = await rpc("eddie", "events/list");
  assert.equal(list.result.events[0].name, "t3.eddie.requested");
  assert.deepEqual(list.result.events[0].inputSchema.required, ["inbox_id"]);
  assert.ok((await rpc("other", "events/subscribe", f.p)).error);
  assert.ok(
    (
      await rpc("eddie", "events/subscribe", {
        ...f.p,
        arguments: { inbox_id: "eddie", host: "local" },
      })
    ).error,
  );
  assert.ok((await rpc("eddie", "events/subscribe", f.p)).result.id);
  const stopped = await rpc("eddie", "events/unsubscribe", {
    ...f.p,
    delivery: { mode: "webhook", url: f.p.delivery.url },
  });
  assert.equal(stopped.error, undefined);
  assert.equal(f.store.all("subscription")[0].active, false);
});

test("caller rejects even same-origin redirects before forwarding its credential to another path", async (t) => {
  const f = fixture(t);
  let redirected = 0;
  const server = createServer((req, res) => {
    if (req.url === "/mcp") {
      res.writeHead(307, { location: "/credential-sink" });
      res.end();
    } else {
      redirected++;
      res.writeHead(401);
      res.end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const path = join(f.dir, "question.json");
  writeFileSync(path, JSON.stringify(f.input));
  const child = spawn(process.execPath, ["scripts/caller.mjs", "ask", path], {
    env: {
      ...process.env,
      EDDIE_T3_CALLER_TOKEN: f.tokens.caller,
      EDDIE_T3_CALLER_ENDPOINT: `http://127.0.0.1:${server.address().port}/mcp`,
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (b) => (output += b));
  child.stderr.on("data", (b) => (output += b));
  const code = await new Promise((resolve, reject) => {
    child.once("exit", resolve);
    child.once("error", reject);
  });
  assert.equal(code, 1);
  assert.equal(redirected, 0);
  assert.equal(output.includes(f.tokens.caller), false);
});

test("multi-round conversations preserve exact parents and sequence across retries, restart and paginated history", async (t) => {
  const f = fixture(t),
    root = await f.bridge.exchanges.ask("caller", f.input);
  assert.equal(root.conversation_id, root.request_id);
  assert.equal(root.sequence, 1);
  assert.equal(root.in_reply_to, null);
  const child = {
    ...f.input,
    request_id: randomUUID(),
    conversation_id: root.conversation_id,
    in_reply_to: root.request_id,
    question: "Second round",
  };
  await assert.rejects(f.bridge.exchanges.ask("caller", child), /reply_not_available/);
  await f.bridge.exchanges.get("eddie", { request_id: root.request_id }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", { request_id: root.request_id, reply: "First answer" });
  const pair = await Promise.all([
    f.bridge.exchanges.ask("caller", child),
    f.bridge.exchanges.ask("caller", child),
  ]);
  assert.equal(pair[0].sequence, 2);
  assert.deepEqual(pair[0], pair[1]);
  await assert.rejects(
    f.bridge.exchanges.ask("caller", { ...child, in_reply_to: child.request_id }),
    /idempotency_conflict/,
  );
  const restarted = new Exchanges(f.bridge);
  const first = await restarted.conversation("eddie", {
    conversation_id: root.conversation_id,
    limit: 1,
  });
  assert.equal(first.through_sequence, 2);
  assert.equal(first.next_cursor, 1);
  assert.equal(first.requests[0].reply, "First answer");
  const next = await restarted.conversation("caller", {
    conversation_id: root.conversation_id,
    after_sequence: first.next_cursor,
    through_sequence: first.through_sequence,
    limit: 1,
  });
  assert.equal(next.next_cursor, null);
  assert.equal(next.requests[0].question, "Second round");
  assert.equal(next.requests[0].read_at, null);
  assert.equal(f.store.all("command").length, 0);
  assert.equal(f.store.all("followup").length, 0);
});

test("conversation history includes expired and unconsumed replies without reviving them or crossing bindings", async (t) => {
  const f = fixture(t);
  const root = await f.bridge.exchanges.ask("caller", { ...f.input, ttl_ms: 60000 });
  await assert.rejects(
    f.bridge.exchanges.ask("stranger", {
      ...f.input,
      run_id: "run-b",
      request_id: randomUUID(),
      conversation_id: root.conversation_id,
      in_reply_to: root.request_id,
    }),
    /forbidden/,
  );
  await assert.rejects(
    f.bridge.exchanges.conversation("other", { conversation_id: root.conversation_id }),
    /forbidden/,
  );
  await assert.rejects(
    f.bridge.exchanges.conversation("reader", { conversation_id: root.conversation_id }),
    /forbidden/,
  );
  f.advance(60001);
  const history = await f.bridge.exchanges.conversation("eddie", {
    conversation_id: root.conversation_id,
  });
  assert.equal(history.requests[0].status, "expired");
  assert.equal(history.requests[0].read_at, null);
  assert.deepEqual((await f.bridge.exchanges.list("eddie")).requests, []);
  await assert.rejects(
    f.bridge.exchanges.reply("eddie", { request_id: root.request_id, reply: "Late" }),
    /exchange_expired/,
  );
  f.policy.principals[2].eddieCaller.threadId = "thread-b";
  await assert.rejects(
    f.bridge.exchanges.conversation("caller", { conversation_id: root.conversation_id }),
    /forbidden/,
  );
});

test("history pagination has a stable high-water mark, rechecks revocation and surfaces source outages", async (t) => {
  const f = fixture(t),
    root = await f.bridge.exchanges.ask("caller", f.input);
  await f.bridge.exchanges.get("eddie", { request_id: root.request_id }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", { request_id: root.request_id, reply: "Answer" });
  const page = await f.bridge.exchanges.conversation("caller", {
    conversation_id: root.conversation_id,
    limit: 1,
  });
  const child = await f.bridge.exchanges.ask("caller", {
    ...f.input,
    request_id: randomUUID(),
    conversation_id: root.conversation_id,
    in_reply_to: root.request_id,
  });
  const snapshot = await f.bridge.exchanges.conversation("caller", {
    conversation_id: root.conversation_id,
    through_sequence: page.through_sequence,
  });
  assert.equal(snapshot.requests.length, 1);
  const fresh = await f.bridge.exchanges.conversation("caller", {
    conversation_id: root.conversation_id,
    after_sequence: page.through_sequence,
  });
  assert.equal(fresh.requests[0].request_id, child.request_id);
  let reads = 0;
  f.hook(() => {
    if (++reads === 3) f.policy.principals[2].enabled = false;
  });
  await assert.rejects(
    f.bridge.exchanges.conversation("eddie", { conversation_id: root.conversation_id }),
    /forbidden/,
  );
  f.policy.principals[2].enabled = true;
  f.hook(() => {
    throw Object.assign(new Error("offline"), { reason: "source_unavailable" });
  });
  await assert.rejects(
    f.bridge.exchanges.conversation("caller", { conversation_id: root.conversation_id }),
    /source_unavailable/,
  );
});

test("legacy records gain independent conversation roots without changing idempotency or expiry", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  const old = f.store.get("exchange", f.input.request_id);
  delete old.conversation_id;
  delete old.in_reply_to;
  delete old.sequence;
  f.store.put("exchange", old.request_id, old);
  const restarted = new Exchanges(f.bridge),
    receipt = await restarted.ask("caller", f.input);
  assert.equal(receipt.conversation_id, old.request_id);
  assert.equal(receipt.sequence, 1);
  assert.equal(Date.parse(receipt.expires_at), old.expiresAt);
  assert.equal(f.store.get("exchange", old.request_id).contentHash, old.contentHash);
  assert.equal(
    new Exchanges(f.bridge).receipt(f.store.get("exchange", old.request_id)).sequence,
    1,
  );
});

test("passive capabilities expose distinct limits and expiry without granting execution", async (t) => {
  const f = fixture(t);
  await f.bridge.exchanges.ask("caller", f.input);
  const c = f.bridge.exchanges.capabilities("caller");
  assert.equal(c.limits.used_today, 1);
  assert.equal(c.limits.outstanding, 1);
  assert.equal(c.resumes_t3, false);
  assert.equal(c.host, "local");
  assert.throws(() => f.bridge.exchanges.capabilities("eddie"), /forbidden/);
  f.advance(86400001);
  assert.throws(() => f.bridge.exchanges.capabilities("caller"), /forbidden/);
});

test("wake reconciliation works without event data across duplicate and reordered wakeups and empty authorized pages", async (t) => {
  const f = fixture(t),
    ids = ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002"];
  for (const request_id of ids) await f.bridge.exchanges.ask("caller", { ...f.input, request_id });
  const first = f.store.get("exchange", ids[0]);
  first.caller = "stranger";
  f.store.put("exchange", ids[0], first);
  const empty = await f.bridge.exchanges.list("eddie", { limit: 1 });
  assert.equal(empty.requests.length, 0);
  assert.equal(empty.next_cursor, ids[0]);
  const page = await f.bridge.exchanges.list("eddie", { limit: 1, cursor: empty.next_cursor });
  assert.equal(page.requests[0].request_id, ids[1]);
  assert.equal(page.next_cursor, null);
  await f.bridge.exchanges.get("eddie", { request_id: ids[1] }, { reviewer: true });
  await f.bridge.exchanges.reply("eddie", { request_id: ids[1], reply: "Exact pending answer" });
  // Every wake starts a fresh pending scan; duplicate/reordered hints cannot create replies.
  for (let i = 0; i < 2; i++)
    assert.deepEqual((await f.bridge.exchanges.list("eddie")).requests, []);
  assert.equal(
    f.store.db.prepare("SELECT count(*) AS n FROM audit WHERE action='exchange.reply'").get().n,
    1,
  );
});

test("CLI preserves request ID after accepted ask loses its transport response and does not resend", async (t) => {
  const f = fixture(t),
    backend = httpServer(f.bridge);
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  let attempts = 0;
  const proxy = createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    const message = JSON.parse(body),
      isAsk = message.method === "tools/call" && message.params?.name === "ask_eddie";
    const headers = { ...req.headers };
    delete headers.host;
    delete headers["content-length"];
    delete headers.connection;
    const response = await fetch(`http://127.0.0.1:${backend.address().port}/mcp`, {
      method: "POST",
      headers,
      body,
    });
    const result = await response.text();
    if (isAsk) {
      attempts++;
      res.destroy();
      return;
    }
    res.writeHead(response.status, { "content-type": response.headers.get("content-type") });
    res.end(result);
  });
  await new Promise((r) => proxy.listen(0, "127.0.0.1", r));
  t.after(async () => {
    await new Promise((r) => proxy.close(r));
    await new Promise((r) => backend.close(r));
  });
  const path = join(f.dir, "uncertain.json");
  writeFileSync(path, JSON.stringify(f.input));
  const child = spawn(process.execPath, ["scripts/caller.mjs", "ask", path], {
    env: {
      ...process.env,
      EDDIE_T3_CALLER_TOKEN: f.tokens.caller,
      EDDIE_T3_CALLER_ENDPOINT: `http://127.0.0.1:${proxy.address().port}/mcp`,
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "",
    err = "";
  child.stdout.on("data", (b) => (out += b));
  child.stderr.on("data", (b) => (err += b));
  const code = await new Promise((resolve, reject) => {
    child.once("exit", resolve);
    child.once("error", reject);
  });
  assert.equal(code, 1);
  const receipt = JSON.parse(out);
  assert.equal(receipt.request_id, f.input.request_id);
  assert.equal(receipt.outcome, "unknown");
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(attempts, 1);
  assert.equal(f.store.all("exchange").length, 1);
  assert.equal(err.includes(f.tokens.caller), false);
  assert.equal(out.includes(f.input.question), false);
  assert.equal(
    (await f.bridge.exchanges.get("caller", { request_id: receipt.request_id })).status,
    "pending",
  );
});
