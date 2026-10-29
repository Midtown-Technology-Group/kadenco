// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Store } from "../src/store.mjs";
import { Bridge } from "../src/bridge.mjs";

function fixture(t) {
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  let now = Date.parse("2026-10-27T00:00:00Z"),
    outage = false,
    revoked = false,
    readFail = false,
    posts = [];
  const policy = {
    principals: [{ id: "eddie", sessions: [], readHosts: [{ host: "a" }, { host: "b" }] }],
    sessions: [],
    callbackHosts: ["callbacks.example.com"],
  };
  const grant = { providerInstanceIds: ["opencode"] };
  const inventory = {
    a: [
      {
        threadId: "t",
        projectId: "p",
        providerInstanceId: "opencode",
        latestRunId: "r",
        status: "completed",
        updatedAt: new Date(now + 1000).toISOString(),
      },
    ],
    b: [],
  };
  const data = {
    thread: {
      threadId: "t",
      projectId: "p",
      providerInstanceId: "opencode",
      pendingRequestCount: 0,
    },
    runs: [{ runId: "r", status: "completed", completedAt: new Date(now + 1000).toISOString() }],
  };
  const calls = [],
    questions = [];
  const bridge = new Bridge({
    store,
    policy: () => policy,
    backend: {},
    now: () => now,
    post: async (_u, _h, body) => {
      const e = JSON.parse(body);
      posts.push(e);
      return { status: 200, body: JSON.stringify({ challenge: e.challenge }) };
    },
  });
  bridge.commands = {
    grant: (owner, host, project) => {
      if (
        revoked ||
        owner !== "eddie" ||
        !["a", "b"].includes(host) ||
        (project && project !== "p")
      )
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
      return { grant };
    },
    requests: async (_o, p) => ({
      project_id: "p",
      requests: questions.filter(
        (q) => !p.native_request_id || q.native_request_id === p.native_request_id,
      ),
      next_cursor: null,
    }),
  };
  bridge.fleetReads = {
    inventory: async (_o, p) => {
      calls.push(p);
      if (outage && p.host === "a") throw Error("secret source detail");
      return { threads: inventory[p.host], next_cursor: null };
    },
    read: async (_o, p) => {
      if (readFail) throw Error("read failed");
      return { ...structuredClone(data), thread: { ...data.thread, threadId: p.thread_id } };
    },
  };
  const p = {
    name: "t3.fleet.activity",
    arguments: { scope: "authorized_fleet" },
    ttlMs: null,
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/fleet",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  };
  return {
    bridge,
    store,
    policy,
    inventory,
    data,
    calls,
    questions,
    p,
    posts,
    grant,
    outage: (v) => (outage = v),
    revoke: (v) => (revoked = v),
    readFail: (v) => (readFail = v),
    advance: (ms) => (now += ms),
  };
}

test("visibility diagnostics preserve timeout reasons, scan age, grant expiry and webhook event correlation", async (t) => {
  const f = fixture(t);
  f.grant.expiresAt = Date.parse("2026-11-19T00:00:00Z");
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.fleetEvents.observe();
  await f.bridge.deliver();
  let status = f.bridge.fleetEvents.status("eddie");
  const a = status.subscriptions[0].hosts.find((h) => h.host === "a");
  assert.equal(a.command_grant_expires_at, "2026-11-19T00:00:00.000Z");
  assert.equal(a.last_complete_age_ms, 0);
  assert.equal(a.monitoring_requires_live_command_grant, true);
  const delivery = f.store.diagnostics("a").find((r) => r.stage === "webhook");
  assert.equal(delivery.delivery_state, "acknowledged");
  assert.equal(delivery.http_status, 200);
  assert.match(delivery.event_id, /^evt_/);
  f.bridge.fleetReads.inventory = async () => {
    throw Object.assign(Error("PRIVATE"), { reason: "source_timeout" });
  };
  f.advance(1000);
  await f.bridge.fleetEvents.observe();
  status = f.bridge.fleetEvents.status("eddie");
  const down = status.subscriptions[0].hosts.find((h) => h.host === "a");
  assert.equal(down.reason, "source_timeout");
  assert.equal(down.last_complete_age_ms, 1000);
  assert.equal(JSON.stringify(status).includes("PRIVATE"), false);
  assert.equal(f.store.all("command").length, 0);
});
test("one durable subscription covers existing and new threads; refresh/restart deduplicate without dispatch", async (t) => {
  const f = fixture(t),
    policy = JSON.stringify(f.policy),
    s = await f.bridge.subscribe("eddie", f.p);
  assert.equal(s.refreshBefore, null);
  await f.bridge.fleetEvents.observe();
  await f.bridge.deliver();
  assert.equal(f.posts.filter((e) => e.data?.kind === "task_finished").length, 1);
  f.advance(2 * 86400000);
  const resumed = new Bridge({ ...f.bridge });
  resumed.commands = f.bridge.commands;
  resumed.fleetReads = f.bridge.fleetReads;
  assert.equal((await resumed.subscribe("eddie", { ...f.p, ttlMs: undefined })).id, s.id);
  await resumed.fleetEvents.observe();
  await resumed.deliver();
  assert.equal(f.posts.filter((e) => e.data?.kind === "task_finished").length, 1);
  f.inventory.a.push({ ...f.inventory.a[0], threadId: "new" });
  await resumed.fleetEvents.observe();
  await resumed.deliver();
  assert.equal(f.posts.filter((e) => e.data?.kind === "task_finished").length, 2);
  assert.equal(f.store.all("subscription").length, 1);
  assert.equal(f.store.all("command").length, 0);
  assert.equal(JSON.stringify(f.policy), policy);
});
test("scope, provider, project and owner are enforced at observation and delivery", async (t) => {
  const f = fixture(t);
  await assert.rejects(f.bridge.subscribe("other", f.p), /forbidden/);
  await f.bridge.subscribe("eddie", f.p);
  f.inventory.a.push(
    { ...f.inventory.a[0], threadId: "forbidden-provider", providerInstanceId: "codex" },
    { ...f.inventory.a[0], threadId: "forbidden-project", projectId: "private" },
  );
  await f.bridge.fleetEvents.observe();
  assert.equal(
    f.store.all("delivery").filter((d) => d.event.data.kind === "task_finished").length,
    1,
  );
  f.revoke(true);
  await f.bridge.deliver();
  assert.equal(f.posts.filter((e) => e.data).length, 0);
  assert.ok(f.store.all("delivery").every((d) => d.status === "revoked"));
});
test("outages retain checkpoint, expose sanitized coverage and recover independently by host", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  f.outage(true);
  await f.bridge.fleetEvents.observe();
  let status = f.bridge.fleetEvents.status("eddie");
  assert.equal(status.subscriptions[0].hosts.find((h) => h.host === "a").state, "unavailable");
  assert.equal(status.subscriptions[0].hosts.find((h) => h.host === "b").state, "available");
  assert.doesNotMatch(JSON.stringify(status), /secret source detail/);
  f.outage(false);
  await f.bridge.fleetEvents.observe();
  status = f.bridge.fleetEvents.status("eddie");
  assert.equal(status.subscriptions[0].hosts[0].state, "available");
  assert.ok(
    f.store
      .all("delivery")
      .some(
        (d) => d.event.data.kind === "coverage_changed" && d.event.data.state === "unavailable",
      ),
  );
});
test("empty inventory pages advance persisted cursor and a failed thread page retries idempotently", async (t) => {
  const f = fixture(t);
  let page = 0;
  const calls = [];
  f.bridge.fleetReads.inventory = async (_o, p) => {
    calls.push(p);
    return p.host === "a"
      ? page++ === 0
        ? { threads: [], next_cursor: "next" }
        : { threads: f.inventory.a, next_cursor: null }
      : { threads: [], next_cursor: null };
  };
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.fleetEvents.observe();
  f.readFail(true);
  await f.bridge.fleetEvents.observe();
  f.readFail(false);
  await f.bridge.fleetEvents.observe();
  assert.equal(calls.filter((p) => p.host === "a")[2].cursor, "next");
  assert.equal(
    f.store.all("delivery").filter((d) => d.event.data.kind === "task_finished").length,
    1,
  );
  assert.ok(calls.every((p) => ["a", "b"].includes(p.host)));
});
test("native pending questions use exact request identity; resolved questions are revoked before webhook", async (t) => {
  const f = fixture(t);
  f.data.thread.pendingRequestCount = 1;
  f.questions.push({ native_request_id: "q", run_id: "r", live_answer_allowed: false });
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.fleetEvents.observe();
  await f.bridge.fleetEvents.observe();
  const q = f.store.all("delivery").filter((d) => d.event.data.kind === "input_requested");
  assert.equal(q.length, 1);
  assert.equal(q[0].event.data.native_request_id, "q");
  f.questions.length = 0;
  await f.bridge.deliver();
  assert.equal(f.store.get("delivery", q[0].id).status, "revoked");
});
test("unsubscribe, grant/provider change during reads and transient delivery failure never bypass checks", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.fleetEvents.observe();
  f.readFail(true);
  await f.bridge.deliver();
  assert.equal(f.posts.filter((e) => e.data?.kind === "task_finished").length, 0);
  const d = f.store.all("delivery").find((d) => d.event.data.kind === "task_finished");
  assert.equal(d.status, "pending");
  f.readFail(false);
  f.grant.providerInstanceIds = [];
  f.advance(30001);
  await f.bridge.deliver();
  assert.equal(f.store.get("delivery", d.id).status, "revoked");
  f.grant.providerInstanceIds = ["opencode"];
  f.bridge.unsubscribe("eddie", f.p);
  assert.equal(f.bridge.fleetEvents.status("eddie").subscriptions.length, 0);
});
test("stable webhook IDs survive duplicate retries and bootstrap history is excluded", async (t) => {
  const f = fixture(t);
  f.data.runs.push({ runId: "old", status: "completed", completedAt: "2026-10-26T00:00:00Z" });
  await f.bridge.subscribe("eddie", f.p);
  await f.bridge.fleetEvents.observe();
  let fail = true;
  const sent = [];
  f.bridge.post = async (_u, _h, body) => {
    sent.push(JSON.parse(body));
    return { status: fail ? 503 : 200 };
  };
  await f.bridge.deliver();
  f.advance(5000);
  fail = false;
  await f.bridge.deliver();
  const events = sent.filter((e) => e.data.kind === "task_finished");
  assert.equal(events.length, 2);
  assert.equal(events[0].eventId, events[1].eventId);
  assert.equal(events[0].data.run_id, "r");
});
test("aggregate admission respects eight active slots during concurrent verification and inactive refresh", async (t) => {
  const f = fixture(t),
    p = (i) => ({
      ...f.p,
      delivery: { ...f.p.delivery, url: "https://callbacks.example.com/fleet" + i },
    });
  for (let i = 0; i < 7; i++) await f.bridge.subscribe("eddie", p(i));
  const results = await Promise.allSettled([
    f.bridge.subscribe("eddie", p(7)),
    f.bridge.subscribe("eddie", p(8)),
  ]);
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(f.bridge.fleetEvents.active("eddie").length, 8);
  await f.bridge.subscribe("eddie", p(0));
  f.bridge.unsubscribe("eddie", p(0));
  await f.bridge.subscribe("eddie", p(9));
  await assert.rejects(f.bridge.subscribe("eddie", p(0)), /subscription_limit/);
});
