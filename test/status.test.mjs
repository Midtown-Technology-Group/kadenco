// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { Store } from "../dist/store.mjs";
import { Bridge } from "../dist/bridge.mjs";
import { FleetReader } from "../dist/fleet-read.mjs";
import { httpServer } from "../dist/server.mjs";
import {
  statusReport,
  JOURNEY_FRESH_MS,
  JOURNEY_STUCK_MS,
  STATUS_CACHE_MS,
} from "../dist/status.mjs";

const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-status-")),
    store = new Store(join(dir, "bridge.db"), randomBytes(32));
  let now = Date.now(),
    code = 204;
  const tokens = Object.fromEntries(
    ["eddie", "other", "caller"].map((id) => [id, randomBytes(32).toString("base64")]),
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
          expiresAt: now + 30 * 86400000,
          maxPerDay: 10,
        },
      },
    ],
  };
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
        readThread: async ({ threadId }) => ({
          thread: { threadId, projectId: "p", activeRunId: "run-a" },
          recentRuns: [{ runId: "run-a", status: "running" }],
          items: [],
          hasMore: false,
          nextPosition: null,
        }),
      }),
      close: async () => {},
    }),
  });
  bridge.fleetReads = reader;
  const subscription = {
    name: "t3.eddie.requested",
    arguments: { inbox_id: "eddie" },
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/event",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  };
  t.after(async () => {
    await reader.close();
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  // One complete ask -> deliver -> read -> reply -> acknowledge round trip.
  const roundTrip = async () => {
    const request_id = randomUUID();
    await bridge.exchanges.ask("caller", {
      request_id,
      run_id: "run-a",
      question: "status journey?",
      ttl_ms: 3600000,
    });
    await bridge.deliver();
    await bridge.exchanges.get("eddie", { request_id }, { reviewer: true });
    const replied = await bridge.exchanges.reply("eddie", { request_id, reply: "OK" });
    await bridge.exchanges.acknowledge("caller", {
      request_id,
      run_id: "run-a",
      reply_sha256: replied.reply_sha256,
    });
    return request_id;
  };
  return {
    bridge,
    store,
    tokens,
    subscription,
    roundTrip,
    advance: (ms) => {
      now += ms;
    },
    code: (n) => {
      code = n;
    },
  };
}

test("fresh install reports build identity, standalone runtime and unverified journeys", (t) => {
  const f = fixture(t);
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.schema, 1);
  assert.equal(s.build.package_version, pkg.version);
  assert.equal(s.build.protocol_version, "0.11.0");
  assert.deepEqual(s.runtime, { mode: "standalone", lease: { state: "not_applicable" } });
  assert.equal(s.overall, "unverified");
  assert.equal(s.journeys.ask_eddie.state, "unverified");
  assert.equal(s.journeys.event_delivery.state, "unverified");
  assert.deepEqual(
    s.hosts.map((h) => [h.host, h.last_outcome]),
    [["local", "unknown"]],
  );
});

test("a completed round trip verifies both journeys, then goes stale without new evidence", async (t) => {
  const f = fixture(t);
  // Non-expiring: an expired subscription stops contributing evidence at all.
  await f.bridge.subscribe("eddie", { ...f.subscription, ttlMs: null });
  const id = await f.roundTrip();
  let s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "verified");
  assert.equal(s.journeys.ask_eddie.last_verified.request_id, id);
  assert.equal(s.journeys.ask_eddie.latest.stage_reached, "acknowledged");
  assert.equal(s.journeys.event_delivery.state, "verified");
  assert.equal(s.overall, "ok");
  // Thread callers never see aggregate status; another inbox sees none of this one's.
  assert.equal(statusReport(f.bridge, "caller"), undefined);
  assert.equal(statusReport(f.bridge, "other").journeys.ask_eddie.state, "unverified");
  assert.equal(s.journeys.ask_eddie.last_verified.wake_delivered, true);
  f.advance(JOURNEY_FRESH_MS + 1000);
  s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "stale");
  assert.equal(s.journeys.event_delivery.state, "stale");
  assert.equal(s.overall, "unverified");
});

test("an unanswered request past the stuck window reports failing at the stage reached", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  await f.roundTrip();
  f.advance(1000);
  f.code(503);
  await f.bridge.exchanges.ask("caller", {
    request_id: randomUUID(),
    run_id: "run-a",
    question: "will this be answered?",
    ttl_ms: 3600000,
  });
  await f.bridge.deliver();
  f.advance(JOURNEY_STUCK_MS + 1000);
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "failing");
  assert.equal(s.journeys.ask_eddie.latest.stage_reached, "asked");
  assert.equal(s.journeys.event_delivery.state, "failing");
  assert.match(s.journeys.event_delivery.last_failure.outcome, /^pending:503$/);
  assert.equal(s.overall, "degraded");
});

test("runtime lease evidence drives overall state and local-cache authority", (t) => {
  const f = fixture(t);
  const lease = (state) => () => ({
    mode: "central_edge",
    lease: {
      state,
      generation: 3,
      last_renewed_at: null,
      expires_at: null,
      last_failure: { reason: "fenced", at: new Date().toISOString() },
    },
  });
  f.bridge.runtimeStatus = lease("lost");
  let s = statusReport(f.bridge, "eddie");
  assert.equal(s.overall, "down");
  assert.equal(s.state_authority, "local_cache_without_lease");
  f.bridge.runtimeStatus = lease("renewal_failing");
  assert.equal(statusReport(f.bridge, "eddie").overall, "degraded");
  f.bridge.runtimeStatus = lease("held");
  s = statusReport(f.bridge, "eddie");
  assert.equal(s.state_authority, "local");
  assert.equal(s.overall, "unverified");
});

test("GET /status requires an owner bearer and never caches", async (t) => {
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const url = `http://127.0.0.1:${server.address().port}/status`;
  assert.equal((await fetch(url)).status, 401);
  assert.equal(
    (
      await fetch(url, {
        headers: { authorization: "Bearer " + randomBytes(32).toString("base64") },
      })
    ).status,
    401,
  );
  const caller = await fetch(url, { headers: { authorization: "Bearer " + f.tokens.caller } });
  assert.equal(caller.status, 403);
  assert.deepEqual(await caller.json(), { reason: "operator_status_only" });
  const ok = await fetch(url, { headers: { authorization: "Bearer " + f.tokens.eddie } });
  assert.equal(ok.status, 200);
  assert.equal(ok.headers.get("cache-control"), "no-store");
  const body = await ok.json();
  assert.equal(body.build.package_version, pkg.version);
  assert.equal(body.overall, "unverified");
  assert.equal((await fetch(url, { method: "POST" })).status, 404);
});

test("status-check script reports the summary and exit code for an installed listener", async (t) => {
  const { spawn } = await import("node:child_process");
  const f = fixture(t),
    server = httpServer(f.bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const url = `http://127.0.0.1:${server.address().port}/status`;
  const run = (token, input) =>
    new Promise((resolve) => {
      // Async spawn: the in-process listener must keep serving while it runs.
      const child = spawn(process.execPath, ["scripts/status-check.mjs"], {
        env: { ...process.env, KADENCO_STATUS_URL: url, KADENCO_STATUS_TOKEN: token ?? "" },
        windowsHide: true,
      });
      let stdout = "";
      child.stdout.on("data", (c) => (stdout += c));
      child.stdin.end(input ?? "");
      child.on("close", (status) => resolve({ status, stdout }));
    });
  let r = await run(f.tokens.eddie);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /^overall\s+unverified/m);
  assert.match(r.stdout, /ask_eddie\s+unverified/);
  assert.equal((await run(randomBytes(32).toString("base64"))).status, 2);
  // Bearer on stdin when the environment variable is unset.
  await f.bridge.subscribe("eddie", f.subscription);
  await f.roundTrip();
  f.advance(STATUS_CACHE_MS);
  r = await run(undefined, f.tokens.eddie + "\n");
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^overall\s+ok/m);
});

test("an older stuck request stays failing after newer requests arrive", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  await f.roundTrip();
  f.advance(1000);
  const ask = (question) =>
    f.bridge.exchanges.ask("caller", {
      request_id: randomUUID(),
      run_id: "run-a",
      question,
      ttl_ms: 3600000,
    });
  await ask("A: never answered");
  f.advance(JOURNEY_STUCK_MS + 1000);
  await ask("B: just asked");
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "failing");
  assert.equal(s.journeys.ask_eddie.latest.stage_reached, "asked");
  // A completion acknowledged after A was asked clears it.
  await f.roundTrip();
  f.advance(STATUS_CACHE_MS);
  assert.equal(statusReport(f.bridge, "eddie").journeys.ask_eddie.state, "verified");
});

test("last verified is the newest acknowledgement, not the newest question", async (t) => {
  const f = fixture(t);
  const first = randomUUID(),
    second = randomUUID();
  for (const request_id of [first, second])
    await f.bridge.exchanges.ask("caller", {
      request_id,
      run_id: "run-a",
      question: request_id,
      ttl_ms: 3600000,
    });
  const finish = async (request_id) => {
    await f.bridge.exchanges.get("eddie", { request_id }, { reviewer: true });
    const r = await f.bridge.exchanges.reply("eddie", { request_id, reply: "OK" });
    await f.bridge.exchanges.acknowledge("caller", {
      request_id,
      run_id: "run-a",
      reply_sha256: r.reply_sha256,
    });
  };
  await finish(second);
  f.advance(1000);
  await finish(first);
  assert.equal(statusReport(f.bridge, "eddie").journeys.ask_eddie.last_verified.request_id, first);
});

test("central receipts count at their central result time; untimed ones are never fresh", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  await f.bridge.exchanges.ask("caller", {
    request_id: randomUUID(),
    run_id: "run-a",
    question: "central",
    ttl_ms: 3600000,
  });
  const [delivery] = f.store.all("delivery");
  // Central edge: the local record is centralized, then a receipt reconciles it.
  f.store.put("delivery", delivery.id, { ...delivery, status: "centralized", central_id: "c1" });
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.pending, 1);
  f.advance(STATUS_CACHE_MS);
  const now = f.bridge.now();
  // Reconciled now, but the delivery itself happened two days ago: stale, not fresh.
  f.store.put("delivery", delivery.id, {
    ...delivery,
    status: "acknowledged",
    central_id: "c1",
    httpStatus: 204,
    centralResultAt: now - 2 * 86400000,
  });
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "stale");
  f.advance(STATUS_CACHE_MS);
  f.store.put("delivery", delivery.id, {
    ...delivery,
    status: "acknowledged",
    central_id: "c1",
    httpStatus: 204,
    centralResultAt: null,
  });
  let s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.event_delivery.state, "unverified");
  assert.equal(s.journeys.event_delivery.untimed_central_receipts, 1);
  f.advance(STATUS_CACHE_MS);
  f.store.put("delivery", delivery.id, {
    ...delivery,
    status: "acknowledged",
    central_id: "c1",
    httpStatus: 204,
    centralResultAt: f.bridge.now() - 1000,
  });
  s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.event_delivery.state, "verified");
});

test("other owners' local delivery history cannot crowd out this owner's evidence", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  await f.bridge.exchanges.ask("caller", {
    request_id: randomUUID(),
    run_id: "run-a",
    question: "local",
    ttl_ms: 3600000,
  });
  await f.bridge.deliver();
  // 6000 newer outcomes for someone else's deliveries must not hide ours.
  f.store.transaction(() => {
    for (let i = 0; i < 6000; i++) f.store.audit("webhook.delivery", `foreign:${i}`, "stopped:500");
  });
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.event_delivery.state, "verified");
  assert.equal(s.journeys.event_delivery.last_failure, null);
});

test("status-check exits 2 when a 200 response body is incomplete or invalid", async (t) => {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"overall":');
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const status = await new Promise((resolve) => {
    const child = spawn(process.execPath, ["scripts/status-check.mjs"], {
      env: {
        ...process.env,
        KADENCO_STATUS_URL: `http://127.0.0.1:${server.address().port}/status`,
        KADENCO_STATUS_TOKEN: "fixture",
      },
      windowsHide: true,
    });
    child.stdin.end();
    child.on("close", resolve);
  });
  assert.equal(status, 2);
});

test("an exchange Eddie found by polling verifies the loop but not the wake delivery", async (t) => {
  const f = fixture(t);
  const request_id = randomUUID();
  await f.bridge.exchanges.ask("caller", {
    request_id,
    run_id: "run-a",
    question: "polled",
    ttl_ms: 3600000,
  });
  await f.bridge.exchanges.get("eddie", { request_id }, { reviewer: true });
  const r = await f.bridge.exchanges.reply("eddie", { request_id, reply: "OK" });
  await f.bridge.exchanges.acknowledge("caller", {
    request_id,
    run_id: "run-a",
    reply_sha256: r.reply_sha256,
  });
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "verified");
  assert.equal(s.journeys.ask_eddie.last_verified.wake_delivered, false);
  assert.equal(s.journeys.event_delivery.state, "unverified");
  assert.equal(s.overall, "unverified");
});

test("revoked inbox scope and inactive subscriptions stop contributing evidence", async (t) => {
  const f = fixture(t);
  const sub = await f.bridge.subscribe("eddie", f.subscription);
  await f.roundTrip();
  f.bridge.unsubscribe("eddie", {
    ...f.subscription,
    delivery: { mode: "webhook", url: f.subscription.delivery.url },
  });
  f.advance(STATUS_CACHE_MS);
  assert.ok(sub);
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "unverified");
  const eddie = f.bridge.policy().principals.find((p) => p.id === "eddie");
  eddie.eddieInbox = false;
  f.advance(STATUS_CACHE_MS);
  assert.equal(statusReport(f.bridge, "eddie").journeys.ask_eddie.state, "unverified");
});

test("polls inside the cache window reuse store evidence but always report current lease", async (t) => {
  const f = fixture(t);
  let lease = "held";
  f.bridge.runtimeStatus = () => ({
    mode: "central_edge",
    lease: {
      state: lease,
      generation: 1,
      last_renewed_at: null,
      expires_at: null,
      last_failure: null,
    },
  });
  // Same scope (grants and active subscriptions) across both polls.
  await f.bridge.subscribe("eddie", f.subscription);
  const first = statusReport(f.bridge, "eddie");
  await f.roundTrip();
  lease = "lost";
  const second = statusReport(f.bridge, "eddie");
  assert.equal(second.evidence_observed_at, first.evidence_observed_at);
  assert.equal(second.journeys.ask_eddie.state, "unverified", "cached evidence");
  assert.equal(second.overall, "down", "lease is never cached");
  f.advance(STATUS_CACHE_MS);
  lease = "held";
  assert.equal(statusReport(f.bridge, "eddie").journeys.ask_eddie.state, "verified");
});

test("status-check exits 2 for a 200 body that is not a status report", async (t) => {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"overall":"ok"}');
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const status = await new Promise((resolve) => {
    const child = spawn(process.execPath, ["scripts/status-check.mjs"], {
      env: {
        ...process.env,
        KADENCO_STATUS_URL: `http://127.0.0.1:${server.address().port}/status`,
        KADENCO_STATUS_TOKEN: "fixture",
      },
      windowsHide: true,
    });
    child.stdin.end();
    child.on("close", resolve);
  });
  assert.equal(status, 2);
});

test("a later stuck delivery is not hidden by an earlier success", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  const [sub] = f.store.all("subscription");
  const base = f.bridge.now();
  const put = (id, status, ts, extra = {}) =>
    f.store.put("delivery", id, {
      id,
      subId: sub.id,
      status,
      event: { name: "t3.eddie.requested", timestamp: new Date(ts).toISOString(), data: {} },
      ...extra,
    });
  put("A", "pending", base);
  put("B", "acknowledged", base + 1000, {
    central_id: "cB",
    httpStatus: 204,
    centralResultAt: base + 2000,
  });
  put("C", "pending", base + 3000);
  f.advance(JOURNEY_STUCK_MS + 10000);
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
});

test("equal acknowledgement times pick the later conversation round, then a stable id", async (t) => {
  const f = fixture(t);
  const at = f.bridge.now();
  const rec = (request_id, sequence) => ({
    request_id,
    conversation_id: "conv",
    sequence,
    reviewer: "eddie",
    caller: "caller",
    createdAt: at,
    expiresAt: at + 3600000,
    readAt: at,
    repliedAt: at,
    reply: "ok",
    acknowledgedAt: at,
  });
  f.store.put("exchange", "b-first", rec("b-first", 1));
  f.store.put("exchange", "a-second", rec("a-second", 2));
  assert.equal(
    statusReport(f.bridge, "eddie").journeys.ask_eddie.last_verified.request_id,
    "a-second",
  );
});

test("revoked grants invalidate cached evidence immediately", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", { ...f.subscription, ttlMs: null });
  const id = await f.roundTrip();
  assert.equal(statusReport(f.bridge, "eddie").journeys.ask_eddie.last_verified.request_id, id);
  const eddie = f.bridge.policy().principals.find((p) => p.id === "eddie");
  eddie.eddieInbox = false;
  eddie.readHosts = [];
  // No time passes: the cache must not serve the revoked scope.
  const s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.last_verified, null);
  assert.deepEqual(s.hosts, []);
});

test("a stuck older request is reported as such, separate from the latest attempt", async (t) => {
  const f = fixture(t);
  const ask = (q) =>
    f.bridge.exchanges.ask("caller", {
      request_id: randomUUID(),
      run_id: "run-a",
      question: q,
      ttl_ms: 3600000,
    });
  const old = await ask("old");
  f.advance(JOURNEY_STUCK_MS + 1000);
  const fresh = await ask("fresh");
  const j = statusReport(f.bridge, "eddie").journeys.ask_eddie;
  assert.equal(j.stuck.request_id, old.request_id);
  assert.equal(j.latest.request_id, fresh.request_id);
});

test("status-check exits 2 when a report contradicts itself or has malformed hosts", async (t) => {
  const { createServer } = await import("node:http");
  const { spawn } = await import("node:child_process");
  const ok = {
    schema: 1,
    overall: "ok",
    runtime: { mode: "central_edge", lease: { state: "lost" } },
    journeys: { ask_eddie: { state: "verified" }, event_delivery: { state: "verified" } },
    hosts: [],
  };
  let body;
  const server = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const run = () =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, ["scripts/status-check.mjs"], {
        env: {
          ...process.env,
          KADENCO_STATUS_URL: `http://127.0.0.1:${server.address().port}/status`,
          KADENCO_STATUS_TOKEN: "fixture",
        },
        windowsHide: true,
      });
      child.stdin.end();
      child.on("close", resolve);
    });
  body = ok; // "ok" with a lost lease
  assert.equal(await run(), 2);
  body = { ...ok, runtime: { mode: "central_edge", lease: { state: "held" } }, hosts: {} };
  assert.equal(await run(), 2);
  body = { ...ok, runtime: { mode: "central_edge", lease: { state: "not_applicable" } } };
  assert.equal(await run(), 2, "central edge cannot have a not-applicable lease");
  body = {
    ...ok,
    runtime: { mode: "central_edge", lease: { state: "held" } },
    build: { source_commit: 42 },
  };
  assert.equal(await run(), 2, "malformed build identity");
  body = { ...ok, runtime: { mode: "central_edge", lease: { state: "held" } } };
  assert.equal(await run(), 0);
});

test("a terminal delivery failure is not hidden by unrelated pending work", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  const [sub] = f.store.all("subscription");
  const base = f.bridge.now();
  const put = (id, status, ts, extra = {}) =>
    f.store.put("delivery", id, {
      id,
      subId: sub.id,
      status,
      event: { name: "t3.eddie.requested", timestamp: new Date(ts).toISOString(), data: {} },
      ...extra,
    });
  put("A", "acknowledged", base, { central_id: "cA", httpStatus: 204, centralResultAt: base });
  put("B", "stopped", base + 1000, {
    central_id: "cB",
    httpStatus: 410,
    centralResultAt: base + 2000,
  });
  put("C", "pending", base + 3000);
  f.advance(5000);
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
});

test("a later central failure in the same millisecond wins by central audit order", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  const [sub] = f.store.all("subscription");
  const at = f.bridge.now() - 1000;
  const put = (id, status, http, seq) =>
    f.store.put("delivery", id, {
      id,
      subId: sub.id,
      status,
      central_id: "c" + id,
      httpStatus: http,
      centralResultAt: at,
      centralResultSeq: seq,
      event: { name: "t3.eddie.requested", timestamp: new Date(at).toISOString(), data: {} },
    });
  put("ok", "acknowledged", 204, 10);
  put("bad", "stopped", 403, 11);
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
});

test("a success exactly at a pending attempt's start time counts as recovery", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  const [sub] = f.store.all("subscription");
  const at = f.bridge.now();
  f.store.put("delivery", "done", {
    id: "done",
    subId: sub.id,
    status: "acknowledged",
    central_id: "cdone",
    httpStatus: 204,
    centralResultAt: at,
    centralResultSeq: 1,
    event: { name: "t3.eddie.requested", timestamp: new Date(at).toISOString(), data: {} },
  });
  f.store.put("delivery", "waiting", {
    id: "waiting",
    subId: sub.id,
    status: "pending",
    event: { name: "t3.eddie.requested", timestamp: new Date(at).toISOString(), data: {} },
  });
  f.advance(JOURNEY_STUCK_MS + 1000);
  assert.notEqual(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
});

test("a later retryable failure cannot hide an earlier terminal one; a later ack recovers", async (t) => {
  const f = fixture(t);
  await f.bridge.subscribe("eddie", f.subscription);
  const [sub] = f.store.all("subscription");
  const base = f.bridge.now() - 60000;
  const central = (id, status, http, ms, seq) =>
    f.store.put("delivery", id, {
      id,
      subId: sub.id,
      status,
      central_id: "c" + id,
      httpStatus: http,
      centralResultAt: ms,
      centralResultSeq: seq,
      event: { name: "t3.eddie.requested", timestamp: new Date(ms).toISOString(), data: {} },
    });
  central("A", "acknowledged", 204, base, 1);
  central("B", "stopped", 410, base + 1000, 2);
  // C: still retrying locally after a 500 (pending, recent, not stuck).
  f.store.put("delivery", "C", {
    id: "C",
    subId: sub.id,
    status: "pending",
    event: { name: "t3.eddie.requested", timestamp: new Date(base + 2000).toISOString(), data: {} },
  });
  f.store.audit("webhook.delivery", "C", "pending:500");
  assert.equal(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
  f.advance(STATUS_CACHE_MS);
  central("D", "acknowledged", 204, f.bridge.now() - 1000, 3);
  assert.notEqual(statusReport(f.bridge, "eddie").journeys.event_delivery.state, "failing");
});
