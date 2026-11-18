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
import { statusReport, JOURNEY_FRESH_MS, JOURNEY_STUCK_MS } from "../dist/status.mjs";

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
  await f.bridge.subscribe("eddie", f.subscription);
  const id = await f.roundTrip();
  let s = statusReport(f.bridge, "eddie");
  assert.equal(s.journeys.ask_eddie.state, "verified");
  assert.equal(s.journeys.ask_eddie.last_verified.request_id, id);
  assert.equal(s.journeys.ask_eddie.latest.stage_reached, "acknowledged");
  assert.equal(s.journeys.event_delivery.state, "verified");
  assert.equal(s.overall, "ok");
  // The asking caller sees the same exchange; an unrelated inbox owner does not.
  assert.equal(statusReport(f.bridge, "caller").journeys.ask_eddie.state, "verified");
  assert.equal(statusReport(f.bridge, "other").journeys.ask_eddie.state, "unverified");
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
  r = await run(undefined, f.tokens.eddie + "\n");
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^overall\s+ok/m);
});
