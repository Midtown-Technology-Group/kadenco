// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash } from "node:crypto";
import { Store } from "../dist/store.mjs";
import {
  diagnosticContext,
  diagnosticRecord,
  diagnose,
  diagnoseWorkerCycle,
} from "../dist/diagnostics.mjs";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { T3FleetTransport } from "../dist/fleet-transport-read.mjs";
import { httpServer } from "../dist/server.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

test("concurrent origins stay isolated and errors/metadata cannot leak secrets", async () => {
  const rows = [];
  let release;
  const gate = new Promise((r) => (release = r));
  const error = Object.assign(Error("Bearer PRIVATE http://private?token=PRIVATE"), {
    reason: "source_unavailable",
    cause: { code: "ECONNREFUSED" },
    diagnosticMetadata: { http_status: 503, token: "PRIVATE", credential_source: "PRIVATE" },
  });
  const worker = diagnosticContext("worker", "event_cycle", () =>
    diagnose(
      (r) => rows.push(r),
      "a",
      "native_read",
      async () => {
        await gate;
        throw error;
      },
    ),
  );
  const checked = assert.rejects(worker, (e) => e === error);
  await diagnosticContext("mcp", "read_thread", () =>
    diagnose(
      (r) => rows.push(r),
      "a",
      "native_read",
      async () => 42,
      { native_operation: "readThread", token: "PRIVATE", url: "PRIVATE" },
    ),
  );
  release();
  await checked;
  assert.equal(rows[0].origin, "mcp");
  assert.equal(rows[1].origin, "worker");
  assert.notEqual(rows[0].correlation_id, rows[1].correlation_id);
  assert.equal(rows[1].transport_code, "ECONNREFUSED");
  assert.equal(rows[1].http_status, 503);
  assert.equal(JSON.stringify(rows).includes("PRIVATE"), false);
  assert.equal(
    await diagnose(
      () => {
        throw Error("storage failed");
      },
      "a",
      "host_read",
      async () => 7,
    ),
    7,
  );
  await assert.rejects(
    diagnose(
      () => {
        throw Error("storage failed");
      },
      "a",
      "host_read",
      async () => {
        throw error;
      },
    ),
    (e) => e === error,
  );
});

test("diagnostics are encrypted, bounded, exclude expired rows and paginate without exposing another host", (t) => {
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  store.diagnostic({
    ...diagnosticRecord("a", "host_read", Date.now()),
    at: "2000-01-01T00:00:00.000Z",
  });
  for (let i = 0; i < 25100; i++)
    store.diagnostic(diagnosticRecord(i % 2 ? "a" : "b", "host_read", Date.now()));
  assert.ok(store.db.prepare("SELECT COUNT(*) n FROM diagnostics").get().n <= 25127);
  const rows = store.diagnostics("a", 0, 10);
  assert.equal(rows.length, 11);
  assert.ok(rows.every((r) => r.host === "a"));
  const next = store.diagnostics("a", rows[9].sequence, 10);
  assert.equal(next[0].sequence, rows[10].sequence);
  assert.equal(store.db.prepare("SELECT COUNT(*) n FROM diagnostics WHERE at<'2001'").get().n, 0);
  assert.equal(
    store.db.prepare("SELECT value FROM diagnostics LIMIT 1").get().value.includes("host_read"),
    false,
  );
});

test("read transport identifies credential, initialization and native read failures without new credentials or writes", async () => {
  const rows = [];
  let status = 200,
    missing = false,
    network = false;
  const transport = new T3FleetTransport({
    diagnostic: (r) => rows.push(r),
    hostsProvider: () => ({ hosts: [{ name: "a", url: "http://127.0.0.1:1234/mcp" }] }),
    cacheProvider: () =>
      missing
        ? {}
        : {
            "a|mcp-client|cache": {
              host: "a",
              base: "http://127.0.0.1:1234",
              access: "read-only",
              token: "PRIVATE",
              scopes: ["orchestration:read"],
              expiresAt: Date.now() + 600000,
            },
          },
    fetchImpl: async (_url, opts) => {
      if (opts.method === "DELETE") return new Response(null, { status: 204 });
      if (network) throw Object.assign(Error("PRIVATE"), { cause: { code: "ECONNRESET" } });
      if (status !== 200) return new Response("PRIVATE", { status });
      const b = JSON.parse(opts.body);
      if (!b.id) return new Response(null, { status: 204 });
      const result =
        b.method === "initialize"
          ? { protocolVersion: "2025-06-18" }
          : b.method === "tools/list"
            ? { structuredContent: { tools: [{ name: "t3_project_list" }] } }
            : { structuredContent: { projects: [], nextCursor: null } };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: b.id, result }), {
        headers: { "content-type": "application/json" },
      });
    },
  });
  const handle = await transport.connect("a");
  await handle.listProjects({});
  status = 503;
  await assert.rejects(handle.listProjects({}));
  assert.equal(rows.at(-1).stage, "native_read");
  assert.equal(rows.at(-1).http_status, 503);
  status = 401;
  await assert.rejects(transport.connect("a"));
  assert.equal(rows.at(-1).reason, "authentication_required");
  assert.equal(rows.at(-1).stage, "mcp_initialize");
  status = 200;
  network = true;
  await assert.rejects(transport.connect("a"));
  assert.equal(rows.at(-1).transport_code, "ECONNRESET");
  network = false;
  missing = true;
  await assert.rejects(transport.connect("a"));
  assert.equal(rows.at(-1).stage, "credential");
  assert.equal(rows.at(-1).reason, "authentication_required");
  assert.ok(rows.some((r) => r.credential_expires_at && r.credential_source === "cache"));
  assert.equal(JSON.stringify(rows).includes("PRIVATE"), false);
  await transport.close();
});

test("MCP diagnostic reads require current host grant, paginate and never refresh credentials", async (t) => {
  const store = new Store(":memory:", randomBytes(32)),
    token = "test-only-token";
  t.after(() => store.close());
  let allowed = true,
    grantChecks = 0;
  const policy = {
    principals: [
      { id: "reader", tokenSha256: createHash("sha256").update(token).digest("hex"), sessions: [] },
    ],
    sessions: [],
  };
  const bridge = {
    store,
    policy: () => policy,
    sessions: () => [],
    fleetReads: {
      grant(owner, host) {
        grantChecks++;
        if (!allowed || owner !== "reader" || host !== "a")
          throw Object.assign(Error(), { reason: "forbidden" });
      },
    },
  };
  for (const host of ["a", "b", "a"])
    store.diagnostic(diagnosticRecord(host, "credential", Date.now()));
  const server = httpServer(bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const c = new Client(
    { name: "test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  t.after(async () => {
    await c.close();
    await new Promise((r) => server.close(r));
  });
  await c.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer " + token } },
    }),
  );
  assert.equal(
    (await c.listTools()).tools.find((x) => x.name === "get_visibility_diagnostics").annotations
      .readOnlyHint,
    true,
  );
  const call = (arguments_) =>
    c.callTool({ name: "get_visibility_diagnostics", arguments: arguments_ });
  const first = (await call({ host: "a", limit: 1 })).structuredContent;
  assert.equal(first.items.length, 1);
  assert.ok(first.next_cursor);
  assert.ok(grantChecks >= 2);
  const second = (await call({ host: "a", after_sequence: first.next_cursor })).structuredContent;
  assert.equal(second.items.length, 1);
  assert.equal(second.next_cursor, null);
  assert.equal((await call({ host: "b" })).isError, true);
  allowed = false;
  assert.equal((await call({ host: "a" })).isError, true);
  assert.equal(store.all("command").length, 0);
  assert.equal(store.all("subscription").length, 0);
});

test("SSH runtime discovery failures retain a safe transport code and exact failing stage", async () => {
  const rows = [];
  const transport = new T3FleetTransport({
    diagnostic: (r) => rows.push(r),
    hostsProvider: () => ({ hosts: [{ name: "a", ssh: "configured", localPort: 1234 }] }),
    cacheProvider: () => ({
      "a|mcp-client|cache": {
        host: "a",
        base: "http://127.0.0.1:1234",
        token: "PRIVATE",
        scopes: ["orchestration:read"],
        expiresAt: Date.now() + 600000,
      },
    }),
    execFileImpl: async () => {
      throw Object.assign(Error("PRIVATE command and stderr"), { code: "EHOSTUNREACH" });
    },
    spawnImpl: () => {
      assert.fail("Must not create a forward after failed discovery");
    },
    fetchImpl: () => {
      assert.fail("Must not send HTTP after failed discovery");
    },
  });
  await assert.rejects(transport.connect("a"));
  assert.equal(rows.at(-1).stage, "runtime_metadata");
  assert.equal(rows.at(-1).transport_code, "EHOSTUNREACH");
  assert.equal(JSON.stringify(rows).includes("PRIVATE"), false);
  await transport.close();
});

test("event loop telemetry accepts only finite nonnegative measurements", () => {
  const r = diagnosticRecord("relay", "worker", Date.now(), null, {
    event_loop_delay_max_ms: 4428.4,
    secret: "PRIVATE",
  });
  assert.equal(r.event_loop_delay_max_ms, 4428);
  assert.equal(JSON.stringify(r).includes("PRIVATE"), false);
  for (const value of [-1, Infinity, NaN, "PRIVATE"]) {
    assert.equal(
      diagnosticRecord("relay", "worker", Date.now(), null, { event_loop_delay_max_ms: value })
        .event_loop_delay_max_ms,
      undefined,
    );
  }
});

test("worker diagnostics sample a final synchronous stall on successful and failed cycles", async () => {
  const histogram = monitorEventLoopDelay({ resolution: 20 });
  histogram.enable();
  const rows = [];
  try {
    for (const failed of [false, true]) {
      await delay(50); // Prime the native sampler before a deliberate final-operation stall.
      const error = Error("PRIVATE");
      const work = diagnoseWorkerCycle(
        (r) => rows.push(r),
        histogram,
        async () => {
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 120);
          if (failed) throw error;
          return 42;
        },
      );
      if (failed) await assert.rejects(work, (e) => e === error);
      else assert.equal(await work, 42);
      assert.ok(rows.at(-1).event_loop_delay_max_ms >= 100, JSON.stringify(rows.at(-1)));
      assert.equal(rows.at(-1).outcome, failed ? "failed" : "ok");
      assert.equal(histogram.max, 0);
    }
    assert.equal(JSON.stringify(rows).includes("PRIVATE"), false);
  } finally {
    histogram.disable();
  }
});
