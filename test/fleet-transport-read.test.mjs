// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { T3FleetTransport } from "../src/fleet-transport-read.mjs";
import { EventEmitter } from "node:events";

test("inventory transport exposes only native read methods, reuses origin-bound credentials and gives MCP errors precedence", async () => {
  const calls = [];
  let fail = false;
  const transport = new T3FleetTransport({
    hostsProvider: () => ({ hosts: [{ name: "test", url: "http://127.0.0.1:1234/mcp" }] }),
    cacheProvider: () => ({
      "test|mcp-client|cached": {
        host: "test",
        base: "http://127.0.0.1:1234",
        access: "approval-required",
        token: "dummy",
        scopes: ["orchestration:read"],
        expiresAt: Date.now() + 600000,
      },
    }),
    fetchImpl: async (_url, opts) => {
      if (opts.method === "DELETE") return new Response(null, { status: 204 });
      const body = JSON.parse(opts.body);
      calls.push(body);
      if (!body.id) return new Response(null, { status: 204 });
      let result;
      if (body.method === "initialize") result = { protocolVersion: "2025-06-18" };
      else if (body.method === "tools/list")
        result = {
          structuredContent: {
            tools: ["t3_thread_search", "t3_thread_read", "t3_project_list", "t3_thread_list"].map(
              (name) => ({ name }),
            ),
          },
        };
      else
        result = fail
          ? { isError: true, structuredContent: { projects: [{ id: "NOT SUCCESS" }] } }
          : { structuredContent: { name: body.params.name, args: body.params.arguments } };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
        headers: { "content-type": "application/json" },
      });
    },
  });
  await assert.rejects(transport.connect("test", "operate"), /read-only/);
  assert.equal(calls.length, 0);
  const client = await transport.connect("test", "read");
  assert.equal(client.sendThreadMessage, undefined);
  assert.equal(client.readQueuedMessage, undefined);
  assert.equal((await client.listProjects({ cursor: 100 })).name, "t3_project_list");
  assert.equal((await client.listThreads({ projectId: "p", cursor: 100 })).args.cursor, 100);
  await client.searchThreads({ query: "x" });
  await client.readThread({ threadId: "t", itemId: "i", textOffset: 4000 });
  assert.ok(
    calls
      .filter((c) => c.method === "tools/call")
      .every((c) =>
        ["t3_project_list", "t3_thread_list", "t3_thread_search", "t3_thread_read"].includes(
          c.params.name,
        ),
      ),
  );
  fail = true;
  await assert.rejects(client.listProjects({}), /MCP isError/);
  await transport.close();
});

test("consecutive read pages reuse verified runtime ports, expire idle metadata and invalidate it on MCP failure", async () => {
  let now = Date.now(),
    metadataReads = 0,
    kills = 0,
    fail = false;
  const runtimePortCache = new Map(),
    base = "http://127.0.0.1:1234";
  const options = {
    runtimePortCache,
    now: () => now,
    hostsProvider: () => ({ hosts: [{ name: "test", ssh: "configured-alias", localPort: 1234 }] }),
    cacheProvider: () => ({
      "test|mcp-client|cached": {
        host: "test",
        base,
        token: "dummy",
        scopes: ["orchestration:read"],
        expiresAt: now + 600000,
      },
    }),
    execFileImpl: async () => {
      metadataReads++;
      return { stdout: JSON.stringify({ port: 2222 }) };
    },
    netImpl: {
      createServer: () => ({
        once() {},
        listen(_port, _host, cb) {
          cb();
        },
        close(cb) {
          cb();
        },
      }),
      createConnection: () => {
        const socket = new EventEmitter();
        socket.destroy = () => {};
        queueMicrotask(() => socket.emit("connect"));
        return socket;
      },
    },
    spawnImpl: () => {
      const child = new EventEmitter();
      child.kill = () => {
        kills++;
      };
      return child;
    },
    fetchImpl: async (_url, opts) => {
      if (opts.method === "DELETE") return new Response(null, { status: 204 });
      const body = JSON.parse(opts.body);
      if (!body.id) return new Response(null, { status: 204 });
      if (fail) return new Response("{}", { status: 503 });
      const result =
        body.method === "initialize"
          ? { protocolVersion: "2025-06-18" }
          : { structuredContent: { tools: [] } };
      return new Response(JSON.stringify({ id: body.id, result }), {
        headers: { "content-type": "application/json" },
      });
    },
  };
  async function connect() {
    const t = new T3FleetTransport(options);
    try {
      await t.connect("test", "read");
    } finally {
      await t.close();
    }
  }
  await connect();
  await connect();
  assert.equal(metadataReads, 1);
  assert.equal(kills, 2);
  assert.deepEqual(
    [...runtimePortCache.values()].map((v) => Object.keys(v).sort()),
    [["expiresAt", "port"]],
  );
  now += 60001;
  await connect();
  assert.equal(metadataReads, 2);
  fail = true;
  await assert.rejects(connect(), /HTTP 503/);
  assert.equal(runtimePortCache.size, 0);
  fail = false;
  await connect();
  assert.equal(metadataReads, 3);
  assert.equal(kills, 5);
});

test("native JSON-RPC/tool errors keep categorized read diagnostics and never surface arbitrary error text", async () => {
  for (const [reply, reason] of [
    [{ error: { code: -32603, message: "PRIVATE" } }, "source_internal_error"],
    [{ error: { code: -32602, message: "PRIVATE" } }, "invalid_source_request"],
    [
      {
        result: { isError: true, structuredContent: { code: "InternalError", message: "PRIVATE" } },
      },
      "source_internal_error",
    ],
    [
      {
        result: {
          isError: true,
          structuredContent: { code: "runtime_mode_escalation_denied", message: "PRIVATE" },
        },
      },
      "forbidden",
    ],
  ]) {
    const transport = new T3FleetTransport({
      hostsProvider: () => ({ hosts: [{ name: "test", url: "http://127.0.0.1:1234/mcp" }] }),
      cacheProvider: () => ({
        "test|mcp-client|x": {
          host: "test",
          base: "http://127.0.0.1:1234",
          token: "dummy",
          access: "approval-required",
          scopes: ["orchestration:read"],
          expiresAt: Date.now() + 600000,
        },
      }),
      fetchImpl: async (_u, opts) => {
        if (opts.method === "DELETE") return new Response(null, { status: 204 });
        const body = JSON.parse(opts.body);
        if (!body.id) return new Response(null, { status: 204 });
        const result =
          body.method === "initialize"
            ? { result: { protocolVersion: "2025-06-18" } }
            : body.method === "tools/list"
              ? { result: { structuredContent: { tools: [{ name: "t3_thread_read" }] } } }
              : reply;
        return new Response(JSON.stringify({ id: body.id, ...result }), {
          headers: { "content-type": "application/json" },
        });
      },
    });
    try {
      const c = await transport.connect("test", "read");
      await assert.rejects(c.readThread({ threadId: "t" }), (e) => {
        assert.equal(e.reason, reason);
        assert.equal(e.message.includes("PRIVATE"), false);
        return true;
      });
    } finally {
      await transport.close();
    }
  }
});
