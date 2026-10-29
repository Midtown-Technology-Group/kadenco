// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { T3FleetTransport } from "../dist/fleet-transport-read.mjs";

function transportWithReply(reply, cleanup = () => new Response(null, { status: 204 })) {
  return new T3FleetTransport({
    now: () => 1000,
    hostsProvider: () => ({ hosts: [{ name: "local", url: "http://127.0.0.1:1234/mcp" }] }),
    cacheProvider: () => ({
      "local|mcp-client|fixture": {
        host: "local",
        base: "http://127.0.0.1:1234",
        token: "synthetic",
        scopes: ["orchestration:read"],
        expiresAt: 100000,
      },
    }),
    fetchImpl: async (_url, options) => {
      if (options.method === "DELETE") return cleanup();
      const body = JSON.parse(options.body);
      if (!body.id) return new Response(null, { status: 204 });
      if (body.method === "tools/call") return reply(body.id);
      const result =
        body.method === "initialize"
          ? { protocolVersion: "2025-06-18" }
          : { tools: [{ name: "t3_thread_read" }] };
      return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), {
        headers: { "mcp-session-id": "synthetic-session" },
      });
    },
  });
}

test("SSE read replies preserve data-line newlines instead of silently changing native values", async () => {
  for (const newline of ["\n", "\r\n", "\r"]) {
    const transport = transportWithReply(
      (id) =>
        new Response(
          `data: {"jsonrpc":"2.0","id":${id},"result":{"structuredContent":{"count":1${newline}data: 2}}}${newline}${newline}`,
          { headers: { "content-type": "text/event-stream" } },
        ),
    );
    try {
      const client = await transport.connect("local");
      await assert.rejects(
        client.readThread({ threadId: "synthetic" }),
        (error) => error.reason === "source_protocol_error",
      );
    } finally {
      await transport.close();
    }
  }
});

test("SSE read replies accept multiline JSON with LF, CRLF and CR event boundaries", async () => {
  for (const newline of ["\n", "\r\n", "\r"]) {
    const transport = transportWithReply(
      (id) =>
        new Response(
          `: heartbeat${newline}${newline}data: {"jsonrpc":"2.0","id":${id},${newline}data:${newline}data: "result":{"structuredContent":{"text":"synthetic"}}}${newline}${newline}`,
          { headers: { "content-type": "text/event-stream" } },
        ),
    );
    try {
      const client = await transport.connect("local");
      assert.deepEqual(await client.readThread({ threadId: "synthetic" }), { text: "synthetic" });
    } finally {
      await transport.close();
    }
  }
});

test("MCP session cleanup cancels ignored response bodies without waiting for body data", async () => {
  for (const status of [200, 500]) {
    let cancelled = 0;
    const transport = transportWithReply(
      () => new Response("{}"),
      () =>
        new Response(
          new ReadableStream({
            cancel() {
              cancelled++;
            },
          }),
          { status },
        ),
    );
    await transport.connect("local");
    await transport.close();
    assert.equal(cancelled, 1);
    await transport.close();
    assert.equal(cancelled, 1);
  }
});

test("MCP cleanup remains best effort when response cancellation fails", async () => {
  const transport = transportWithReply(
    () => new Response("{}"),
    () =>
      new Response(
        new ReadableStream({
          cancel() {
            throw new Error("synthetic cancellation failure");
          },
        }),
      ),
  );
  await transport.connect("local");
  await transport.close();
});
