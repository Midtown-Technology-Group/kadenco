// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { boundedResponseText } from "../src/http-limits.mjs";
import { httpServer } from "../src/server.mjs";
import { resolveCallback, postWebhook } from "../src/webhook.mjs";
import { createServer } from "node:http";
import { T3FleetTransport } from "../src/fleet-transport-read.mjs";

test("native response cap counts bytes, rejects misleading/missing lengths and cancels oversize streams", async () => {
  assert.equal(await boundedResponseText(new Response("é"), 2), "é");
  await assert.rejects(
    boundedResponseText(new Response("é"), 1),
    (e) => e.reason === "source_protocol_error",
  );
  for (const headers of [{}, { "content-length": "1" }]) {
    let cancelled = false;
    const body = new ReadableStream({
      start(c) {
        c.enqueue(new Uint8Array(5));
      },
      cancel() {
        cancelled = true;
      },
    });
    await assert.rejects(
      boundedResponseText(new Response(body, { headers }), 4),
      /source_response_too_large/,
    );
    assert.equal(cancelled, true);
  }
  let cancelled = false;
  const body = new ReadableStream({
    cancel() {
      cancelled = true;
    },
  });
  await assert.rejects(
    boundedResponseText(new Response(body, { headers: { "content-length": "100" } }), 4),
    /source_response_too_large/,
  );
  assert.equal(cancelled, true);
});

test("DNS stalls are bounded, failures sanitized, and mixed public/private DNS answers fail closed", async () => {
  await assert.rejects(
    resolveCallback("example.test", () => new Promise(() => {}), 5),
    /callback_resolution_timeout/,
  );
  await assert.rejects(
    resolveCallback("example.test", async () => {
      throw Error("PRIVATE credentials");
    }),
    (e) => e.message === "callback_resolution_failed",
  );
  await assert.rejects(
    postWebhook("https://example.test", {}, "{}", ["example.test"], async () => [
      { address: "8.8.8.8", family: 4 },
      { address: "127.0.0.1", family: 4 },
    ]),
    /address_denied/,
  );
});

test("MCP listener enforces explicit header/body/keepalive lifecycle bounds", () => {
  const server = httpServer({});
  assert.equal(server.headersTimeout, 10000);
  assert.equal(server.requestTimeout, 30000);
  assert.equal(server.keepAliveTimeout, 5000);
  assert.equal(server.maxRequestsPerSocket, 100);
});

test("native HTTP redirects cannot leave the exact configured origin", async (t) => {
  let leaked = 0;
  const sink = createServer((_req, res) => {
    leaked++;
    res.end("{}");
  });
  await new Promise((r) => sink.listen(0, "127.0.0.1", r));
  const server = createServer((_req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${sink.address().port}/leak` });
    res.end();
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const transport = new T3FleetTransport({
    hostsProvider: () => ({ hosts: [{ name: "local", url: base + "/mcp" }] }),
    cacheProvider: () => ({
      "local|mcp-client|fixture": {
        host: "local",
        base,
        token: "synthetic-token",
        scopes: ["orchestration:read"],
        expiresAt: Date.now() + 600000,
      },
    }),
  });
  t.after(async () => {
    await transport.close();
    await Promise.all([server, sink].map((s) => new Promise((r) => s.close(r))));
  });
  await assert.rejects(transport.connect("local"));
  assert.equal(leaked, 0);
});
