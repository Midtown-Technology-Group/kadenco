// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { boundedResponseText, fetchWithReadDeadline } from "../dist/http-limits.mjs";
import { httpServer } from "../dist/server.mjs";
import { resolveCallback, postWebhook, sendWhenSecure } from "../dist/webhook.mjs";
import { createServer } from "node:http";
import { T3FleetTransport } from "../dist/fleet-transport-read.mjs";
import { listenLoopback } from "./support/listen.mjs";

test("read fetch wrapper preserves a caller cleanup signal and only supplies a missing deadline", async () => {
  const signal = AbortSignal.abort();
  const seen = [];
  const fake = async (url, options) => {
    seen.push({ url, options });
    return 42;
  };
  assert.equal(
    await fetchWithReadDeadline("http://127.0.0.1/", { method: "DELETE", signal }, fake),
    42,
  );
  assert.equal(seen[0].options.signal, signal);
  assert.equal(seen[0].options.signal.aborted, true);
  assert.equal(seen[0].options.method, "DELETE");
  await fetchWithReadDeadline("http://127.0.0.1/", {}, fake);
  assert.ok(seen[1].options.signal instanceof AbortSignal);
});

test("native response body aborts retain timeout classification and size caps retain protocol errors", async () => {
  for (const kind of ["AbortError", "TimeoutError", "oversize"]) {
    const transport = new T3FleetTransport({
      hostsProvider: () => ({ hosts: [{ name: "local", url: "http://127.0.0.1:1234/mcp" }] }),
      cacheProvider: () => ({
        "local|mcp-client|fixture": {
          host: "local",
          base: "http://127.0.0.1:1234",
          token: "synthetic",
          scopes: ["orchestration:read"],
          expiresAt: Date.now() + 600000,
        },
      }),
      fetchImpl: async () =>
        kind === "oversize"
          ? new Response("x".repeat(2 * 1024 * 1024 + 1))
          : new Response(
              new ReadableStream({
                start(c) {
                  c.error(new DOMException("PRIVATE response body", kind));
                },
              }),
            ),
    });
    await assert.rejects(
      transport.connect("local"),
      (error) =>
        error.reason === (kind === "oversize" ? "source_protocol_error" : "source_timeout") &&
        !error.message.includes("PRIVATE"),
    );
    await transport.close();
  }
});

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
  await listenLoopback(sink);
  const server = createServer((_req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${sink.address().port}/leak` });
    res.end();
  });
  await listenLoopback(server);
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

test("webhook effect guard runs after DNS and before any request is sent", async () => {
  const calls = [];
  await assert.rejects(
    postWebhook(
      "https://callbacks.example.com/hook",
      {},
      "{}",
      ["callbacks.example.com"],
      async () => {
        calls.push("dns");
        return [{ address: "93.184.216.34", family: 4 }];
      },
      () => {
        calls.push("guard");
        throw Error("edge_lease_unavailable");
      },
    ),
    /edge_lease_unavailable/,
  );
  assert.deepEqual(calls, ["dns", "guard"]);
});

test("the webhook body is queued only after TLS connects and the guard passes again", async () => {
  const { EventEmitter } = await import("node:events");
  const run = (allowed) => {
    const socket = Object.assign(new EventEmitter(), { encrypted: true, connecting: true });
    const req = Object.assign(new EventEmitter(), {
      ended: undefined,
      destroyed: undefined,
      end(body) {
        this.ended = body;
      },
      destroy(error) {
        this.destroyed = error;
      },
    });
    let refused;
    sendWhenSecure(
      req,
      "signed-body",
      () => {
        if (!allowed()) throw Error("edge_lease_unavailable");
      },
      (e) => (refused = e),
    );
    req.emit("socket", socket);
    return { req, socket, refused: () => refused };
  };
  let ok = true;
  const sent = run(() => ok);
  assert.equal(sent.req.ended, undefined, "nothing queued before TLS is up");
  sent.socket.emit("secureConnect");
  assert.equal(sent.req.ended, "signed-body");
  // Lease lost during the handshake: nothing is ever queued.
  const lost = run(() => ok);
  ok = false;
  lost.socket.emit("secureConnect");
  assert.equal(lost.req.ended, undefined);
  assert.match(String(lost.req.destroyed), /edge_lease_unavailable/);
  assert.match(String(lost.refused()), /edge_lease_unavailable/);
});
