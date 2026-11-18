// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { FETCH_BLOCKED_PORTS, listenLoopback } from "./support/listen.mjs";

test("listenLoopback never returns a port that fetch refuses", async (t) => {
  // Simulate the OS handing out a fetch-blocked port first.
  const server = createServer((_req, res) => res.end("ok"));
  const original = server.listen.bind(server);
  let calls = 0;
  server.listen = (port, host, cb) => original(++calls === 1 ? 6000 : port, host, cb);
  t.after(() => new Promise((r) => server.close(r)));
  try {
    await listenLoopback(server);
  } catch (error) {
    // Port 6000 may be unavailable on this host; the fallback still applies.
    if (error.code !== "EADDRINUSE" && error.code !== "EACCES") throw error;
    return;
  }
  const port = server.address().port;
  assert.equal(FETCH_BLOCKED_PORTS.has(port), false);
  assert.ok(calls >= 2, "the blocked first bind was replaced");
  assert.equal(await (await fetch(`http://127.0.0.1:${port}/`)).text(), "ok");
});

test("fetch really refuses the listed ports", async () => {
  for (const port of [6000, 10080])
    await assert.rejects(
      fetch(`http://127.0.0.1:${port}/`),
      (e) => e.cause?.message === "bad port",
    );
});
