// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { exitController } from "../packages/control-plane/operator/exit-controller.mjs";

const harness = (shutdown, timeoutMs = 50) => {
  const exits = [],
    reports = [];
  let zeroed = 0;
  const request = exitController({
    shutdown,
    zero: () => zeroed++,
    exit: (code) => exits.push(code),
    report: (v) => reports.push(v.event),
    timeoutMs,
  });
  return { request, exits, reports, zeroed: () => zeroed };
};

test("lease loss after a signal still exits 75, once, with the key zeroed", async () => {
  let release;
  const h = harness(() => new Promise((r) => (release = r)), 1000);
  const first = h.request(0);
  assert.equal(h.request(75), first, "one shared exit path");
  release();
  await first;
  assert.deepEqual(h.exits, [75]);
  assert.equal(h.zeroed(), 1);
});

test("a stalled shutdown is bounded by the deadline", async () => {
  const h = harness(() => new Promise(() => {}), 30);
  void h.request(75);
  await new Promise((r) => setTimeout(r, 80));
  assert.deepEqual(h.exits, [75]);
  assert.equal(h.zeroed(), 1);
  assert.deepEqual(h.reports, ["edge_shutdown_timeout"]);
});

test("a rejected shutdown is reported without its text and still zeroes and exits", async () => {
  const h = harness(async () => {
    throw Error("secret-bearing detail");
  });
  await h.request(75);
  assert.deepEqual(h.exits, [75]);
  assert.equal(h.zeroed(), 1);
  assert.deepEqual(h.reports, ["edge_shutdown_failed"]);
});

test("loss during startup waits for startup to settle and closes what it produced", async () => {
  let resolveStart;
  const starting = new Promise((r) => (resolveStart = r));
  let closed = 0;
  const exits = [];
  const request = (
    await import("../packages/control-plane/operator/exit-controller.mjs")
  ).exitController({
    shutdown: async () => {
      const started = await starting;
      await started?.shutdown();
    },
    zero: () => {},
    exit: (code) => exits.push(code),
    report: () => {},
    timeoutMs: 1000,
  });
  const done = request(75);
  assert.deepEqual(exits, [], "does not exit while startup is still unwinding");
  resolveStart({ shutdown: async () => closed++ });
  await done;
  assert.equal(closed, 1);
  assert.deepEqual(exits, [75]);
});
