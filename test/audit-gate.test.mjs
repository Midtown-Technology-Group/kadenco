// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, stale } from "../scripts/audit-gate.mjs";

const report = (...ids) => ({
  vulnerabilities: Object.fromEntries(
    ids.map(([pkg, id]) => [
      pkg,
      { via: [{ name: pkg, url: `https://github.com/advisories/${id}` }, "parent"] },
    ]),
  ),
});
const clean = { vulnerabilities: {} };
const exception = { advisory: "GHSA-a", package: "picomatch", expires: "2026-12-18" };
const today = new Date("2026-11-18T00:00:00Z");

test("only the listed, unexpired, dev-only advisory is accepted", () => {
  assert.deepEqual(evaluate(report(["picomatch", "GHSA-a"]), clean, [exception], today), []);
});

test("any other advisory fails", () => {
  const f = evaluate(
    report(["picomatch", "GHSA-a"], ["lodash", "GHSA-b"]),
    clean,
    [exception],
    today,
  );
  assert.deepEqual(f, ["unapproved advisory GHSA-b (lodash)"]);
});

test("an expired exception fails", () => {
  const f = evaluate(
    report(["picomatch", "GHSA-a"]),
    clean,
    [exception],
    new Date("2026-12-18T00:00:01Z"),
  );
  assert.match(f[0], /expired/);
});

test("a listed advisory reaching production dependencies fails", () => {
  const f = evaluate(
    report(["picomatch", "GHSA-a"]),
    report(["picomatch", "GHSA-a"]),
    [exception],
    today,
  );
  assert.deepEqual(f, ["advisory GHSA-a reaches production dependencies"]);
});

test("an exception naming a different package fails", () => {
  const f = evaluate(report(["minimatch", "GHSA-a"]), clean, [exception], today);
  assert.match(f[0], /names picomatch, found minimatch/);
});

test("unreadable reports fail closed", () => {
  assert.deepEqual(evaluate(undefined, clean, [exception], today), ["audit report unreadable"]);
  assert.deepEqual(evaluate(clean, undefined, [exception], today), [
    "production audit report unreadable",
  ]);
});

test("a stale exception (fixed upstream, no longer reported anywhere) fails", () => {
  assert.deepEqual(stale([exception], [clean, clean]), [
    "stale exception GHSA-a: no longer reported, remove it",
  ]);
  assert.deepEqual(stale([exception], [clean, report(["picomatch", "GHSA-a"])]), []);
});
