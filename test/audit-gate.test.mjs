// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { evaluate, stale, expiryTime } from "../scripts/audit-gate.mjs";

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
  assert.deepEqual(f, ["production dependencies are vulnerable (GHSA-a)"]);
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

test("null or array vulnerability maps are unreadable, an empty map is valid", () => {
  for (const bad of [{ vulnerabilities: null }, { vulnerabilities: [] }, null, {}])
    assert.deepEqual(evaluate(report(["picomatch", "GHSA-a"]), bad, [exception], today), [
      "production audit report unreadable",
    ]);
  assert.deepEqual(evaluate(clean, clean, [exception], today), []);
});

test("any production finding fails, even without an extractable advisory id", () => {
  const prod = { vulnerabilities: { fdir: { via: ["picomatch"] } } };
  assert.deepEqual(evaluate(report(["picomatch", "GHSA-a"]), prod, [exception], today), [
    "production dependencies are vulnerable (fdir)",
  ]);
});

test("expiry must be a real YYYY-MM-DD calendar date", () => {
  assert.ok(Number.isFinite(expiryTime("2026-12-18")));
  for (const bad of ["2027-02-30", "2026-13-01", "next month", "2026-12-18T00:00:00Z", undefined])
    assert.ok(Number.isNaN(expiryTime(bad)), String(bad));
  const f = evaluate(
    report(["picomatch", "GHSA-a"]),
    clean,
    [{ ...exception, expires: "2027-02-30" }],
    today,
  );
  assert.match(f[0], /invalid expiry date/);
});

test("staleness is only decided when every report is readable", () => {
  assert.deepEqual(stale([exception], [clean, undefined]), [
    "cannot check exception staleness: audit report unreadable",
  ]);
});
