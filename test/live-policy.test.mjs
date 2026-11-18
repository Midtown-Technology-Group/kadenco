// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, renameSync, rmSync } from "node:fs";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { livePolicy } from "../dist/sidecar.mjs";

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-policy-"));
  const state = join(dir, "state");
  mkdirSync(state);
  const path = join(dir, "policy.json");
  const write = (port, target = path) =>
    writeFileSync(
      target,
      JSON.stringify({
        port,
        stateDirectory: state,
        source: { type: "local-projection", databasePath: "unused" },
        callbackHosts: [],
        principals: [],
        sessions: [],
      }),
    );
  write(41001);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return { dir, path, write };
}

test("live policy sees every edit or replacement on the next read", (t) => {
  const f = fixture(t);
  const read = livePolicy(f.path);
  assert.equal(read().port, 41001);
  f.write(41002); // in-place edit, same size
  assert.equal(read().port, 41002);
  f.write(41003, join(f.dir, "next.json"));
  renameSync(join(f.dir, "next.json"), f.path); // atomic replacement
  assert.equal(read().port, 41003);
  writeFileSync(f.path, "{ not json");
  assert.throws(() => read());
  assert.throws(() => read(), "an invalid file keeps failing; no stale value is served");
  f.write(41004);
  assert.equal(read().port, 41004);
});

test("each read is an independent copy and the validate hook runs every time", (t) => {
  const f = fixture(t);
  let validated = 0;
  const read = livePolicy(f.path, () => validated++);
  const first = read();
  first.port = 1;
  first.principals.push({ id: "mutated" });
  const second = read();
  assert.equal(second.port, 41001);
  assert.deepEqual(second.principals, []);
  assert.notEqual(first, second);
  assert.equal(validated, 2);
  assert.throws(
    () =>
      livePolicy(f.path, () => {
        throw Error("guard_refused");
      })(),
    /guard_refused/,
  );
});

test("an unchanged file is not re-read or re-parsed", (t) => {
  const f = fixture(t);
  const read = livePolicy(f.path);
  let reads = 0;
  const original = fs.readFileSync;
  const mocked = t.mock.method(fs, "readFileSync", (...args) => {
    // The reader reads through an open descriptor (or, formerly, the path).
    if (args[0] === f.path || typeof args[0] === "number") reads++;
    return original(...args);
  });
  // The reader imports readFileSync by name: re-sync builtin named exports.
  syncBuiltinESMExports();
  try {
    for (let i = 0; i < 50; i++) read();
    assert.equal(reads, 1, "parsed once for 50 reads of an unchanged file");
    f.write(41009);
    assert.equal(read().port, 41009);
    assert.equal(reads, 2, "an edit is read again");
  } finally {
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
});
