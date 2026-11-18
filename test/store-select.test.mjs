// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { Store } from "../dist/store.mjs";

function fixture(t) {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-select-"));
  const store = new Store(join(dir, "state.db"), randomBytes(32));
  t.after(() => {
    store.db.close();
    rmSync(dir, { recursive: true, force: true });
  });
  let decodes = 0;
  const decode = store.decode.bind(store);
  store.decode = (raw) => {
    decodes++;
    return decode(raw);
  };
  return { store, decodes: () => decodes, reset: () => (decodes = 0) };
}
const pending = (d) => d.status === "pending";
const ids = (rows) => rows.map((r) => r.id);

test("select returns matching records in id order, same as filtering all()", (t) => {
  const { store } = fixture(t);
  for (const [id, status] of [
    ["c", "pending"],
    ["a", "acknowledged"],
    ["b", "pending"],
  ])
    store.put("delivery", id, { id, status });
  store.put("subscription", "b", { id: "b", status: "pending" });
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["b", "c"]);
  assert.deepEqual(
    store.select("delivery", "pending", pending),
    store.all("delivery").filter(pending),
  );
});

test("unchanged non-matching records are not decrypted again", (t) => {
  const { store, decodes, reset } = fixture(t);
  for (let i = 0; i < 200; i++)
    store.put("delivery", `d${String(i).padStart(3, "0")}`, {
      status: i % 50 ? "acknowledged" : "pending",
    });
  assert.equal(store.select("delivery", "pending", pending).length, 4);
  reset();
  assert.equal(store.select("delivery", "pending", pending).length, 4);
  assert.equal(decodes(), 4, "only the matching rows are decoded on a repeat call");
});

test("any write, rollback or direct SQL change is seen on the next call", (t) => {
  const { store } = fixture(t);
  store.put("delivery", "a", { id: "a", status: "pending" });
  store.put("delivery", "b", { id: "b", status: "acknowledged" });
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["a"]);
  store.put("delivery", "a", { id: "a", status: "acknowledged" });
  store.put("delivery", "b", { id: "b", status: "pending" });
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["b"]);
  // A transaction that is observed mid-flight and then rolled back.
  assert.throws(() =>
    store.transaction(() => {
      store.put("delivery", "a", { id: "a", status: "pending" });
      assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["a", "b"]);
      throw Error("rollback");
    }),
  );
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["b"]);
  // A writer that bypasses Store.put (for example replica rehydration).
  const raw = store.encode({ id: "a", status: "pending" });
  store.db.prepare("UPDATE records SET value=? WHERE kind='delivery' AND id='a'").run(raw);
  store.db
    .prepare("INSERT INTO records(kind,id,value) VALUES('delivery','c',?)")
    .run(store.encode({ id: "c", status: "pending" }));
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["a", "b", "c"]);
});

test("results are independent objects; predicates are cached per name", (t) => {
  const { store } = fixture(t);
  store.put("delivery", "a", { id: "a", status: "pending", n: 1 });
  const [first] = store.select("delivery", "pending", pending);
  first.n = 99;
  assert.equal(store.select("delivery", "pending", pending)[0].n, 1);
  assert.deepEqual(
    ids(store.select("delivery", "centralized", (d) => d.status === "centralized")),
    [],
  );
  assert.deepEqual(ids(store.select("delivery", "pending", pending)), ["a"]);
});

test("signatures are read from the covering index, not from row values", (t) => {
  const { store } = fixture(t);
  const plan = store.db
    .prepare(
      "EXPLAIN QUERY PLAN SELECT id, substr(value,1,40) AS sig FROM records WHERE kind=? ORDER BY id",
    )
    .all("delivery")
    .map((r) => r.detail)
    .join(" ");
  assert.match(plan, /COVERING INDEX records_signature/);
});
