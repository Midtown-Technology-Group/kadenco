// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { randomBytes } from "node:crypto";
import { coreSchema } from "../src/core-schema.ts";
import { serviceSchema } from "../src/services.ts";
import {
  recoveryTables,
  legacyRecoveryTables,
  recoveryPage,
  restoreInert,
  type RecoveryRow,
} from "../src/recovery.ts";
import { packRecovery, verifyRecovery } from "../src/recovery-archive.ts";
function fixture() {
  const db = new DatabaseSync(":memory:");
  const sql = {
    exec(q: string, ...args: unknown[]) {
      if (q.trimStart().startsWith("CREATE")) {
        db.exec(q);
        return { toArray: () => [] };
      }
      const s = db.prepare(q),
        rows = s.columns().length ? s.all(...(args as never[])) : (s.run(...(args as never[])), []);
      return {
        toArray: () => rows,
        one: () => {
          assert.equal(rows.length, 1);
          return rows[0];
        },
      };
    },
  } as unknown as SqlStorage;
  db.exec(coreSchema);
  serviceSchema(sql);
  const transactionSync = <T,>(fn: () => T) => {
    db.exec("BEGIN");
    try {
      const r = fn();
      db.exec("COMMIT");
      return r;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  };
  return { db, sql, transactionSync };
}
test("authenticated inventory v2 preserves host identities and uncertain receipts while fencing recovered sessions; exact legacy inventory upgrades inertly", () => {
  const source = fixture(),
    target = fixture(),
    legacy = fixture(),
    key = randomBytes(32);
  try {
    source.db.exec(
      "INSERT INTO auth_policy VALUES(1,'fixture'); UPDATE control SET epoch=7,mode='active'; INSERT INTO host_links VALUES('a','a','original-connection',8,999999,0,0); INSERT INTO host_link_sessions VALUES('a','original-connection','a',8,1); INSERT INTO host_link_attempts VALUES('original-request','original-connection',8,3)",
    );
    const rows: RecoveryRow[] = [];
    for (let table = 0; table < recoveryTables.length; table++) {
      let after = 0;
      while (true) {
        const p = recoveryPage(source.sql, table, after);
        rows.push(...p.rows);
        if (!p.next || p.next.table !== table) break;
        after = p.next.after;
      }
    }
    const counts = Object.fromEntries(
      recoveryTables.map((t) => [t, rows.filter((r) => r.table === t).length]),
    );
    const header = { epoch: 7, watermark: 0, counts };
    const verified = verifyRecovery(packRecovery(header, rows, key), key, header);
    restoreInert(target, verified.rows, verified.header);
    assert.deepEqual(
      { ...target.db.prepare("SELECT connection,generation,expires FROM host_links").get() },
      { connection: "original-connection", generation: 9, expires: 0 },
    );
    assert.equal(
      target.db.prepare("SELECT request FROM host_link_attempts").get()!.request,
      "original-request",
    );
    assert.equal(target.db.prepare("SELECT mode FROM control").get()!.mode, "quiesced");
    const oldRows = rows.filter((r) =>
      (legacyRecoveryTables as readonly string[]).includes(r.table),
    );
    const oldHeader = {
      ...header,
      counts: Object.fromEntries(legacyRecoveryTables.map((t) => [t, counts[t]])),
    };
    const old = verifyRecovery(packRecovery(oldHeader, oldRows, key), key, header);
    restoreInert(legacy, old.rows, old.header);
    assert.equal(legacy.db.prepare("SELECT COUNT(*) n FROM host_links").get()!.n, 0);
    const partial = { ...counts };
    delete partial.host_link_attempts;
    assert.throws(
      () => verifyRecovery(packRecovery({ ...header, counts: partial }, rows, key), key, header),
      /schema_mismatch/,
    );
    assert.equal(legacy.db.prepare("SELECT epoch FROM control").get()!.epoch, 8);
  } finally {
    source.db.close();
    target.db.close();
    legacy.db.close();
  }
});
