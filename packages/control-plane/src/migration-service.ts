// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { type Snapshot } from "./snapshot.ts";
/** Caller supplies an enforceable quiescence lease, not a boolean assertion. */
export function extractSnapshot(
  db: DatabaseSync,
  migration_id: string,
  provenance: string,
  assertQuiesced: () => void,
): Snapshot {
  assertQuiesced();
  db.exec("BEGIN IMMEDIATE");
  try {
    const records = db
      .prepare("SELECT kind,id,value FROM records ORDER BY kind,id")
      .all()
      .map((r) => ({ kind: String(r.kind), id: String(r.id), ciphertext: String(r.value) }));
    // Include exact retained audit/diagnostic windows, not invented historical completeness.
    for (const table of ["audit", "diagnostics"]) {
      if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)) {
        for (const row of db.prepare(`SELECT * FROM ${table} ORDER BY seq`).all())
          records.push({ kind: "$" + table, id: String(row.seq), ciphertext: JSON.stringify(row) });
      }
    }
    const source_snapshot = createHash("sha256").update(JSON.stringify(records)).digest("hex");
    assertQuiesced();
    db.exec("COMMIT");
    return { migration_id, source_snapshot, encryption_provenance: provenance, records };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
