// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import { type Snapshot } from "./snapshot.ts";
import { sourcePreflight } from "./source-preflight.ts";
export type LocalArchiveReference = {
  archive_sha256: string;
  operational_sha256: string;
  audit_rows: number;
  diagnostic_rows: number;
};
/** Caller supplies an enforceable quiescence lease, not a boolean assertion. */
export function extractSnapshot(
  db: DatabaseSync,
  migration_id: string,
  provenance: string,
  assertQuiesced: () => void,
  retainedArchive?: { verify: () => LocalArchiveReference },
): Snapshot {
  assertQuiesced();
  db.exec("BEGIN IMMEDIATE");
  try {
    const preflight = sourcePreflight(db, retainedArchive ? "local_archive" : "include");
    if (!preflight.fits_current_materialized_path)
      throw Error("source_volume_requires_streaming_migration");
    const records = db
      .prepare("SELECT kind,id,value FROM records ORDER BY kind,id")
      .all()
      .map((r) => ({ kind: String(r.kind), id: String(r.id), ciphertext: String(r.value) }));
    if (retainedArchive) {
      const archive = retainedArchive.verify();
      const digest = createHash("sha256").update(JSON.stringify(records)).digest("hex");
      if (
        !/^[a-f0-9]{64}$/.test(archive.archive_sha256) ||
        archive.operational_sha256 !== digest ||
        archive.audit_rows !== preflight.retained_history.audit ||
        archive.diagnostic_rows !== preflight.retained_history.diagnostics
      )
        throw Error("local_archive_not_verified");
      records.push({
        kind: "$history_archive",
        id: archive.archive_sha256,
        ciphertext: JSON.stringify(archive),
      });
    } else
      for (const table of ["audit", "diagnostics"]) {
        if (db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table)) {
          for (const row of db.prepare(`SELECT * FROM ${table} ORDER BY seq`).all())
            records.push({
              kind: "$" + table,
              id: String(row.seq),
              ciphertext: JSON.stringify(row),
            });
        }
      }
    const source_snapshot = createHash("sha256").update(JSON.stringify(records)).digest("hex");
    if (retainedArchive && JSON.stringify(retainedArchive.verify()) !== records.at(-1)!.ciphertext)
      throw Error("local_archive_changed");
    assertQuiesced();
    db.exec("COMMIT");
    return { migration_id, source_snapshot, encryption_provenance: provenance, records };
  } catch (e) {
    db.exec("ROLLBACK");
    throw e;
  }
}
