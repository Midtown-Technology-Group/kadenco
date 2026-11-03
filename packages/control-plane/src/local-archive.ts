// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { openSync, closeSync, readSync, fstatSync } from "node:fs";
import { createHash } from "node:crypto";
import { sourcePreflight } from "./source-preflight.ts";
import type { LocalArchiveReference } from "./migration-service.ts";

/** Fingerprint existing local DB + WAL bytes in bounded buffers. Never export them. */
function fingerprint(path: string) {
  const hash = createHash("sha256"),
    buffer = Buffer.alloc(65536);
  for (const suffix of ["", "-wal"]) {
    hash.update(suffix === "" ? "database:" : "wal:");
    let fd: number;
    try {
      fd = openSync(path + suffix, "r");
    } catch (error) {
      if (suffix && (error as NodeJS.ErrnoException).code === "ENOENT") {
        hash.update("absent");
        continue;
      }
      throw Error("local_archive_unavailable");
    }
    try {
      const before = fstatSync(fd);
      if (!before.isFile()) throw Error("local_archive_unavailable");
      // SQLite may create an empty WAL while opening a quiesced WAL-mode DB
      // read-only. Empty and absent WALs both contain no retained frames.
      if (suffix && before.size === 0) {
        hash.update("absent");
        continue;
      }
      hash.update(String(before.size) + ":");
      for (;;) {
        const n = readSync(fd, buffer);
        if (!n) break;
        hash.update(buffer.subarray(0, n));
      }
      const after = fstatSync(fd);
      if (
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ino !== after.ino
      )
        throw Error("local_archive_changed");
    } finally {
      closeSync(fd);
    }
  }
  return hash.digest("hex");
}

/** Read-only archive evidence; authority/quiescence and enforced retention remain separate. */
export function localArchiveReference(path: string): LocalArchiveReference {
  const before = fingerprint(path);
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    db.exec("BEGIN");
    const p = sourcePreflight(db, "local_archive");
    if (!p.fits_current_materialized_path) throw Error("local_archive_operational_state_too_large");
    const rows = db
      .prepare("SELECT kind,id,value FROM records ORDER BY kind,id")
      .all()
      .map((r) => ({ kind: String(r.kind), id: String(r.id), ciphertext: String(r.value) }));
    const result = {
      archive_sha256: before,
      operational_sha256: createHash("sha256").update(JSON.stringify(rows)).digest("hex"),
      audit_rows: p.retained_history.audit,
      diagnostic_rows: p.retained_history.diagnostics,
    };
    if (fingerprint(path) !== before) throw Error("local_archive_changed");
    db.exec("ROLLBACK");
    return result;
  } finally {
    db.close();
  }
}
