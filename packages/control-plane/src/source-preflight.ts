// SPDX-License-Identifier: AGPL-3.0-or-later
import type { DatabaseSync } from "node:sqlite";

/** Aggregate metadata only: no ciphertext, IDs, audit text, keys or authorization inference. */
export function sourcePreflight(db: DatabaseSync) {
  const tables = new Set(
    db
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all()
      .map((r) => String(r.name)),
  );
  if (!tables.has("records")) throw Error("unsupported_source_schema");
  const columns = db
    .prepare("PRAGMA table_info(records)")
    .all()
    .map((r) => String(r.name));
  if (columns.length !== 3 || !["kind", "id", "value"].every((c) => columns.includes(c)))
    throw Error("unsupported_source_schema");
  const records = db
    .prepare("SELECT COUNT(*) n, COALESCE(MAX(length(value)),0) largest FROM records")
    .get()!;
  let retained = 0;
  const history: Record<string, number> = {};
  for (const table of ["audit", "diagnostics"]) {
    const count = tables.has(table)
      ? Number(db.prepare(`SELECT COUNT(*) n FROM ${table}`).get()!.n)
      : 0;
    history[table] = count;
    retained += count;
  }
  const total = Number(records.n) + retained;
  const blockers = [];
  if (total > 100000) blockers.push("snapshot_row_limit_exceeded");
  if (total > 10000) blockers.push("legacy_adoption_row_limit_exceeded");
  if (Number(records.largest) > 32768) blockers.push("record_envelope_limit_exceeded");
  return {
    records: Number(records.n),
    retained_history: history,
    total_rows: total,
    largest_record_chars: Number(records.largest),
    blockers,
    fits_current_materialized_path: blockers.length === 0,
    consistency: "caller_transaction_required_for_consistent_counts",
    production_ready: false,
    authority_checked: false,
    encrypted_content_checked: false,
  };
}
