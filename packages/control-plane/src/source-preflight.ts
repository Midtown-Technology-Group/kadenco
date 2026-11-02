// SPDX-License-Identifier: AGPL-3.0-or-later
import type { DatabaseSync } from "node:sqlite";

/** Emit aggregate metadata only; inspect retained rows one at a time, never export their contents. */
export function sourcePreflight(
  db: DatabaseSync,
  historyMode: "include" | "local_archive" = "include",
) {
  if (!["include", "local_archive"].includes(historyMode)) throw Error("unsupported_history_mode");
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
  let largestEnvelope = Number(records.largest);
  const history: Record<string, number> = {};
  for (const table of ["audit", "diagnostics"]) {
    let count = 0;
    if (tables.has(table)) {
      if (historyMode === "local_archive") {
        count = Number(db.prepare(`SELECT COUNT(*) n FROM ${table}`).get()!.n);
      } else {
        // Use the identical serialization to extractSnapshot, including escaping and
        // UTF-16 length. SQL length(raw) would undercount both controls and astral text.
        for (const row of db.prepare(`SELECT * FROM ${table}`).iterate()) {
          count++;
          largestEnvelope = Math.max(largestEnvelope, JSON.stringify(row).length);
        }
      }
    }
    history[table] = count;
    retained += count;
  }
  const total = Number(records.n) + (historyMode === "include" ? retained : 1);
  const blockers = [];
  if (total > 100000) blockers.push("snapshot_row_limit_exceeded");
  if (total > 10000) blockers.push("legacy_adoption_row_limit_exceeded");
  if (largestEnvelope > 32768) blockers.push("record_envelope_limit_exceeded");
  return {
    records: Number(records.n),
    retained_history: history,
    total_rows: total,
    history_mode: historyMode,
    largest_record_chars: Number(records.largest),
    largest_envelope_chars: largestEnvelope,
    blockers,
    fits_current_materialized_path: blockers.length === 0,
    consistency: "caller_transaction_required_for_consistent_counts",
    production_ready: false,
    authority_checked: false,
    encrypted_content_checked: false,
  };
}
