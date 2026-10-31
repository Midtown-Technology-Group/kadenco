// SPDX-License-Identifier: AGPL-3.0-or-later
export const recoveryTables = [
  "recovery_freezes",
  "auth_policy",
  "revoked",
  "control",
  "commands",
  "imported",
  "audit",
  "budget_reservations",
  "subscriptions",
  "observations",
  "outbox",
  "edge_lease",
] as const;
export type RecoveryRow = {
  table: (typeof recoveryTables)[number];
  key: number;
  values: Record<string, string | number | null>;
};
export function assertRecoverySchema(sql: SqlStorage) {
  const names = sql
    .exec<{ name: string }>(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT GLOB 'sqlite_*'",
    )
    .toArray()
    .map((r) => r.name);
  if (
    names.some((n) => !recoveryTables.includes(n as (typeof recoveryTables)[number])) ||
    recoveryTables.some((n) => !names.includes(n))
  )
    throw Error("schema_mismatch");
}
export function recoveryPage(sql: SqlStorage, table: number, after: number) {
  if (
    !Number.isSafeInteger(table) ||
    table < 0 ||
    table >= recoveryTables.length ||
    !Number.isSafeInteger(after) ||
    after < 0
  )
    throw Error("invalid_request");
  const name = recoveryTables[table],
    rows = sql
      .exec<Record<string, string | number | null>>(
        `SELECT rowid AS _recovery_key,* FROM ${name} WHERE rowid>? ORDER BY rowid LIMIT 101`,
        after,
      )
      .toArray();
  const result: RecoveryRow[] = [];
  let bytes = 128;
  for (const row of rows.slice(0, 100)) {
    const { _recovery_key: key, ...values } = row;
    const entry = { table: name, key: Number(key), values };
    const size = new TextEncoder().encode(JSON.stringify(entry)).byteLength;
    if (bytes + size > 60000) break;
    result.push(entry);
    bytes += size;
  }
  if (rows.length && !result.length) throw Error("body_too_large");
  const next =
    rows.length > result.length
      ? { table, after: result.at(-1)!.key }
      : table + 1 < recoveryTables.length
        ? { table: table + 1, after: 0 }
        : null;
  return { rows: result, next };
}
/** Offline/local fixture restore only: no HTTP restore endpoint is installed.
 * Caller runs this in a single SQL transaction after authenticating ALL pages. */
function restoreRows(
  sql: SqlStorage,
  rows: RecoveryRow[],
  expected: { epoch: number; counts: Record<string, number> },
) {
  assertRecoverySchema(sql);
  if (
    sql.exec<{ mode: string; epoch: number }>("SELECT mode,epoch FROM control WHERE id=1").one()
      .mode !== "staging"
  )
    throw Error("destination_not_staging");
  if (
    expected.counts.control !== 1 ||
    expected.counts.auth_policy !== 1 ||
    Object.keys(expected.counts).some(
      (n) => !recoveryTables.includes(n as (typeof recoveryTables)[number]),
    )
  )
    throw Error("incomplete_recovery");
  if (rows.length > 100000) throw Error("recovery_too_large");
  for (const table of recoveryTables) {
    if (
      !["auth_policy", "control", "audit"].includes(table) &&
      sql.exec<{ n: number }>(`SELECT COUNT(*) n FROM ${table}`).one().n
    )
      throw Error("destination_not_empty");
  }
  const seen = new Set<string>();
  const control = rows.find((r) => r.table === "control");
  if (
    !control ||
    !Number.isSafeInteger(control.values.epoch) ||
    control.values.epoch !== expected.epoch
  )
    throw Error("invalid_recovery");
  for (const table of recoveryTables)
    if (
      !Number.isSafeInteger(expected.counts[table]) ||
      expected.counts[table] < 0 ||
      rows.filter((r) => r.table === table).length !== expected.counts[table]
    )
      throw Error("incomplete_recovery");
  for (const row of rows) {
    if (
      !recoveryTables.includes(row.table) ||
      !Number.isSafeInteger(row.key) ||
      row.key < 1 ||
      seen.has(row.table + ":" + row.key)
    )
      throw Error("invalid_recovery");
    seen.add(row.table + ":" + row.key);
    const columns = sql
      .exec<{ name: string }>(`PRAGMA table_info(${row.table})`)
      .toArray()
      .map((c) => c.name);
    if (
      Object.keys(row.values).length !== columns.length ||
      columns.some((k) => !(k in row.values)) ||
      Object.values(row.values).some(
        (v) =>
          v !== null && typeof v !== "string" && (typeof v !== "number" || !Number.isFinite(v)),
      )
    )
      throw Error("schema_mismatch");
  }
  for (const table of recoveryTables) sql.exec(`DELETE FROM ${table}`);
  for (const row of rows) {
    const values = { ...row.values };
    if (row.table === "control") {
      values.mode = "quiesced";
      values.epoch = Number(values.epoch) + 1;
    }
    if (row.table === "commands" && ["pending", "claimed"].includes(String(values.state)))
      values.state = "uncertain";
    if (row.table === "edge_lease") {
      values.holder = null;
      values.expires = 0;
      values.generation = Number(values.generation) + 1;
    }
    const columns = Object.keys(values);
    sql.exec(
      `INSERT INTO ${row.table}(rowid,${columns.map((c) => '"' + c + '"').join(",")}) VALUES(${[row.key, ...columns].map(() => "?").join(",")})`,
      row.key,
      ...columns.map((c) => values[c]),
    );
  }
  return { restored_rows: rows.length, activation_permitted: false };
}

export function restoreInert(
  storage: { sql: SqlStorage; transactionSync<T>(fn: () => T): T },
  rows: RecoveryRow[],
  expected: { epoch: number; counts: Record<string, number> },
) {
  return storage.transactionSync(() => restoreRows(storage.sql, rows, expected));
}
