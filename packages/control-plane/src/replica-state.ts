// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ServicePrincipal } from "./services.ts";
/** Opaque operational envelopes only. Historical audit/diagnostics stay archived.
 * Every operation executes inside FleetState's current-policy SQL transaction. */
export function replicaSchema(sql: SqlStorage) {
  sql.exec(`
CREATE TABLE IF NOT EXISTS replica_head(id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL);
INSERT OR IGNORE INTO replica_head VALUES(1,0);
CREATE TABLE IF NOT EXISTS replica_records(kind TEXT NOT NULL,id TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE IF NOT EXISTS replica_receipts(id TEXT PRIMARY KEY,executor TEXT NOT NULL,value TEXT NOT NULL,revision INTEGER NOT NULL);
`);
}
const fail = (reason: string): never => {
  throw Error(reason);
};
const integer = (v: unknown): number =>
  Number.isSafeInteger(v) && Number(v) >= 0 ? Number(v) : fail("invalid_request");
const text = (v: unknown, max: number): string =>
  typeof v === "string" && v.length > 0 && v.length <= max ? v : fail("invalid_request");
function keys(p: object, allowed: string[]) {
  if (Object.keys(p).some((k) => !allowed.includes(k))) fail("invalid_request");
}
export function replicaOperation(
  sql: SqlStorage,
  actor: ServicePrincipal,
  op: string,
  p: Record<string, unknown>,
  now: number,
) {
  if (!["replica_head", "replica_page", "replica_apply", "replica_receipt"].includes(op))
    return undefined;
  if (actor.role !== "executor" || actor.stateCustodian !== true) fail("forbidden");
  const lease = sql
    .exec<{ holder: string; generation: number; expires: number }>(
      "SELECT holder,generation,expires FROM edge_lease WHERE id=1",
    )
    .toArray()[0];
  if (
    !lease ||
    lease.holder !== actor.id ||
    lease.generation !== integer(p.generation) ||
    lease.expires <= now
  )
    fail("fenced");
  const revision = sql
    .exec<{ revision: number }>("SELECT revision FROM replica_head WHERE id=1")
    .one().revision;
  if (op === "replica_head") {
    keys(p, ["epoch", "generation"]);
    return { revision };
  }
  if (op === "replica_receipt") {
    keys(p, ["epoch", "generation", "request_id"]);
    const row = sql
      .exec<{ executor: string; revision: number }>(
        "SELECT executor,revision FROM replica_receipts WHERE id=?",
        text(p.request_id, 100),
      )
      .toArray()[0];
    if (row && row.executor !== actor.id) fail("forbidden");
    return { committed: !!row, revision: row?.revision ?? null };
  }
  if (op === "replica_page") {
    keys(p, ["epoch", "generation", "revision", "after_kind", "after_id"]);
    if (integer(p.revision) !== revision) fail("fenced");
    const kind = p.after_kind === undefined ? "" : text(p.after_kind, 200);
    const id = p.after_id === undefined ? "" : text(p.after_id, 2048);
    const rows = sql
      .exec<{ kind: string; id: string; ciphertext: string }>(
        `
SELECT kind,id,ciphertext FROM (
 SELECT kind,id,ciphertext FROM replica_records
 UNION ALL SELECT i.kind,i.id,i.ciphertext FROM imported i
 WHERE i.kind NOT GLOB '$*' AND NOT EXISTS(SELECT 1 FROM replica_records r WHERE r.kind=i.kind AND r.id=i.id)
) WHERE kind>? OR (kind=? AND id>?) ORDER BY kind,id LIMIT 101`,
        kind,
        kind,
        id,
      )
      .toArray();
    const records: typeof rows = [];
    let bytes = 128;
    for (const row of rows.slice(0, 100)) {
      const size = new TextEncoder().encode(JSON.stringify(row)).byteLength + 1;
      if (bytes + size > 60000) break;
      records.push(row);
      bytes += size;
    }
    if (rows.length && !records.length) fail("body_too_large");
    const last = records.at(-1);
    return {
      revision,
      records,
      next: rows.length > records.length ? { after_kind: last!.kind, after_id: last!.id } : null,
    };
  }
  keys(p, ["epoch", "generation", "request_id", "expected_revision", "records"]);
  const id = text(p.request_id, 100);
  if (!/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(id)) fail("invalid_request");
  const expected = integer(p.expected_revision);
  if (!Array.isArray(p.records) || !p.records.length || p.records.length > 100)
    fail("invalid_request");
  const seen = new Set<string>();
  const records = (p.records as unknown[]).map((raw) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) fail("invalid_request");
    const r = raw as Record<string, unknown>;
    keys(r, ["kind", "id", "ciphertext"]);
    const kind = text(r.kind, 200),
      key = text(r.id, 2048),
      ciphertext = text(r.ciphertext, 32768);
    if (kind.startsWith("$") || seen.has(JSON.stringify([kind, key]))) fail("invalid_request");
    seen.add(JSON.stringify([kind, key]));
    return { kind, id: key, ciphertext };
  });
  const value = JSON.stringify({ expected_revision: expected, records });
  // A receipt is itself exported in bounded recovery pages. Reserve wrapper room.
  if (
    new TextEncoder().encode(value).byteLength > 40000 ||
    new TextEncoder().encode(JSON.stringify(value)).byteLength > 56000
  )
    fail("body_too_large");
  const old = sql
    .exec<{ executor: string; value: string; revision: number }>(
      "SELECT * FROM replica_receipts WHERE id=?",
      id,
    )
    .toArray()[0];
  if (old) {
    if (old.executor !== actor.id) fail("forbidden");
    if (old.value !== value) fail("idempotency_conflict");
    return { committed: true, revision: old.revision };
  }
  if (expected !== revision) fail("fenced");
  if (!Number.isSafeInteger(revision + 1)) fail("fenced");
  for (const r of records)
    sql.exec(
      "INSERT INTO replica_records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET ciphertext=excluded.ciphertext",
      r.kind,
      r.id,
      r.ciphertext,
    );
  sql.exec("UPDATE replica_head SET revision=? WHERE id=1", revision + 1);
  sql.exec("INSERT INTO replica_receipts VALUES(?,?,?,?)", id, actor.id, value, revision + 1);
  return { committed: true, revision: revision + 1 };
}
