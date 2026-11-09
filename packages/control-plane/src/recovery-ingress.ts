// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { recoveryTables, recoveryInventory, restoreInert, type RecoveryRow } from "./recovery.ts";
import type { RecoveryHeader } from "./recovery-archive.ts";

export const recoveryIngressSchema = `
CREATE TABLE IF NOT EXISTS recovery_imports(id TEXT PRIMARY KEY,actor TEXT NOT NULL,metadata TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_chunks(id TEXT NOT NULL,sequence INTEGER NOT NULL,value TEXT NOT NULL,item_count INTEGER NOT NULL,PRIMARY KEY(id,sequence));
CREATE TABLE IF NOT EXISTS recovery_import_receipts(id TEXT PRIMARY KEY,actor TEXT NOT NULL,digest TEXT NOT NULL,value TEXT NOT NULL);
`;
const fail = (reason: string): never => {
  throw Error(reason);
};
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const integer = (v: unknown, max = 100000) =>
  Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= max
    ? Number(v)
    : fail("invalid_request");
const text = (v: unknown) =>
  typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(v)
    ? v
    : fail("invalid_request");
const keys = (v: object, allowed: string[]) => {
  if (
    !v ||
    typeof v !== "object" ||
    Array.isArray(v) ||
    Object.keys(v).some((k) => !allowed.includes(k))
  )
    fail("invalid_request");
};
type Metadata = { expected_epoch: number; header: RecoveryHeader; digest: string; chunks: number };
/** Authenticated transport for an already verified current-state recovery
 * archive. Called INSIDE the existing FleetState transaction. It never activates
 * a destination, substitutes policy or accepts arbitrary SQL. */
export function recoveryIngress(
  sql: SqlStorage,
  actor: { id: string; role: string; migrationAuthority?: boolean },
  currentPolicy: unknown,
  op: string,
  p: Record<string, unknown>,
) {
  if (
    !["stage_recovery", "recovery_chunk", "commit_recovery", "recovery_import_receipt"].includes(op)
  )
    return undefined;
  if (!["owner", "migration"].includes(actor.role) || actor.migrationAuthority !== true)
    fail("forbidden");
  const id = text(p.import_id);
  const prior = sql
    .exec<{ actor: string; digest: string; value: string }>(
      "SELECT actor,digest,value FROM recovery_import_receipts WHERE id=?",
      id,
    )
    .toArray()[0];
  if (op === "recovery_import_receipt") {
    keys(p, ["import_id"]);
    if (prior && prior.actor !== actor.id) fail("forbidden");
    return prior ? { committed: true, ...JSON.parse(prior.value) } : { committed: false };
  }
  if (prior) {
    if (prior.actor !== actor.id) fail("forbidden");
    if (op !== "commit_recovery" || p.digest !== prior.digest) fail("idempotency_conflict");
    keys(p, ["import_id", "digest"]);
    return JSON.parse(prior.value);
  }
  const state = sql
    .exec<{ mode: string; epoch: number }>("SELECT mode,epoch FROM control WHERE id=1")
    .one();
  if (state.mode !== "staging") fail("not_active");
  const staged = sql
    .exec<{ actor: string; metadata: string }>(
      "SELECT actor,metadata FROM recovery_imports WHERE id=?",
      id,
    )
    .toArray()[0];
  if (staged && staged.actor !== actor.id) fail("forbidden");
  if (op === "stage_recovery") {
    keys(p, ["import_id", "expected_epoch", "header", "digest", "chunks"]);
    const h = p.header as RecoveryHeader;
    keys(h, ["epoch", "watermark", "counts", "activation_permitted"]);
    if (h.activation_permitted !== undefined && h.activation_permitted !== false)
      fail("invalid_request");
    if (!h.counts || typeof h.counts !== "object" || Array.isArray(h.counts))
      fail("invalid_request");
    const rows = recoveryInventory(h.counts).reduce((n, t) => n + integer(h.counts[t]), 0);
    if (rows > 100000 || h.counts.recovery_imports !== 0 || h.counts.recovery_chunks !== 0)
      fail("invalid_request");
    integer(h.epoch, Number.MAX_SAFE_INTEGER - 1);
    integer(h.watermark, Number.MAX_SAFE_INTEGER);
    const digest =
      typeof p.digest === "string" && /^[a-f0-9]{64}$/.test(p.digest)
        ? p.digest
        : fail("invalid_request");
    const m: Metadata = {
      expected_epoch: integer(p.expected_epoch),
      header: h,
      digest,
      chunks: integer(p.chunks, 10000),
    };
    if (m.chunks < 1 || m.expected_epoch !== state.epoch) fail("fenced");
    const encoded = JSON.stringify(m);
    if (staged) {
      if (staged.metadata !== encoded) fail("idempotency_conflict");
      return { staged: true };
    }
    if (sql.exec<{ n: number }>("SELECT COUNT(*) n FROM recovery_imports").one().n)
      fail("migration_conflict");
    sql.exec("INSERT INTO recovery_imports VALUES(?,?,?)", id, actor.id, encoded);
    return { staged: true };
  }
  if (!staged) fail("not_found");
  const m = JSON.parse(staged!.metadata) as Metadata;
  if (state.epoch !== m.expected_epoch) fail("fenced");
  if (op === "recovery_chunk") {
    keys(p, ["import_id", "sequence", "rows"]);
    const sequence = integer(p.sequence, m.chunks - 1);
    if (!Array.isArray(p.rows) || !p.rows.length || p.rows.length > 100) fail("invalid_request");
    for (const raw of p.rows as unknown[]) {
      const r = raw as RecoveryRow;
      keys(r, ["table", "key", "values"]);
      if (
        !recoveryTables.includes(r.table) ||
        integer(r.key, Number.MAX_SAFE_INTEGER) < 1 ||
        !r.values ||
        typeof r.values !== "object" ||
        Array.isArray(r.values)
      )
        fail("invalid_request");
    }
    const value = JSON.stringify(p.rows);
    if (new TextEncoder().encode(value).byteLength > 60000) fail("body_too_large");
    const old = sql
      .exec<{ value: string }>(
        "SELECT value FROM recovery_chunks WHERE id=? AND sequence=?",
        id,
        sequence,
      )
      .toArray()[0];
    if (old && old.value !== value) fail("idempotency_conflict");
    const size = sql
      .exec<{ n: number; items: number }>(
        "SELECT COALESCE(SUM(length(CAST(value AS BLOB))),0) n,COALESCE(SUM(item_count),0) items FROM recovery_chunks WHERE id=?",
        id,
      )
      .one();
    if (
      !old &&
      (size.n + new TextEncoder().encode(value).byteLength > 32 * 1024 * 1024 ||
        size.items + (p.rows as unknown[]).length > 100000)
    )
      fail("body_too_large");
    sql.exec(
      "INSERT OR IGNORE INTO recovery_chunks VALUES(?,?,?,?)",
      id,
      sequence,
      value,
      (p.rows as unknown[]).length,
    );
    return { stored: true, sequence };
  }
  keys(p, ["import_id", "digest"]);
  if (p.digest !== m.digest) fail("idempotency_conflict");
  const chunks = sql
    .exec<{ sequence: number; value: string }>(
      "SELECT sequence,value FROM recovery_chunks WHERE id=? ORDER BY sequence",
      id,
    )
    .toArray();
  if (chunks.length !== m.chunks || chunks.some((r, i) => r.sequence !== i))
    fail("incomplete_recovery");
  const rows = chunks.flatMap((r) => JSON.parse(r.value)) as RecoveryRow[];
  if (hash({ header: m.header, rows }) !== m.digest) fail("recovery_digest_mismatch");
  // Recovery may preserve revocations, but cannot replace the authenticated
  // destination policy with a broader or different source policy.
  const policies = rows.filter((r) => r.table === "auth_policy");
  if (policies.length !== 1 || policies[0].values.value !== JSON.stringify(currentPolicy))
    fail("recovery_policy_mismatch");
  for (const r of rows) {
    if (r.table === "recovery_import_receipts" && r.values.id === id) fail("idempotency_conflict");
    if (r.table === "recovery_imports" || r.table === "recovery_chunks")
      fail("incomplete_recovery");
  }
  // Remove staging inside this transaction only. Any restore failure rolls back
  // both deletion and imported rows, retaining the exact retry identity.
  sql.exec("DELETE FROM recovery_chunks WHERE id=?", id);
  sql.exec("DELETE FROM recovery_imports WHERE id=?", id);
  let result: ReturnType<typeof restoreInert>;
  try {
    result = restoreInert({ sql, transactionSync: (fn) => fn() }, rows, m.header);
  } catch (error) {
    const reason = error instanceof Error ? error.message : "invalid_recovery";
    if (
      [
        "destination_not_staging",
        "destination_not_empty",
        "invalid_recovery",
        "incomplete_recovery",
        "schema_mismatch",
        "recovery_too_large",
      ].includes(reason)
    )
      throw error;
    throw Error("invalid_recovery");
  }
  const value = { ...result, epoch: m.header.epoch + 1, digest: m.digest };
  sql.exec(
    "INSERT INTO recovery_import_receipts VALUES(?,?,?,?)",
    id,
    actor.id,
    m.digest,
    JSON.stringify(value),
  );
  return value;
}
