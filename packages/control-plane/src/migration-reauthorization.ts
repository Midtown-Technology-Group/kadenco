// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
type Principal = {
  id: string;
  role: string;
  hosts: string[];
  expiresAt: number;
  migrationAuthority?: boolean;
  stateCustodian?: boolean;
  maxPerDay?: number | null;
  scopes?: unknown[];
  nativeGrants?: unknown[];
  threadBudgets?: unknown[];
};
export const migrationReauthorizationSchema = `CREATE TABLE IF NOT EXISTS migration_reauthorizations(principal TEXT PRIMARY KEY,request TEXT UNIQUE NOT NULL,actor TEXT NOT NULL,input TEXT NOT NULL,value TEXT NOT NULL);`;
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const fail = (s: string): never => {
  throw Error(s);
};
const text = (v: unknown) =>
  typeof v === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(v) ? v : fail("invalid_request");
const keys = (p: object, allowed: string[]) => {
  if (Object.keys(p).some((k) => !allowed.includes(k))) fail("invalid_request");
};
/** Owner-only operator path, not MCP. One extension per existing migration
 * principal for its entire retained lifetime. Caller authentication and this
 * mutation execute in the same DO transaction; environment policy is not edited. */
export function migrationReauthorization(
  sql: SqlStorage,
  actor: Principal,
  current: { revision: number; principals: Principal[] },
  op: string,
  p: Record<string, unknown>,
) {
  if (
    ![
      "migration_reauthorization_challenge",
      "migration_reauthorization_receipt",
      "reauthorize_migration",
    ].includes(op)
  )
    return undefined;
  if (actor.role !== "owner") fail("forbidden");
  const principal = text(p.principal_id);
  const target = current.principals.find((a) => a.id === principal) ?? fail("forbidden");
  if (
    target.role !== "migration" ||
    target.migrationAuthority !== true ||
    target.stateCustodian === true ||
    target.maxPerDay !== 0 ||
    (target.scopes?.length ?? 0) ||
    (target.nativeGrants?.length ?? 0) ||
    (target.threadBudgets?.length ?? 0) ||
    target.hosts.some((h) => !actor.hosts.includes(h))
  )
    fail("forbidden");
  const prior = sql
    .exec<{ request: string; actor: string; input: string; value: string }>(
      "SELECT request,actor,input,value FROM migration_reauthorizations WHERE principal=?",
      principal,
    )
    .toArray()[0];
  if (prior && prior.actor !== actor.id) fail("forbidden");
  if (op !== "migration_reauthorization_challenge") {
    const used = sql
      .exec<{ principal: string }>(
        "SELECT principal FROM migration_reauthorizations WHERE request=?",
        text(p.request_id),
      )
      .toArray()[0];
    if (used && used.principal !== principal) fail("idempotency_conflict");
  }
  if (op === "migration_reauthorization_receipt") {
    keys(p, ["principal_id", "request_id"]);
    const request = text(p.request_id);
    if (prior && prior.request !== request) fail("idempotency_conflict");
    return prior ? { committed: true, ...JSON.parse(prior.value) } : { committed: false };
  }
  if (op === "migration_reauthorization_challenge") {
    keys(p, ["principal_id"]);
    if (prior) fail("idempotency_conflict");
  } else
    keys(p, [
      "principal_id",
      "request_id",
      "expected_revision",
      "expected_principal_sha256",
      "previous_expires_at",
      "expires_at",
      "approval_reference",
    ]);
  const input =
    op === "reauthorize_migration"
      ? JSON.stringify([
          principal,
          text(p.request_id),
          p.expected_revision,
          p.expected_principal_sha256,
          p.previous_expires_at,
          p.expires_at,
          text(p.approval_reference),
        ])
      : "";
  if (prior) {
    if (prior.input !== input) fail("idempotency_conflict");
    return JSON.parse(prior.value);
  }
  const now = Date.now();
  if (
    sql.exec("SELECT id FROM revoked WHERE id=?", principal).toArray().length ||
    target.expiresAt > now
  )
    fail("forbidden");
  if (sql.exec<{ mode: string }>("SELECT mode FROM control WHERE id=1").one().mode === "quiesced")
    fail("fenced");
  if (op === "migration_reauthorization_challenge")
    return {
      principal_id: principal,
      revision: current.revision,
      principal_sha256: hash(target),
      previous_expires_at: target.expiresAt,
      maximum_expires_at: Math.min(now + 3600000, actor.expiresAt),
      hosts: target.hosts,
      recovery_only: true,
    };
  if (
    p.expected_revision !== current.revision ||
    p.expected_principal_sha256 !== hash(target) ||
    p.previous_expires_at !== target.expiresAt
  )
    fail("fenced");
  const expires = p.expires_at;
  if (
    typeof expires !== "number" ||
    !Number.isSafeInteger(expires) ||
    expires <= now ||
    expires > Math.min(now + 3600000, actor.expiresAt)
  )
    fail("invalid_request");
  if (!Number.isSafeInteger(current.revision + 1)) fail("fenced");
  const next = {
    ...current,
    revision: current.revision + 1,
    principals: current.principals.map((a) =>
      a.id === principal ? { ...a, expiresAt: expires } : a,
    ),
  };
  const result = {
    kind: "migration_reauthorization",
    request_id: p.request_id,
    principal_id: principal,
    previous_expires_at: target.expiresAt,
    expires_at: expires,
    revision: next.revision,
    applied_at: now,
    approval_reference: p.approval_reference,
  };
  sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(next));
  sql.exec(
    "INSERT INTO migration_reauthorizations VALUES(?,?,?,?,?)",
    principal,
    String(p.request_id),
    actor.id,
    input,
    JSON.stringify(result),
  );
  sql.exec(
    "INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)",
    actor.id,
    op,
    principal,
    now,
  );
  return result;
}
