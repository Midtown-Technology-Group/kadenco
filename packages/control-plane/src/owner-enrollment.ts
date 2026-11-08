// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { NativeGrantScope, OperationBinding } from "./binding";
export type ControlPrincipal = {
  id: string;
  tokenSha256: string;
  role: "owner" | "executor" | "migration";
  hosts: string[];
  scopes?: OperationBinding[];
  nativeGrants?: NativeGrantScope[];
  migrationAuthority?: boolean;
  stateCustodian?: boolean;
  maxPerDay?: number | null;
  threadBudgets?: { thread: string; provider: string; maxPerDay: number; expiresAt: number }[];
  expiresAt: number;
};
export type ControlPolicy = { revision: number; fleet: string; principals: ControlPrincipal[] };
const fail = (reason: string): never => {
  throw Error(reason);
};
function canonical(value: unknown): string {
  if (value === undefined) return "undefined";
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value && typeof value === "object")
    return (
      "{" +
      Object.entries(value)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => JSON.stringify(k) + ":" + canonical(v))
        .join(",") +
      "}"
    );
  return JSON.stringify(value);
}
export const enrollmentPolicyDigest = (policy: ControlPolicy) =>
  createHash("sha256").update(canonical(policy)).digest("hex");
const identity = (v: unknown) =>
  typeof v === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(v) ? v : fail("invalid_request");
/** Operator-only, not MCP. Environment policy is the independent approval input.
 * Caller-supplied policy/roles cannot authorize enrollment. Execute in the same
 * transaction as current caller authentication. Audit is already in recovery. */
export function ownerEnrollment(
  sql: SqlStorage,
  actor: ControlPrincipal,
  current: ControlPolicy,
  configured: ControlPolicy,
  op: string,
  p: Record<string, unknown>,
) {
  if (
    !["enroll_configured_owner", "owner_enrollment_receipt", "owner_enrollment_challenge"].includes(
      op,
    )
  )
    return undefined;
  if (actor.role !== "owner") fail("forbidden");
  if (op === "owner_enrollment_challenge") {
    if (Object.keys(p).length) fail("invalid_request");
    return {
      revision: current.revision,
      current_policy_sha256: enrollmentPolicyDigest(current),
      configured_policy_sha256: enrollmentPolicyDigest(configured),
    };
  }
  const receiptOnly = op === "owner_enrollment_receipt";
  const allowed = receiptOnly
    ? ["request_id"]
    : ["request_id", "principal_id", "executor_id", "expected_revision", "expected_policy_sha256"];
  if (Object.keys(p).some((k) => !allowed.includes(k))) fail("invalid_request");
  const request = identity(p.request_id);
  const prior = sql
    .exec<{ actor: string; subject: string }>(
      "SELECT actor,subject FROM audit WHERE action='enroll_configured_owner' AND json_extract(subject,'$.request_id')=?",
      request,
    )
    .toArray()[0];
  if (prior && prior.actor !== actor.id) fail("forbidden");
  if (receiptOnly)
    return prior ? { committed: true, ...JSON.parse(prior.subject) } : { committed: false };
  const principal = identity(p.principal_id);
  const executor = identity(p.executor_id);
  if (
    !Number.isSafeInteger(p.expected_revision) ||
    typeof p.expected_policy_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(p.expected_policy_sha256)
  )
    fail("invalid_request");
  const input = createHash("sha256").update(canonical(p)).digest("hex");
  if (prior) {
    const receipt = JSON.parse(prior.subject);
    if (receipt.input_sha256 !== input) fail("idempotency_conflict");
    return { committed: true, ...receipt };
  }
  if (
    p.expected_revision !== current.revision ||
    configured.revision !== current.revision + 1 ||
    p.expected_policy_sha256 !== enrollmentPolicyDigest(configured)
  )
    fail("fenced");
  const target = configured.principals.find((n) => n.id === principal) ?? fail("forbidden");
  if (
    current.principals.some((n) => n.id === principal) ||
    target.role !== "owner" ||
    target.migrationAuthority === true ||
    target.stateCustodian === true ||
    target.expiresAt <= Date.now() ||
    target.expiresAt > actor.expiresAt ||
    sql.exec("SELECT id FROM revoked WHERE id=?", principal).toArray().length
  )
    fail("forbidden");
  // Deliberately narrow: mirror this sponsor's operational authority exactly,
  // with a distinct credential and no migration/custody authority. No arbitrary grants.
  const authority = (a: ControlPrincipal) => {
    const {
      id: _id,
      tokenSha256: _token,
      expiresAt: _expiry,
      migrationAuthority: _migration,
      stateCustodian: _custody,
      ...rest
    } = a;
    return canonical({
      ...rest,
      nativeGrants: rest.nativeGrants?.map(
        ({ grant: _grant, expires: _expires, ...scope }) => scope,
      ),
    });
  };
  if (
    authority(target) !== authority(actor) ||
    current.principals.some((n) => n.tokenSha256 === target.tokenSha256)
  )
    fail("forbidden");
  if (
    (target.nativeGrants ?? []).some(
      (g, i) =>
        g.grant === actor.nativeGrants?.[i]?.grant ||
        g.expires > actor.nativeGrants![i]!.expires ||
        g.expires > target.expiresAt ||
        g.expires <= Date.now(),
    )
  )
    fail("forbidden");
  const oldExecutor =
    current.principals.find((n) => n.id === executor && n.role === "executor") ?? fail("forbidden");
  if (
    oldExecutor.expiresAt < target.expiresAt ||
    target.hosts.some((h) => !oldExecutor.hosts.includes(h)) ||
    sql.exec("SELECT id FROM revoked WHERE id=?", executor).toArray().length
  )
    fail("forbidden");
  const expectedExecutor = {
    ...oldExecutor,
    nativeGrants: [...(oldExecutor.nativeGrants ?? []), ...(target.nativeGrants ?? [])],
  };
  if (
    configured.fleet !== current.fleet ||
    configured.principals.length !== current.principals.length + 1 ||
    current.principals.some(
      (old) =>
        canonical(configured.principals.find((n) => n.id === old.id)) !==
        canonical(old.id === executor ? expectedExecutor : old),
    )
  )
    fail("forbidden");
  const receipt = {
    request_id: request,
    principal_id: principal,
    revision: configured.revision,
    policy_sha256: p.expected_policy_sha256,
    input_sha256: input,
  };
  sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(configured));
  sql.exec(
    "INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)",
    actor.id,
    op,
    JSON.stringify(receipt),
    Date.now(),
  );
  return { committed: true, ...receipt };
}
