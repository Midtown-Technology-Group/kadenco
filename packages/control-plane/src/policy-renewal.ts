// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { NativeGrantScope } from "./binding";
import {
  enrollmentPolicyDigest,
  type ControlPolicy,
  type ControlPrincipal,
} from "./owner-enrollment";

/** Upper bound on a renewed owner/executor expiry, measured from apply time.
 * The deployed policy chooses the actual ceiling; this only rejects mistakes. */
export const MAX_RENEWAL_MS = 366 * 86400000;
export const RENEWAL_OPS = [
  "policy_renewal_challenge",
  "renew_configured_policy",
  "policy_renewal_receipt",
];
const fail = (reason: string): never => {
  throw Error(reason);
};
const identity = (v: unknown) =>
  typeof v === "string" && /^[a-zA-Z0-9_-]{1,100}$/.test(v) ? v : fail("invalid_request");
const subset = (next: string[] | null, prior: string[] | null) =>
  prior === null || (next !== null && next.every((x) => prior.includes(x)));
/** A renewed grant keeps an existing host and purpose with no wider project or
 * provider scope. Its fingerprint may differ: the configured policy reconciles
 * changed routes or expiries, which is what fingerprints exist to force. */
const renewsGrant = (next: NativeGrantScope, prior: NativeGrantScope) =>
  next.host === prior.host &&
  next.purpose === prior.purpose &&
  subset(next.projects, prior.projects) &&
  subset(next.providers, prior.providers);

/** Each native grant replaces its own distinct prior grant: an injective
 * matching where every successor has the same host and purpose as its
 * predecessor, no wider projects or providers, and expires no later than its
 * principal and, unless that principal's own expiry is being extended, no later
 * than that same predecessor. A successor therefore never sits beside the
 * fingerprint it replaces, nor borrows another grant's scope or expiry. */
function grantsRenewed(n: ControlPrincipal, prior: ControlPrincipal, extended: boolean) {
  const next = n.nativeGrants ?? [],
    old = prior.nativeGrants ?? [];
  // A retained fingerprint is pinned to its own predecessor; only a new
  // fingerprint may replace some other grant.
  const retained = (g: NativeGrantScope) =>
    old.some((x) => x.grant === g.grant && x.host === g.host && x.purpose === g.purpose);
  const fits = (g: NativeGrantScope, x: NativeGrantScope) =>
    (!retained(g) || x.grant === g.grant) &&
    renewsGrant(g, x) &&
    (extended || g.expires <= x.expires);
  if (next.some((g) => !n.hosts.includes(g.host) || g.expires > n.expiresAt)) return false;
  // Bipartite matching (augmenting paths); at most 40 grants per principal.
  const owner: (number | undefined)[] = Array.from({ length: old.length });
  const assign = (i: number, seen: Set<number>): boolean => {
    for (let k = 0; k < old.length; k++) {
      if (seen.has(k) || !fits(next[i]!, old[k]!)) continue;
      seen.add(k);
      if (owner[k] === undefined || assign(owner[k]!, seen)) {
        owner[k] = i;
        return true;
      }
    }
    return false;
  };
  return next.every((_g, i) => assign(i, new Set()));
}

/** The single observation grant a principal holds for `host`, if exactly one. */
const soleObservation = (p: ControlPrincipal | undefined, host: string) => {
  const grants = (p?.nativeGrants ?? []).filter(
    (g) => g.host === host && g.purpose === "observation",
  );
  return grants.length === 1 ? grants[0] : undefined;
};
/** Inside the renewal transaction, move each live standing subscription whose
 * observation binding tracks its owner's sole grant for that host (same
 * fingerprint, revision and expiry) to that owner's sole renewed grant. This is
 * the binding the edge derives after it restarts with the renewed policy, so
 * queued callbacks, cursors and receipts keep authorizing without the edge
 * resubmitting anything. Anything ambiguous, expired or inactive is left as is. */
function rebindSubscriptions(
  sql: SqlStorage,
  current: ControlPolicy,
  configured: ControlPolicy,
  now: number,
) {
  let count = 0;
  const rows = sql
    .exec<{
      id: string;
      owner: string;
      host: string;
      binding: string;
      value: string;
      expires: number | null;
    }>("SELECT id,owner,host,binding,value,expires FROM subscriptions WHERE active=1")
    .toArray();
  for (const row of rows) {
    const binding = JSON.parse(row.binding);
    const owner = current.principals.find((p) => p.id === row.owner);
    // Never revive: the subscription, its owner and its binding must all be live.
    if (
      (row.expires !== null && row.expires <= now) ||
      !owner ||
      owner.expiresAt <= now ||
      sql.exec("SELECT id FROM revoked WHERE id=?", owner.id).toArray().length
    )
      continue;
    const before = soleObservation(owner, row.host),
      after = soleObservation(
        configured.principals.find((p) => p.id === row.owner),
        row.host,
      );
    if (
      !before ||
      !after ||
      binding.expires <= now ||
      binding.grant !== before.grant ||
      binding.revision !== before.revision ||
      binding.expires !== before.expires
    )
      continue;
    const next = {
      ...binding,
      grant: after.grant,
      revision: after.revision,
      expires: after.expires,
    };
    const value = JSON.parse(row.value);
    value.binding = next;
    sql.exec(
      "UPDATE subscriptions SET binding=?,value=? WHERE id=?",
      JSON.stringify(next),
      JSON.stringify(value),
      row.id,
    );
    count++;
  }
  return count;
}

/** Can `n` replace `prior` in a renewal? Identity, role and custody stay exactly
 * as they are; hosts, scopes, grants and budgets can only stay or narrow. Only
 * the expiry of an owner or executor may move later, bounded by `ceiling`. */
function renewable(n: ControlPrincipal, prior: ControlPrincipal, now: number, ceiling: number) {
  const budgetsKept = (prior.threadBudgets ?? []).every((old) =>
    (n.threadBudgets ?? []).some(
      (cap) =>
        cap.thread === old.thread &&
        cap.provider === old.provider &&
        cap.maxPerDay <= old.maxPerDay &&
        cap.expiresAt <= old.expiresAt,
    ),
  );
  const budgetsKnown = (n.threadBudgets ?? []).every((cap) =>
    (prior.threadBudgets ?? []).some(
      (old) => cap.thread === old.thread && cap.provider === old.provider,
    ),
  );
  const extended = n.expiresAt > prior.expiresAt;
  return (
    prior.tokenSha256 === n.tokenSha256 &&
    prior.role === n.role &&
    (n.migrationAuthority !== true || prior.migrationAuthority === true) &&
    (n.stateCustodian !== true || prior.stateCustodian === true) &&
    n.hosts.every((h) => prior.hosts.includes(h)) &&
    (n.scopes ?? []).every((scope) =>
      (prior.scopes ?? []).some((old) => JSON.stringify(old) === JSON.stringify(scope)),
    ) &&
    grantsRenewed(n, prior, extended) &&
    budgetsKept &&
    budgetsKnown &&
    (prior.maxPerDay === undefined
      ? n.maxPerDay === undefined
      : prior.maxPerDay === null ||
        (n.maxPerDay !== undefined && n.maxPerDay !== null && n.maxPerDay <= prior.maxPerDay)) &&
    // Migration principals keep their own one-time reauthorization path.
    (!extended || (n.role !== "migration" && n.migrationAuthority !== true)) &&
    // Never revive: only a principal that is still live can be extended, so an
    // expired owner's subscriptions and grants stay fail-closed.
    (!extended || (prior.expiresAt > now && n.expiresAt > now && n.expiresAt <= ceiling))
  );
}

/** Owner-only operator path, not MCP. Adopts the operator-deployed AUTH_POLICY
 * (the independent approval input, as for owner enrollment) as the next durable
 * revision when it renews the current policy: same fleet and principal
 * identities, no new principal, host, scope, role or custody, and native grants
 * renewed only for existing host/purpose pairs. Owner and executor expiries may
 * be extended up to MAX_RENEWAL_MS from now. Authentication, fencing, mutation
 * and receipt share the caller's DO transaction. A principal must renew before
 * it expires: an expired principal can no longer authenticate. */
export function policyRenewal(
  sql: SqlStorage,
  actor: ControlPrincipal,
  current: ControlPolicy,
  configured: ControlPolicy,
  op: string,
  p: Record<string, unknown>,
  now = Date.now(),
) {
  if (!RENEWAL_OPS.includes(op)) return undefined;
  if (actor.role !== "owner") fail("forbidden");
  if (op === "policy_renewal_challenge") {
    if (Object.keys(p).length) fail("invalid_request");
    // Hashes and grant metadata only; the policy holds no credential values.
    return {
      revision: current.revision,
      current_policy_sha256: enrollmentPolicyDigest(current),
      configured_revision: configured.revision,
      configured_policy_sha256: enrollmentPolicyDigest(configured),
      current_policy: current,
    };
  }
  const receiptOnly = op === "policy_renewal_receipt";
  const allowed = receiptOnly
    ? ["request_id"]
    : ["request_id", "expected_revision", "expected_policy_sha256"];
  if (Object.keys(p).some((k) => !allowed.includes(k))) fail("invalid_request");
  const request = identity(p.request_id);
  const prior = sql
    .exec<{ actor: string; subject: string }>(
      "SELECT actor,subject FROM audit WHERE action='renew_configured_policy' AND json_extract(subject,'$.request_id')=?",
      request,
    )
    .toArray()[0];
  // Bound to the credential, not only the ID: an ID dropped and later
  // re-enrolled under another credential cannot read or replay this receipt.
  if (
    prior &&
    (prior.actor !== actor.id || JSON.parse(prior.subject).actor_sha256 !== actor.tokenSha256)
  )
    fail("forbidden");
  if (receiptOnly)
    return prior ? { committed: true, ...JSON.parse(prior.subject) } : { committed: false };
  if (
    !Number.isSafeInteger(p.expected_revision) ||
    typeof p.expected_policy_sha256 !== "string" ||
    !/^[a-f0-9]{64}$/.test(p.expected_policy_sha256)
  )
    fail("invalid_request");
  const input = createHash("sha256")
    .update(JSON.stringify([request, p.expected_revision, p.expected_policy_sha256]))
    .digest("hex");
  if (prior) {
    const receipt = JSON.parse(prior.subject);
    if (receipt.input_sha256 !== input) fail("idempotency_conflict");
    return { committed: true, ...receipt };
  }
  // Only a live service renews. Staging may hold an uploaded recovery import and
  // a freeze compares exact policies: neither may see the policy change under it.
  if (sql.exec<{ mode: string }>("SELECT mode FROM control WHERE id=1").one().mode !== "active")
    fail("fenced");
  const configuredDigest = enrollmentPolicyDigest(configured);
  if (
    p.expected_revision !== current.revision ||
    configured.revision !== current.revision + 1 ||
    p.expected_policy_sha256 !== configuredDigest
  )
    fail("fenced");
  const ceiling = now + MAX_RENEWAL_MS;
  if (
    configured.fleet !== current.fleet ||
    !configured.principals.length ||
    // The initiating owner stays live, so it can reconcile this receipt.
    !configured.principals.some(
      (n) => n.id === actor.id && n.tokenSha256 === actor.tokenSha256 && n.expiresAt > now,
    ) ||
    configured.principals.some((n) => {
      const old = current.principals.find((c) => c.id === n.id);
      return (
        !old ||
        !renewable(n, old, now, ceiling) ||
        (n.expiresAt > old.expiresAt &&
          sql.exec("SELECT id FROM revoked WHERE id=?", n.id).toArray().length > 0)
      );
    })
  )
    fail("forbidden");
  const receipt = {
    request_id: request,
    revision: configured.revision,
    policy_sha256: configuredDigest,
    previous_policy_sha256: enrollmentPolicyDigest(current),
    input_sha256: input,
    actor_sha256: actor.tokenSha256,
    rebound_subscriptions: 0,
  };
  receipt.rebound_subscriptions = rebindSubscriptions(sql, current, configured, now);
  sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(configured));
  sql.exec(
    "INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)",
    actor.id,
    "renew_configured_policy",
    JSON.stringify(receipt),
    now,
  );
  return { committed: true, ...receipt };
}
