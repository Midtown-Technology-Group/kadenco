// SPDX-License-Identifier: AGPL-3.0-or-later
import { configSchema, type Policy } from "../../../dist/config.mjs";
import { projectNativeGrant } from "./grant-projection.ts";
import { enrollmentPolicyDigest, type ControlPolicy } from "./owner-enrollment.ts";
import { MAX_CONTROL_PRINCIPALS, MAX_NATIVE_GRANTS_PER_PRINCIPAL } from "./policy-limits.ts";
/** Offline preparation only. Takes a separately custodied credential HASH;
 * never creates credentials, writes policy, contacts hosts or dispatches work. */
export function prepareOwnerEnrollment(input: {
  local: Policy;
  central: ControlPolicy;
  sponsor: string;
  principal: string;
  tokenSha256: string;
  executor: string;
  expiresAt: number;
  requestId: string;
}) {
  const { sponsor, principal, tokenSha256, executor, expiresAt, requestId } = input;
  const local = configSchema.parse(structuredClone(input.local));
  const central = structuredClone(input.central);
  const source = local.principals.find((p) => p.id === sponsor && p.enabled !== false);
  const owner = central.principals.find((p) => p.id === sponsor && p.role === "owner");
  const worker = central.principals.find((p) => p.id === executor && p.role === "executor");
  if (
    !source ||
    source.eddieCaller ||
    source.eddieHostCaller ||
    !owner ||
    !worker ||
    owner.tokenSha256 !== source.tokenSha256 ||
    !/^[a-zA-Z0-9_-]{1,100}$/.test(principal) ||
    !/^[a-f0-9]{64}$/.test(tokenSha256) ||
    !/^[a-zA-Z0-9_-]{1,100}$/.test(requestId) ||
    !Number.isSafeInteger(expiresAt) ||
    expiresAt <= Date.now() ||
    expiresAt > owner.expiresAt ||
    expiresAt > worker.expiresAt ||
    owner.hosts.some((h) => !worker.hosts.includes(h)) ||
    local.principals.some((p) => p.id === principal || p.tokenSha256 === tokenSha256) ||
    central.principals.some((p) => p.id === principal || p.tokenSha256 === tokenSha256)
  )
    throw Error("owner_enrollment_preparation_forbidden");
  if (
    central.principals.length + 1 > MAX_CONTROL_PRINCIPALS ||
    (worker.nativeGrants?.length ?? 0) + (owner.nativeGrants?.length ?? 0) >
      MAX_NATIVE_GRANTS_PER_PRINCIPAL
  )
    throw Error("owner_enrollment_capacity_exceeded");
  local.principals.push({ ...structuredClone(source), id: principal, tokenSha256 });
  // Limits and modes are copied exactly, including any explicit uncapped budget.
  // Expiry is an additional central ceiling, never an extension of native grants.
  const nativeGrants = (owner.nativeGrants ?? []).map((g) => {
    const projected = projectNativeGrant(local, principal, g.host, g.purpose, expiresAt);
    if (
      projected.revision !== g.revision ||
      JSON.stringify(projected.projects) !== JSON.stringify(g.projects) ||
      JSON.stringify(projected.providers) !== JSON.stringify(g.providers)
    )
      throw Error("owner_enrollment_scope_drift");
    return { ...projected, expires: Math.min(projected.expires, g.expires, expiresAt) };
  });
  const target = { ...structuredClone(owner), id: principal, tokenSha256, expiresAt, nativeGrants };
  delete target.migrationAuthority;
  delete target.stateCustodian;
  central.principals.push(target);
  worker.nativeGrants = [...(worker.nativeGrants ?? []), ...nativeGrants];
  central.revision++;
  return {
    local: configSchema.parse(local),
    central,
    admission: {
      request_id: requestId,
      principal_id: principal,
      executor_id: executor,
      expected_revision: input.central.revision,
      expected_policy_sha256: enrollmentPolicyDigest(central),
    },
    activation_permitted: false as const,
  };
}
