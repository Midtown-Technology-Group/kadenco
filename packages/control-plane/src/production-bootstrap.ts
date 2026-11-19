// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { Bridge } from "../../../dist/bridge.mjs";
import type { Policy } from "../../../dist/config.mjs";
import type { NativeGrantScope, OperationBinding } from "./binding.ts";
import { isAbsolute } from "node:path";
import { createEdgeRuntime } from "./edge-runtime.ts";
import { centralTransport } from "./transport.ts";
import { projectNativeGrant } from "./grant-projection.ts";
import { existingBindings } from "./existing-bindings.ts";
import { diagnosticIdentity } from "../../../dist/diagnostics.mjs";
import type { ControlPolicy } from "./owner-enrollment.ts";
export type BootstrapConfig = {
  fleet: string;
  origin: string;
  epoch: number;
  executor: string;
  executorToken: string;
  ownerTokens: ReadonlyMap<string, string>;
  observationOwner: string;
  serviceExpiresAt: number;
  key: Buffer;
  journalPath: string;
  fetch?: typeof fetch;
  leaseFailure?: import("./edge-runtime.ts").EdgeRuntimePorts["leaseFailure"];
  leaseLost?: import("./edge-runtime.ts").EdgeRuntimePorts["leaseLost"];
  checkpointFailure?: import("./edge-runtime.ts").EdgeRuntimePorts["checkpointFailure"];
};
const hash = (value: string) => createHash("sha256").update(value).digest("hex");
/** Read-only central diagnostics for MCP tools. They run long after bootstrap,
 * so each call first passes the edge runtime's synchronous lease fence
 * (`bridge.effectGuard`): an MCP request admitted before loss makes no central
 * call after it. */
export function diagnosticHooks(
  bridge: Pick<Bridge, "effectGuard">,
  ownerCall: (owner: string, op: string, body: object) => Promise<Record<string, unknown>>,
  epoch: number,
) {
  return {
    deliveryHistory: async (owner: string, id: string, after: number, limit: number) => {
      bridge.effectGuard?.();
      return ownerCall(owner, "outbox_history", {
        epoch,
        id,
        after_sequence: after,
        limit,
      });
    },
    relayDiagnosticAccess: async (owner: string) => {
      bridge.effectGuard?.();
      const current = await ownerCall(owner, "status", {});
      if (current.reason === "forbidden")
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
      if (current.mode !== "active" || current.epoch !== epoch)
        throw Object.assign(Error("source_unavailable"), {
          reason: "source_unavailable",
        });
    },
  };
}
function ownedCredentials(policy: Policy, config: BootstrapConfig) {
  const owners = new Map(config.ownerTokens);
  if (
    !owners.size ||
    !owners.has(config.observationOwner) ||
    !Number.isSafeInteger(config.serviceExpiresAt) ||
    config.serviceExpiresAt <= Date.now()
  )
    throw Error("bootstrap_owner_configuration_required");
  for (const [owner, token] of owners) {
    const p = policy.principals.find((p) => p.id === owner && p.enabled !== false);
    if (
      !p ||
      p.eddieCaller ||
      p.eddieHostCaller ||
      !token ||
      token.length > 8192 ||
      /[\r\n]/.test(token) ||
      hash(token) !== p.tokenSha256
    )
      throw Error("bootstrap_owner_identity_mismatch");
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(config.executor) ||
    policy.principals.some((p) => p.id === config.executor) ||
    !config.executorToken ||
    config.executorToken.length < 32 ||
    config.executorToken.length > 8192 ||
    /[\r\n]/.test(config.executorToken) ||
    policy.principals.some((p) => p.tokenSha256 === hash(config.executorToken))
  )
    throw Error("bootstrap_executor_identity_mismatch");
  return owners;
}
/** Offline hash-only projection for the reviewed Worker secret. This does not
 * provision credentials, install policy or activate anything. Original caller
 * principals stay behind their existing edge roles, never central owner roles. */
export function projectControlPolicy(policy: Policy, config: BootstrapConfig) {
  const owners = ownedCredentials(policy, config);
  const all: NativeGrantScope[] = [];
  const principals = [...owners.keys()].map((owner) => {
    const p = policy.principals.find((p) => p.id === owner)!;
    const grants: NativeGrantScope[] = [];
    for (const g of p.readHosts ?? [])
      grants.push(
        projectNativeGrant(policy, owner, g.host, "observation", config.serviceExpiresAt),
      );
    for (const g of p.commandHosts ?? []) {
      if (g.codexExceptions?.some((e) => !g.providerInstanceIds.includes(e.providerInstanceId)))
        throw Error("legacy_provider_exception_mapping_required");
      const s = projectNativeGrant(policy, owner, g.host, "command");
      grants.push({
        ...s,
        expires: Math.min(s.expires, config.serviceExpiresAt),
      });
    }
    const caps = new Set((p.commandHosts ?? []).map((g) => g.maxPerDay));
    if (caps.size > 1) throw Error("heterogeneous_host_budget_mapping_required");
    all.push(...grants);
    return {
      id: owner,
      role: "owner" as const,
      tokenSha256: p.tokenSha256,
      hosts: [...new Set(grants.map((g) => g.host))],
      nativeGrants: grants,
      scopes: [] as OperationBinding[],
      ...(caps.size ? { maxPerDay: [...caps][0] } : {}),
      expiresAt: config.serviceExpiresAt,
    };
  });
  const dedup = new Map(all.map((s) => [JSON.stringify([s.host, s.purpose, s.grant]), s]));
  return {
    revision: 1,
    fleet: config.fleet,
    principals: [
      ...principals,
      {
        id: config.executor,
        role: "executor" as const,
        stateCustodian: true,
        tokenSha256: hash(config.executorToken),
        hosts: [...new Set(all.map((s) => s.host))],
        nativeGrants: [...dedup.values()],
        scopes: [] as OperationBinding[],
        expiresAt: config.serviceExpiresAt,
      },
    ],
  };
}
/** Offline: the next revision of the CURRENT central policy (from the owner's
 * `policy_renewal_challenge`) for `renew_configured_policy`. The configured
 * owners' and executor's hosts and native grants are re-projected from the
 * validated local policy, and their expiry becomes `config.serviceExpiresAt`.
 * Every other field, and every other principal, is kept exactly as it is. The
 * Worker re-checks that the result only renews; this makes no credential. */
export function projectRenewalPolicy(
  current: ControlPolicy,
  policy: Policy,
  config: BootstrapConfig,
): ControlPolicy {
  const projected = projectControlPolicy(policy, config);
  // The executor's grants are rebuilt from the projected owners alone, so an
  // enrolled owner left out would keep authority the executor can no longer claim.
  if (
    current.principals.some(
      (p) => p.role === "owner" && !projected.principals.some((n) => n.id === p.id),
    )
  )
    throw Error("renewal_owner_omitted");
  for (const n of projected.principals) {
    const old = current.principals.find((p) => p.id === n.id);
    if (!old || old.tokenSha256 !== n.tokenSha256 || old.role !== n.role)
      throw Error("renewal_identity_mismatch");
    // Dedicated verification scopes are capped at the old ceiling and are kept
    // unchanged, while the restarted edge would bind them at the new one. Let
    // them expire (or re-prepare them) first rather than break them silently.
    if ((old.scopes ?? []).some((s) => s.expires > Date.now()))
      throw Error("renewal_live_verification_scope");
  }
  return {
    ...current,
    revision: current.revision + 1,
    principals: current.principals.map((old) => {
      const n = projected.principals.find((p) => p.id === old.id);
      return n
        ? {
            ...old,
            // Keep verification-only hosts (no native grants); drop hosts whose
            // grants are no longer projected.
            hosts: old.hosts.filter(
              (h) => n.hosts.includes(h) || !(old.nativeGrants ?? []).some((g) => g.host === h),
            ),
            nativeGrants: n.nativeGrants,
            expiresAt: n.expiresAt,
          }
        : old;
    }),
  };
}
/** Exact verification scopes are derived through the original dedicated-session
 * grant and a read-only source preflight. Arbitrary binding objects are refused
 * by omission: the caller supplies only the intended existing-session request. */
export async function projectVerificationPolicy(
  bridge: Bridge,
  config: BootstrapConfig,
  requests: {
    owner: string;
    session_id: string;
    run_id: string;
    request_id: string;
  }[],
) {
  if (!Array.isArray(requests) || requests.length > 50) throw Error("verification_scope_limit");
  const before = JSON.stringify(bridge.policy());
  const policy = projectControlPolicy(bridge.policy(), config);
  const resolver = existingBindings(bridge, config);
  const executor = policy.principals.find((p) => p.id === config.executor)!;
  for (const request of requests) {
    const owner = policy.principals.find((p) => p.id === request.owner && p.role === "owner");
    if (!owner) throw Error("verification_owner_unmapped");
    const { envelope: e } = await resolver.bind("verify_result", request.owner, {
      session_id: request.session_id,
      run_id: request.run_id,
      request_id: request.request_id,
      action: "verify_result",
    });
    const scope = {
      project: e.project,
      provider: e.provider,
      run: e.run,
      grant: e.grant,
      revision: e.revision,
      expires: e.expires,
    };
    owner.scopes.push(scope);
    executor.scopes.push(scope);
    owner.hosts = [...new Set([...owner.hosts, e.host])];
    executor.hosts = [...new Set([...executor.hosts, e.host])];
  }
  if (before !== JSON.stringify(bridge.policy())) throw Error("policy_changed_during_projection");
  return policy;
}
/** Trusted operator composition only. Existing owner credentials must match the
 * original principal hash; there is no broader-caller fallback or raw MCP proxy.
 * Inputs are captured before the first await to prevent identity rebinding. */
export async function createProductionRuntime(bridge: Bridge, input: BootstrapConfig) {
  if (
    !Buffer.isBuffer(input.key) ||
    input.key.length !== 32 ||
    !Number.isSafeInteger(input.epoch) ||
    input.epoch < 1 ||
    typeof input.journalPath !== "string" ||
    !isAbsolute(input.journalPath)
  )
    throw Error("bootstrap_runtime_configuration_required");
  const config = Object.freeze({
    ...input,
    ownerTokens: new Map(input.ownerTokens),
    key: Buffer.from(input.key),
  });
  const owners = ownedCredentials(bridge.policy(), config);
  const diagnostic =
    (principal_id: string) => (record: import("./transport.ts").CentralDiagnostic) => {
      const caller = diagnosticIdentity();
      bridge.store.diagnostic({
        at: new Date().toISOString(),
        host: "@central_http",
        kind: "central_http",
        principal_id,
        initiator_id: caller?.principal_id ?? null,
        parent_correlation_id: caller?.correlation_id ?? null,
        ...record,
      });
    };
  const ownerCalls = new Map(
    [...owners].map(([owner, token]) => [
      owner,
      centralTransport({
        origin: config.origin,
        token: () => token,
        fetch: config.fetch,
        diagnostic: diagnostic(owner),
      }),
    ]),
  );
  const executorCall = centralTransport({
    origin: config.origin,
    token: () => config.executorToken,
    fetch: config.fetch,
    diagnostic: diagnostic(config.executor),
  });
  // Lease renewals get an 8 s deadline, well under the 120 s lease TTL; the
  // heartbeat retries every 2.5 s, so a hung request never consumes the lease
  // and renewals keep retrying through an upstream network drop.
  const leaseCall = centralTransport({
    origin: config.origin,
    token: () => config.executorToken,
    fetch: config.fetch,
    timeoutMs: 8000,
    diagnostic: diagnostic(config.executor),
  });
  const ownerCall = (owner: string, op: string, body: object) => {
    const token = owners.get(owner),
      p = bridge.policy().principals.find((p) => p.id === owner && p.enabled !== false);
    if (!token || !p || p.eddieCaller || p.eddieHostCaller || hash(token) !== p.tokenSha256)
      throw Error("bootstrap_owner_identity_changed");
    return ownerCalls.get(owner)!(op, body);
  };
  const status = await executorCall("status", {});
  if (status.mode !== "active" || status.epoch !== config.epoch)
    throw Error("central_activation_required");
  // Read-only, before any claim: never let this edge displace a live
  // predecessor through a Worker that ignores process-instance leases.
  if (!Array.isArray(status.capabilities) || !status.capabilities.includes("edge_lease_instance"))
    throw Error("central_lease_capability_required");
  Object.assign(bridge, diagnosticHooks(bridge, ownerCall, config.epoch));
  const resolvers = existingBindings(bridge, config);
  return createEdgeRuntime(bridge, {
    ...resolvers,
    epoch: config.epoch,
    executor: config.executor,
    key: config.key,
    journalPath: config.journalPath,
    ownerCall,
    executorCall,
    leaseCall,
    leaseFailure: config.leaseFailure,
    leaseLost: config.leaseLost,
    centralStatus: status,
    checkpointFailure: config.checkpointFailure,
    observationOwnerCall: (op, p) => ownerCall(config.observationOwner, op, p),
  });
}
