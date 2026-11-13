// SPDX-License-Identifier: AGPL-3.0-or-later
import { startSidecar, type SidecarOptions } from "../../../dist/sidecar.mjs";
import type { Policy } from "../../../dist/config.mjs";
import type { Bridge } from "../../../dist/bridge.mjs";
import { createHostLocalRuntime } from "./host-observation.ts";
import { cachePolicyGuard } from "./production-startup.ts";

/** Validate every policy reload, before opening state or constructing a native
 * adapter. Host names are original configured identities, never aliases. */
export function hostLocalPolicyGuard(host: string) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(host)) throw Error("invalid_host_identity");
  return (policy: Policy) => {
    if (
      policy.collaboration?.enabled ||
      policy.fleetHelperPath ||
      policy.sessions.some((s) => s.host !== host) ||
      policy.fleetRead?.hosts.some((h) => h.name !== host) ||
      policy.nativeDelivery?.hosts.some((h) => h.name !== host || h.ssh !== undefined) ||
      policy.principals.some((p) =>
        [...(p.readHosts ?? []), ...(p.commandHosts ?? [])].some((g) => g.host !== host),
      )
    )
      throw Error("host_local_policy_required");
  };
}

/** Explicit operator entry in the existing sidecar lifecycle. No listener,
 * second scheduler, credential discovery, registration or singleton fallback.
 * The embedding must supply its reviewed authenticated transports, current
 * grant resolver and durable checkpoint. This API does not provision them. */
export async function startHostLocalSidecar(input: {
  enabled: boolean;
  host: string;
  configPath: string;
  historicalStateDirectory: string;
  cacheStateDirectory: string;
  stateKey: Buffer;
  backendFactory: NonNullable<SidecarOptions["backendFactory"]>;
  ports(bridge: Bridge): Promise<Parameters<typeof createHostLocalRuntime>[1]>;
}) {
  if (input.enabled !== true) throw Error("host_runtime_disabled");
  const host = input.host;
  const hostGuard = hostLocalPolicyGuard(host);
  const cacheGuard = cachePolicyGuard(input.historicalStateDirectory, input.cacheStateDirectory);
  return startSidecar({
    configPath: input.configPath,
    stateKey: input.stateKey,
    backendFactory: input.backendFactory,
    validatePolicy(policy) {
      cacheGuard(policy);
      hostGuard(policy);
    },
    async runtimeFactory(bridge) {
      const ports = await input.ports(bridge);
      if (ports.host !== host || ports.store !== bridge.store || ports.enabled !== true)
        throw Error("host_runtime_identity_mismatch");
      const runtime = createHostLocalRuntime(bridge, ports);
      return {
        outboundOnly: true,
        async cycle() {
          await runtime.cycle();
        },
        async close() {
          runtime.close();
        },
      };
    },
  });
}
