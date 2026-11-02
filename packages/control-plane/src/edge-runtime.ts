// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
import type { SidecarRuntime } from "../../../dist/sidecar.mjs";
import { composeEdgeRoutes } from "./edge-routes.ts";
import { coordinatorForBridge } from "./coordinator.ts";
import { SqliteJournal } from "./journal.ts";
import { observeExisting, deliveryPass, existingCallback } from "./edge-services.ts";
import { openStoreReplica } from "./store-replica.ts";
import { checkpointNativeEffects } from "./effect-checkpoint.ts";
import { isAbsolute } from "node:path";

export type EdgeRuntimePorts = Omit<Parameters<typeof coordinatorForBridge>[1], "journal"> & {
  executor: string;
  journalPath: string;
  observationBinding: Parameters<typeof observeExisting>[1]["binding"];
  observationOwnerCall: Parameters<typeof observeExisting>[1]["ownerCall"];
};

/** Executable composition of the original relay, not a second scheduler. The
 * sidecar owns listener/timer lifetime; this runtime replaces its local loop.
 * Bootstrap must supply reviewed identity/grant resolvers and existing secrets.
 * Losing a lease never silently acquires a new generation in this process. */
export async function createEdgeRuntime(
  bridge: Bridge,
  ports: EdgeRuntimePorts,
): Promise<SidecarRuntime> {
  if (
    !Number.isSafeInteger(ports.epoch) ||
    ports.epoch < 1 ||
    !ports.executor ||
    !Buffer.isBuffer(ports.key) ||
    ports.key.length !== 32 ||
    typeof ports.journalPath !== "string" ||
    !isAbsolute(ports.journalPath)
  )
    throw Error("invalid_edge_identity");
  let generation: number | undefined;
  let closed = false;
  let renewal: Promise<void> | undefined;
  const refreshLease = () => {
    if (closed) return Promise.reject(Error("edge_runtime_closed"));
    return (renewal ??= (async () => {
      const lease = await ports.executorCall("edge_lease", {
        epoch: ports.epoch,
        ...(generation === undefined ? {} : { generation }),
      });
      if (
        lease.holder !== ports.executor ||
        !Number.isSafeInteger(lease.generation) ||
        Number(lease.generation) < 1 ||
        !Number.isSafeInteger(lease.expires) ||
        Number(lease.expires) <= (ports.now ?? Date.now)() ||
        (generation !== undefined && lease.generation !== generation)
      )
        throw Error("edge_lease_unavailable");
      generation = Number(lease.generation);
    })().finally(() => {
      renewal = undefined;
    }));
  };
  // Refuse before creating listeners or opening an attempt journal.
  await refreshLease();
  const journal = new SqliteJournal(ports.journalPath, ports.key);
  let routes: ReturnType<typeof composeEdgeRoutes>;
  let replica: Awaited<ReturnType<typeof openStoreReplica>>;
  let restoreEffects: (() => void) | undefined;
  try {
    replica = await openStoreReplica(bridge.store, ports.epoch, async (op, p) => {
      await refreshLease();
      return ports.executorCall(op, { ...p, epoch: ports.epoch, generation });
    });
    restoreEffects = checkpointNativeEffects(bridge, async () => {
      await replica.flush();
      await refreshLease();
    });
    const coordinate = coordinatorForBridge(bridge, { ...ports, journal });
    routes = composeEdgeRoutes(
      bridge,
      async () => {
        await refreshLease();
        await replica.flush();
      },
      undefined,
      (kind, owner, input, execute) =>
        coordinate(kind, owner, input, async () => {
          await refreshLease();
          return execute();
        }),
      replica.flush,
    );
  } catch (error) {
    restoreEffects?.();
    journal.close();
    throw error;
  }
  const stopStreams = () => routes.collaboration.inner.stopStreams();
  Object.assign(routes.collaboration.server, { stopStreams });
  // Native reads can take longer than a lease. Renew independently of the
  // observation cycle; a blocked JS event loop still correctly loses its lease.
  const heartbeat = setInterval(() => {
    void refreshLease().catch(() => {
      stopStreams();
    });
  }, 2500);
  heartbeat.unref();
  let cycling = false;
  let continuation: string | undefined;
  return {
    mcp: routes.mcp.server,
    collaboration: routes.collaboration.server,
    async cycle() {
      if (closed || cycling) throw Error("edge_cycle_unavailable");
      cycling = true;
      try {
        await observeExisting(bridge, {
          epoch: ports.epoch,
          refreshLease,
          ownerCall: ports.observationOwnerCall,
          executorCall: ports.executorCall,
          binding: ports.observationBinding,
        });
        await refreshLease();
        const pass = await deliveryPass(
          {
            epoch: ports.epoch,
            call: async (op, p) => {
              await refreshLease();
              return ports.executorCall(op, p);
            },
            postExisting: existingCallback(bridge, async () => {
              await replica.flush();
              await refreshLease();
            }),
          },
          continuation,
        );
        continuation = pass.next ?? undefined;
        await replica.flush();
      } finally {
        cycling = false;
      }
    },
    async close() {
      if (closed) return;
      stopStreams();
      try {
        await replica.flush();
      } finally {
        closed = true;
        clearInterval(heartbeat);
        await renewal?.catch(() => {});
        restoreEffects?.();
        journal.close();
      }
    },
  };
}
