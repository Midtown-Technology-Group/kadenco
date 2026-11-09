// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
import type { SidecarRuntime } from "../../../dist/sidecar.mjs";
import { composeEdgeRoutes } from "./edge-routes.ts";
import { coordinatorForBridge } from "./coordinator.ts";
import { SqliteJournal } from "./journal.ts";
import {
  observeExisting,
  deliveryPass,
  existingCallback,
  reconcileCallbackReceipts,
} from "./edge-services.ts";
import { openStoreReplica } from "./store-replica.ts";
import { checkpointNativeEffects } from "./effect-checkpoint.ts";
import { isAbsolute } from "node:path";
import { isDeepStrictEqual } from "node:util";
import { randomUUID } from "node:crypto";
export { projectNativeGrant } from "./grant-projection.ts";
export { centralTransport } from "./transport.ts";

export type EdgeRuntimePorts = Omit<Parameters<typeof coordinatorForBridge>[1], "journal"> & {
  executor: string;
  journalPath: string;
  observationBinding: Parameters<typeof observeExisting>[1]["binding"];
  observationOwnerCall: Parameters<typeof observeExisting>[1]["ownerCall"];
  leaseFailure?: (reason: "transport_uncertain" | "fenced" | "refused" | "invalid_lease") => void;
  checkpointFailure?: (
    reason:
      | "transport_uncertain"
      | "central_refused"
      | "state_conflict"
      | "record_limit"
      | "unknown",
  ) => void;
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
  ports = Object.freeze({ ...ports, key: Buffer.from(ports.key) });
  let generation: number | undefined;
  const instance = randomUUID();
  let closed = false;
  let renewal: Promise<void> | undefined;
  const leaseErrors = new WeakSet<object>();
  const refreshLease = () => {
    if (closed) return Promise.reject(Error("edge_runtime_closed"));
    return (renewal ??= (async () => {
      const lease = await ports.executorCall("edge_lease", {
        epoch: ports.epoch,
        instance,
        ...(generation === undefined ? {} : { generation }),
      });
      if (lease.reason !== undefined) {
        ports.leaseFailure?.(lease.reason === "fenced" ? "fenced" : "refused");
        throw Error("edge_lease_unavailable");
      }
      if (
        lease.holder !== ports.executor ||
        lease.instance !== instance ||
        !Number.isSafeInteger(lease.generation) ||
        Number(lease.generation) < 1 ||
        !Number.isSafeInteger(lease.expires) ||
        Number(lease.expires) <= (ports.now ?? Date.now)() ||
        (generation !== undefined && lease.generation !== generation)
      ) {
        ports.leaseFailure?.("invalid_lease");
        throw Error("edge_lease_unavailable");
      }
      generation = Number(lease.generation);
    })()
      .catch((error) => {
        if (error !== null && typeof error === "object") leaseErrors.add(error);
        if (error instanceof Error && error.message === "central_transport_uncertain")
          ports.leaseFailure?.("transport_uncertain");
        throw error;
      })
      .finally(() => {
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
    const rawFlush = replica.flush;
    replica.flush = async () => {
      try {
        await rawFlush();
      } catch (error) {
        const message = error instanceof Error ? error.message : "";
        if (
          message !== "edge_lease_unavailable" &&
          message !== "edge_runtime_closed" &&
          !(error !== null && typeof error === "object" && leaseErrors.has(error))
        )
          ports.checkpointFailure?.(
            message === "central_transport_uncertain"
              ? "transport_uncertain"
              : message === "replica_central_unavailable"
                ? "central_refused"
                : message === "replica_current_state_required"
                  ? "state_conflict"
                  : ["replica_record_exceeds_central_limit", "replica_record_too_large"].includes(
                        message,
                      )
                    ? "record_limit"
                    : "unknown",
          );
        throw error;
      }
    };
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
  let receiptContinuation: string | undefined;
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
            postExisting: existingCallback(
              bridge,
              async () => {
                await replica.flush();
                await refreshLease();
              },
              (subscription, event, binding) => {
                if (!isDeepStrictEqual(binding, ports.observationBinding(subscription, event)))
                  throw Error("forbidden");
              },
            ),
          },
          continuation,
        );
        continuation = pass.next ?? undefined;
        receiptContinuation = await reconcileCallbackReceipts(
          bridge,
          {
            epoch: ports.epoch,
            call: ports.executorCall,
            refreshLease,
          },
          receiptContinuation,
        );
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
