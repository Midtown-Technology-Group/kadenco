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
  /** Monotonic clock for lease expiry (default `performance.now`). */
  monotonicNow?: () => number;
  /** Upper bound on the lease TTL this edge assumes (default 30 s); the Worker-reported ttl_ms is used when smaller. */
  leaseTtlMs?: number;
  /** Lease-only transport. Its deadline must be well under the lease TTL so one
   * slow renewal cannot consume the whole lease; defaults to executorCall. */
  leaseCall?: EdgeRuntimePorts["executorCall"];
  /** Called once when this process's generation is irrecoverably lost (fenced,
   * refused, invalid, or expired while renewals fail). The supervisor should
   * shut down and restart the edge; this process never reacquires a generation. */
  leaseLost?: () => void;
  /** How long startup keeps retrying an effect-free first claim that is fenced
   * by a predecessor's unexpired lease. Default 45 s (lease TTL is 30 s). */
  startupClaimMs?: number;
  /** Central Worker/DO identity read by bootstrap before the runtime starts. */
  centralStatus?: { release_version?: unknown; epoch?: unknown };
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
): Promise<Extract<SidecarRuntime, { mcp: unknown }>> {
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
  // Evidence for the read-only /status endpoint; never consulted for authority.
  // `seq` orders renewal outcomes exactly, even within one millisecond.
  let evidenceSeq = 0;
  const leaseEvidence: {
    renewedAt: number | null;
    renewedSeq: number;
    expires: number | null;
    failure: { reason: string; at: number; seq: number } | null;
    // Last terminal refusal, kept apart so a later transient error cannot mask it.
    terminal: { reason: string; at: number; seq: number } | null;
  } = { renewedAt: null, renewedSeq: 0, expires: null, failure: null, terminal: null };
  const now = () => (ports.now ?? Date.now)();
  // Once this process's generation is irrecoverably lost it never renews
  // again, makes no further central calls or external effects, and tells the
  // operator exactly once. Startup is exempt: it retries a fenced first claim.
  let started = false;
  let lossLatched = false;
  let stopStreamsRef: (() => void) | undefined;
  const latchLoss = () => {
    if (!started || lossLatched) return;
    lossLatched = true;
    stopStreamsRef?.();
    ports.leaseLost?.();
  };
  // Expiry is judged on this process's monotonic clock: renewal request start
  // plus the protocol TTL, so edge/central wall-clock skew cannot stretch (or
  // spuriously shorten) the lease. Central's `expires` is kept for reporting.
  const mono = ports.monotonicNow ?? (() => performance.now());
  // Upper bound on the TTL this edge will assume; the Worker reports the TTL it
  // granted (ttl_ms) and the edge uses the smaller. A Worker that reports none
  // is assumed to grant the historical 10 s.
  const leaseTtlMs = ports.leaseTtlMs ?? 30000;
  const grantedTtl = (lease: Record<string, unknown>) =>
    Number.isSafeInteger(lease.ttl_ms) && Number(lease.ttl_ms) > 0
      ? Math.min(Number(lease.ttl_ms), leaseTtlMs)
      : Math.min(10000, leaseTtlMs);
  let monoDeadline: number | null = null;
  const expired = () => monoDeadline !== null && mono() >= monoDeadline;
  const leaseFailure = (reason: "transport_uncertain" | "fenced" | "refused" | "invalid_lease") => {
    leaseEvidence.failure = { reason, at: now(), seq: ++evidenceSeq };
    if (reason !== "transport_uncertain") leaseEvidence.terminal = leaseEvidence.failure;
    ports.leaseFailure?.(reason);
    if (reason !== "transport_uncertain") latchLoss();
  };
  // One synchronous admission check for every central call and external effect:
  // closed, latched loss, or (after startup) a lease past its expiry. Expiry is
  // checked here, not only by the 2.5 s heartbeat sample.
  const fence = () => {
    if (closed) throw Error("edge_runtime_closed");
    if (lossLatched) throw Error("edge_lease_unavailable");
    if (started && expired()) {
      latchLoss();
      throw Error("edge_lease_unavailable");
    }
  };
  const refreshLease = () => {
    try {
      fence();
    } catch (error) {
      return Promise.reject(error);
    }
    return (renewal ??= (async () => {
      const requestedAt = mono();
      const lease = await (ports.leaseCall ?? ports.executorCall)("edge_lease", {
        epoch: ports.epoch,
        instance,
        ...(generation === undefined ? {} : { generation }),
      });
      // Worker-side forwarding or internal faults say nothing about the lease:
      // treat them as transport uncertainty (non-terminal), not as a refusal.
      if (lease.reason === "forwarding_failed" || lease.reason === "internal_error")
        throw Error("central_transport_uncertain");
      if (lease.reason !== undefined) {
        leaseFailure(lease.reason === "fenced" ? "fenced" : "refused");
        throw Error("edge_lease_unavailable");
      }
      if (
        lease.holder !== ports.executor ||
        lease.instance !== instance ||
        !Number.isSafeInteger(lease.generation) ||
        Number(lease.generation) < 1 ||
        !Number.isSafeInteger(lease.expires) ||
        // Judged on our monotonic clock (request start + TTL), never by comparing
        // central's wall-clock expiry with ours: skew must not reject a valid grant.
        mono() >= requestedAt + grantedTtl(lease) ||
        (generation !== undefined && lease.generation !== generation)
      ) {
        leaseFailure("invalid_lease");
        throw Error("edge_lease_unavailable");
      }
      // The transport may have taken a while: never publish a grant (or release
      // waiting callers) after closure, latched loss, or the prior lease's expiry.
      if (closed) throw Error("edge_runtime_closed");
      if (lossLatched || (started && expired())) {
        latchLoss();
        throw Error("edge_lease_unavailable");
      }
      generation = Number(lease.generation);
      leaseEvidence.renewedAt = now();
      leaseEvidence.renewedSeq = ++evidenceSeq;
      leaseEvidence.expires = Number(lease.expires);
      monoDeadline = requestedAt + grantedTtl(lease);
    })()
      .catch((error) => {
        if (error !== null && typeof error === "object") leaseErrors.add(error);
        if (error instanceof Error && error.message === "central_transport_uncertain")
          leaseFailure("transport_uncertain");
        else if (!(error instanceof Error && error.message === "edge_lease_unavailable"))
          leaseEvidence.failure = { reason: "renewal_error", at: now(), seq: ++evidenceSeq };
        if (expired()) latchLoss();
        throw error;
      })
      .finally(() => {
        renewal = undefined;
      }));
  };
  // Refuse before creating listeners or opening an attempt journal. The first
  // claim has no effects, so a claim fenced by a predecessor's unexpired lease
  // (for example a crashed or restarting process) is retried with the same
  // instance until that lease can expire. Other refusals stop startup at once.
  // The deadline is rechecked after every sleep. A grant already in flight when
  // the deadline passes is accepted: it is a valid lease, and abandoning it
  // would only fence the next start for the rest of its TTL.
  const startupDeadline = performance.now() + Math.max(0, ports.startupClaimMs ?? 45000);
  for (let delay = 500; ; delay = Math.min(delay * 2, 4000)) {
    try {
      await refreshLease();
      break;
    } catch (error) {
      const remaining = startupDeadline - performance.now();
      if (generation !== undefined || leaseEvidence.failure?.reason !== "fenced" || remaining <= 0)
        throw error;
      await new Promise((resolve) => setTimeout(resolve, Math.min(delay, remaining)));
      if (performance.now() >= startupDeadline) throw error;
    }
  }
  started = true;
  // Every central call made from here on (coordinator, observation, delivery,
  // receipts, replica) passes the same synchronous fence first; lease renewals
  // are fenced inside refreshLease.
  const fenced =
    <A extends unknown[], R>(fn: (...args: A) => Promise<R>) =>
    async (...args: A): Promise<R> => {
      fence();
      return fn(...args);
    };
  ports = Object.freeze({
    ...ports,
    executorCall: fenced(ports.executorCall),
    ownerCall: fenced(ports.ownerCall),
    observationOwnerCall: fenced(ports.observationOwnerCall),
  });
  // Synchronous last check at external send points (native dispatch, followup,
  // settings, webhook POST): the same fence, reported as lease unavailability.
  bridge.effectGuard = () => {
    try {
      fence();
    } catch {
      throw Error("edge_lease_unavailable");
    }
  };
  const central = {
    release_version:
      typeof ports.centralStatus?.release_version === "string"
        ? ports.centralStatus.release_version
        : null,
    epoch: Number.isSafeInteger(ports.centralStatus?.epoch)
      ? Number(ports.centralStatus!.epoch)
      : null,
    observed_at: new Date(now()).toISOString(),
  };
  bridge.runtimeStatus = () => {
    const { renewedAt, renewedSeq, expires, failure, terminal } = leaseEvidence;
    const failedLast = failure !== null && failure.seq > renewedSeq;
    const terminalLast = terminal !== null && terminal.seq > renewedSeq;
    const shown = terminalLast ? terminal : failure;
    // Expiry is loss even while a renewal is still pending with no failure yet.
    const isExpired = expired();
    const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());
    return {
      mode: "central_edge",
      central,
      lease: {
        // A fenced/refused generation is never reacquired by this process; a
        // transport failure is "renewal_failing" until the lease expiry passes.
        state:
          closed || lossLatched || terminalLast || isExpired
            ? "lost"
            : failedLast
              ? "renewal_failing"
              : renewedAt !== null
                ? "held"
                : "unknown",
        generation: generation ?? null,
        last_renewed_at: iso(renewedAt),
        expires_at: iso(expires),
        // Report the terminal refusal while it is still in force.
        last_failure: shown ? { reason: shown.reason, at: new Date(shown.at).toISOString() } : null,
      },
    };
  };
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
    restoreEffects = checkpointNativeEffects(
      bridge,
      async () => {
        await replica.flush();
        await refreshLease();
      },
      () => bridge.effectGuard?.(),
    );
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
  stopStreamsRef = stopStreams;
  Object.assign(routes.collaboration.server, { stopStreams });
  // Native reads can take longer than a lease. Renew independently of the
  // observation cycle; a blocked JS event loop still correctly loses its lease.
  const heartbeat = setInterval(() => {
    // A renewal still in flight past expiry is loss too (see latchLoss).
    if (expired()) latchLoss();
    // A transient failure must not stop collaboration permanently: latchLoss
    // stops streams on real loss, and each streaming request re-checks the
    // lease itself every second.
    void refreshLease().catch(() => {});
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
        // After loss nothing may reach central: the queued replica state stays
        // local (with the attempt journal) for the next lease holder to reconcile.
        if (!lossLatched) await replica.flush();
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
