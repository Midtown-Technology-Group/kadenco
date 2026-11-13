// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, statSync } from "node:fs";
import { monitorEventLoopDelay } from "node:perf_hooks";
import { SynchronousTimings } from "./synchronous-timings.mjs";
import type { AddressInfo } from "node:net";
import type { Backend } from "./contracts.mjs";
import type { Policy } from "./config.mjs";
import { configSchema } from "./config.mjs";
import { Store } from "./store.mjs";
import { Bridge } from "./bridge.mjs";
import { postWebhook } from "./webhook.mjs";
import { httpServer } from "./server.mjs";
import { localSource } from "./local-source.mjs";
import { fleetReader, type FleetReader } from "./fleet-read.mjs";
import { Commands } from "./commands.mjs";
import { withFleetSessions } from "./fleet-source.mjs";
import { collaborationServer } from "./collaboration-http.mjs";
import { diagnosticContext, diagnoseWorkerCycle } from "./diagnostics.mjs";
import type { Server } from "node:http";

/** Trusted embedding boundary. A runtime owns both HTTP admission and the only
 * observation/delivery loop; it cannot accidentally run alongside local delivery. */
export type SidecarRuntime = {
  collaboration?: Server & { stopStreams?: () => void };
  cycle(): Promise<void>;
  close(): Promise<void>;
} & ({ mcp: Server; outboundOnly?: false } | { mcp?: never; outboundOnly: true });

export interface SidecarOptions {
  configPath?: string;
  stateKey?: Buffer;
  // Operator-owned startup composition only. Never a remote tool argument,
  // selectable module, credential provider or authorization bypass.
  backendFactory?: (policy: Policy) => Backend | Promise<Backend>;
  runtimeFactory?: (bridge: Bridge) => SidecarRuntime | Promise<SidecarRuntime>;
  // Trusted embedding validation runs on every policy read, including before
  // opening the writable Store. It cannot replace or relax config validation.
  validatePolicy?: (policy: Policy) => void;
}
export interface Sidecar {
  address(): AddressInfo | null;
  shutdown(): Promise<void>;
}
function projectionBackend(config: Policy): Backend {
  if (!config.source || config.localClient || config.fleetHelperPath)
    throw Error(
      "Public profile requires local-projection source; private helper profiles are not bundled",
    );
  return localSource(config.source.databasePath);
}

// Preserve the embedding API's fallback across retries/restarts without leaving
// the raw key in the environment inherited by SSH/native helper children.
let environmentKey: Buffer | undefined;

// Importing this module has no process, signal, model or network side effects.
export async function startSidecar(options: SidecarOptions = {}): Promise<Sidecar> {
  const configPath = options.configPath ?? process.env.EDDIE_T3_CONFIG;
  if (process.env.EDDIE_T3_STATE_KEY !== undefined)
    environmentKey = Buffer.from(process.env.EDDIE_T3_STATE_KEY, "base64");
  delete process.env.EDDIE_T3_STATE_KEY;
  const key = options.stateKey ?? environmentKey;
  if (!configPath || !key) throw Error("EDDIE_T3_CONFIG and EDDIE_T3_STATE_KEY required");
  if (key.length !== 32) throw Error("32_byte_state_key_required");
  const synchronous = new SynchronousTimings();
  const policy = () =>
    synchronous.measure("policy", () => {
      const value = configSchema.parse(JSON.parse(readFileSync(configPath, "utf8")));
      options.validatePolicy?.(value);
      return value;
    });
  const config = policy();
  if (process.platform !== "win32" && statSync(config.stateDirectory).mode & 0o077)
    throw Error("state_directory_must_be_private");
  let store: Store | undefined, backend: Backend | undefined, reader: FleetReader | undefined;
  let server: Server | undefined;
  let collaboration: SidecarRuntime["collaboration"];
  let runtime: SidecarRuntime | undefined;
  let stopped = false,
    inFlight = Promise.resolve(),
    stopping: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const eventLoop = monitorEventLoopDelay({ resolution: 20 });
  const shutdown = () =>
    (stopping ??= (async () => {
      stopped = true;
      clearTimeout(timer);
      eventLoop.disable();
      const errors: unknown[] = [];
      try {
        collaboration?.stopStreams?.();
      } catch (error) {
        errors.push(error);
      }
      const listeners = await Promise.allSettled(
        [server, collaboration].filter(Boolean).map(
          (s) =>
            new Promise<void>((resolve, reject) => {
              if (!s.listening) return resolve();
              s.close((error) => (error ? reject(error) : resolve()));
            }),
        ),
      );
      for (const result of listeners) if (result.status === "rejected") errors.push(result.reason);
      try {
        await inFlight;
      } catch (error) {
        errors.push(error);
      }
      for (const close of [
        () => runtime?.close(),
        () => reader?.close(),
        () => backend?.close(),
        () => store?.close(),
      ])
        try {
          await close();
        } catch (error) {
          errors.push(error);
        }
      if (errors.length) throw new AggregateError(errors, "sidecar shutdown failed");
    })());
  try {
    backend = await (options.backendFactory ?? projectionBackend)(config);
    store = new Store(config.stateDirectory + "/bridge.db", key);
    synchronous.wrap(store, "store", [
      "get",
      "all",
      "put",
      "insert",
      "audit",
      "diagnostic",
      "transaction",
    ]);
    synchronous.wrap(backend, "backend", ["read"]);
    reader = config.fleetRead ? await fleetReader(policy, store) : undefined;
    if (config.source) backend = withFleetSessions(backend, reader, policy);
    const bridge = new Bridge({
      store,
      backend,
      policy,
      post: (url, headers, body) => postWebhook(url, headers, body, policy().callbackHosts),
    });
    if (reader) bridge.fleetReads = reader;
    if (config.nativeDelivery) bridge.commands = new Commands({ policy, store, reader });
    runtime = await options.runtimeFactory?.(bridge);
    if (options.runtimeFactory && !runtime) throw Error("runtime_required");
    if (runtime && config.collaboration?.enabled && !runtime.collaboration)
      throw Error("runtime_collaboration_required");
    server = runtime ? runtime.mcp : httpServer(bridge);
    if (!server && runtime?.outboundOnly !== true) throw Error("runtime_listener_required");
    if (server) {
      const listener = server;
      await new Promise<void>((resolve, reject) => {
        listener.once("error", reject);
        listener.listen(config.port ?? 41880, "127.0.0.1", resolve);
      });
    }
    collaboration = config.collaboration?.enabled
      ? runtime
        ? runtime.collaboration
        : collaborationServer(bridge)
      : undefined;
    if (collaboration)
      await new Promise<void>((resolve, reject) => {
        collaboration.once("error", reject);
        collaboration.listen(config.collaboration.port, "127.0.0.1", resolve);
      });
    eventLoop.enable();
    async function cycle(): Promise<void> {
      if (stopped) return;
      try {
        await diagnosticContext("worker", "event_cycle", async () => {
          await diagnoseWorkerCycle(
            (e) => store.diagnostic(e),
            eventLoop,
            async () => {
              if (runtime) return runtime.cycle();
              await bridge.observe();
              await bridge.deliver();
              await bridge.fleetEvents.observe();
              await bridge.deliver();
            },
            () => synchronous.take(),
          );
        });
      } catch {
        store.audit("worker.cycle", "bridge", "failed");
      }
      if (!stopped)
        timer = setTimeout(
          () => {
            inFlight = cycle();
          },
          Math.max(5000, config.pollMs ?? 10000),
        );
    }
    inFlight = cycle();
    return { address: () => (server?.address() as AddressInfo | null) ?? null, shutdown };
  } catch (error) {
    try {
      await shutdown();
    } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "sidecar startup and cleanup failed", {
        cause: error,
      });
    }
    throw error;
  }
}
