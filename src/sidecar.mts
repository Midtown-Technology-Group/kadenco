// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, statSync } from "node:fs";
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
import { diagnosticContext, diagnose } from "./diagnostics.mjs";

export interface SidecarOptions {
  configPath?: string;
  stateKey?: Buffer;
  // Operator-owned startup composition only. Never a remote tool argument,
  // selectable module, credential provider or authorization bypass.
  backendFactory?: (policy: Policy) => Backend | Promise<Backend>;
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

// Importing this module has no process, signal, model or network side effects.
export async function startSidecar(options: SidecarOptions = {}): Promise<Sidecar> {
  const configPath = options.configPath ?? process.env.EDDIE_T3_CONFIG;
  const key =
    options.stateKey ??
    (process.env.EDDIE_T3_STATE_KEY
      ? Buffer.from(process.env.EDDIE_T3_STATE_KEY, "base64")
      : undefined);
  delete process.env.EDDIE_T3_STATE_KEY;
  if (!configPath || !key) throw Error("EDDIE_T3_CONFIG and EDDIE_T3_STATE_KEY required");
  if (key.length !== 32) throw Error("32_byte_state_key_required");
  const policy = () => configSchema.parse(JSON.parse(readFileSync(configPath, "utf8")));
  const config = policy();
  if (process.platform !== "win32" && statSync(config.stateDirectory).mode & 0o077)
    throw Error("state_directory_must_be_private");
  let store: Store | undefined, backend: Backend | undefined, reader: FleetReader | undefined;
  let server: ReturnType<typeof httpServer> | undefined;
  let collaboration: ReturnType<typeof collaborationServer> | undefined;
  let stopped = false,
    inFlight = Promise.resolve(),
    stopping: Promise<void> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const shutdown = () =>
    (stopping ??= (async () => {
      stopped = true;
      clearTimeout(timer);
      collaboration?.stopStreams();
      await Promise.all(
        [server, collaboration].filter(Boolean).map(
          (s) =>
            new Promise<void>((resolve, reject) => {
              if (!s.listening) return resolve();
              s.close((error) => (error ? reject(error) : resolve()));
            }),
        ),
      );
      await inFlight;
      try {
        await reader?.close();
      } finally {
        try {
          await backend?.close();
        } finally {
          store?.close();
        }
      }
    })());
  try {
    backend = await (options.backendFactory ?? projectionBackend)(config);
    store = new Store(config.stateDirectory + "/bridge.db", key);
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
    server = httpServer(bridge);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(config.port ?? 41880, "127.0.0.1", resolve);
    });
    collaboration = config.collaboration?.enabled ? collaborationServer(bridge) : undefined;
    if (collaboration)
      await new Promise<void>((resolve, reject) => {
        collaboration.once("error", reject);
        collaboration.listen(config.collaboration.port, "127.0.0.1", resolve);
      });
    async function cycle(): Promise<void> {
      if (stopped) return;
      try {
        await diagnosticContext("worker", "event_cycle", async () => {
          await diagnose(
            (e) => store.diagnostic(e),
            "relay",
            "worker",
            () => bridge.observe(),
          );
          await bridge.deliver();
          await bridge.fleetEvents.observe();
          await bridge.deliver();
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
    return { address: () => server.address() as AddressInfo | null, shutdown };
  } catch (error) {
    await shutdown();
    throw error;
  }
}
