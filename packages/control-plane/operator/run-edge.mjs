// SPDX-License-Identifier: AGPL-3.0-or-later
// Trusted supervisor entry point. Arguments contain only a configuration path;
// secrets arrive once on private stdin, never argv or a persistent JSON file.
import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { homedir } from "node:os";
import { startupFailure, failureReporter } from "./startup-failure.mjs";
import { exitController } from "./exit-controller.mjs";

let sidecar, stateKey, starting;
// Signals and lease loss share one bounded exit; lease loss (75) wins. Loss can
// arrive while startup is still unwinding: wait for it to settle (bounded by
// the controller's deadline) and close whatever sidecar it produced.
const requestExit = exitController({
  shutdown: async () => {
    const started = sidecar ?? (await starting?.catch(() => undefined));
    await started?.shutdown();
  },
  zero: () => stateKey?.fill(0),
});
try {
  if (process.argv.length !== 3 || !isAbsolute(process.argv[2]))
    throw Error("supervisor_configuration_required");
  const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
  const parts = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > 65536) throw Error("supervisor_secret_input_too_large");
    parts.push(chunk);
  }
  const raw = Buffer.concat(parts);
  let secrets;
  try {
    secrets = JSON.parse(raw.toString("utf8"));
  } finally {
    raw.fill(0);
    for (const p of parts) p.fill(0);
  }
  stateKey = Buffer.from(secrets.stateKey, "base64");
  if (
    stateKey.length !== 32 ||
    typeof secrets.executorToken !== "string" ||
    !Array.isArray(secrets.ownerTokens)
  )
    throw Error("supervisor_identity_required");
  // Validate private input before loading SQLite/native runtime modules. Besides
  // avoiding unnecessary initialization, malformed requests retain the same
  // sanitized refusal on Node versions that warn when importing node:sqlite.
  const [{ startProductionSidecar }, { fleetBackend }, { localSource }, { withLocalFollowup }] =
    await Promise.all([
      import("../dist/edge-runtime.mjs"),
      import("../../../dist/backend.mjs"),
      import("../../../dist/local-source.mjs"),
      import("../../../dist/local-client.mjs"),
    ]);
  process.env.T3_FLEET_DIR ??= join(homedir(), ".config", "mtg-t3-fleet");
  sidecar = await (starting = startProductionSidecar({
    configPath: config.configPath,
    historicalStateDirectory: config.historicalStateDirectory,
    cacheStateDirectory: config.cacheStateDirectory,
    stateKey,
    bootstrap: {
      ...config.bootstrap,
      key: stateKey,
      executorToken: secrets.executorToken,
      ownerTokens: new Map(secrets.ownerTokens),
      leaseFailure: failureReporter("edge_lease_failure"),
      // A lost generation is never reacquired in-process. Exit promptly (75,
      // EX_TEMPFAIL) so the supervisor restarts a fresh edge instead of
      // probing a 503 listener; the attempt journal survives for reconciliation.
      leaseLost: () => {
        console.error(JSON.stringify({ event: "edge_lease_lost_exit", local_fallback: false }));
        void requestExit(75);
      },
      checkpointFailure: failureReporter("edge_checkpoint_failure"),
    },
    backendFactory: async (policy) => {
      let backend =
        policy.source?.type === "local-projection"
          ? localSource(policy.source.databasePath)
          : await fleetBackend(policy.fleetHelperPath);
      if (policy.localClient)
        backend = await withLocalFollowup(backend, policy.fleetHelperPath, policy.localClient);
      return backend;
    },
  }));
  secrets = null;
  process.once("SIGTERM", () => void requestExit(0));
  process.once("SIGINT", () => void requestExit(0));
  console.error("Kadenco central edge ready; original native routes and authorization retained");
} catch (error) {
  await sidecar?.shutdown();
  stateKey?.fill(0);
  // Do not print input, path, provider errors or secret-bearing exception text.
  console.error(JSON.stringify(startupFailure(error)));
  process.exitCode = 1;
}
