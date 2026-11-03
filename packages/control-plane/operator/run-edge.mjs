// SPDX-License-Identifier: AGPL-3.0-or-later
// Trusted supervisor entry point. Arguments contain only a configuration path;
// secrets arrive once on private stdin, never argv or a persistent JSON file.
import { readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { homedir } from "node:os";

let sidecar, stateKey;
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
  sidecar = await startProductionSidecar({
    configPath: config.configPath,
    historicalStateDirectory: config.historicalStateDirectory,
    cacheStateDirectory: config.cacheStateDirectory,
    stateKey,
    bootstrap: {
      ...config.bootstrap,
      key: stateKey,
      executorToken: secrets.executorToken,
      ownerTokens: new Map(secrets.ownerTokens),
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
  });
  secrets = null;
  const stop = async () => {
    await sidecar.shutdown();
    stateKey.fill(0);
    process.exit(0);
  };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  console.error("Kadenco central edge ready; original native routes and authorization retained");
} catch {
  await sidecar?.shutdown();
  stateKey?.fill(0);
  // Do not print input, path, provider errors or secret-bearing exception text.
  console.error("Kadenco central edge startup refused; no local fallback");
  process.exitCode = 1;
}
