// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createServer } from "node:net";
import assert from "node:assert/strict";

const root = resolve(process.argv[2]);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
assert.equal(pkg.name, "kadenco");
const { startSidecar } = await import(pathToFileURL(join(root, "dist/sidecar.mjs")));
assert.equal(
  typeof (await import(pathToFileURL(join(root, "scripts/worker-provenance.mjs"))))
    .verifyWorkerBuild,
  "function",
);
const central = await import(
  pathToFileURL(join(root, "packages/control-plane/dist/edge-runtime.mjs"))
);
for (const name of [
  "startProductionSidecar",
  "resumeManagedRecovery",
  "prepareManagedRecovery",
  "activateManagedSource",
  "projectControlPolicy",
  "captureRecovery",
  "verifyRecovery",
  "encodePolicy",
  "decodePolicy",
])
  assert.equal(typeof central[name], "function");
const refused = spawnSync(
  process.execPath,
  [join(root, "packages/control-plane/operator/run-edge.mjs")],
  { encoding: "utf8", input: "", timeout: 10000, windowsHide: true },
);
assert.equal(refused.status, 1);
assert.match(refused.stderr, /startup refused/);
const directory = mkdtempSync(join(tmpdir(), "kadenco-package-smoke-"));
let sidecar;
try {
  const state = join(directory, "state");
  mkdirSync(state, { mode: 0o700 });
  const listener = createServer();
  await new Promise((r) => listener.listen(0, "127.0.0.1", r));
  const port = listener.address().port;
  await new Promise((r) => listener.close(r));
  const configPath = join(directory, "config.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      port,
      source: { type: "local-projection", databasePath: "synthetic-unused" },
      stateDirectory: state,
      callbackHosts: [],
      principals: [],
      sessions: [],
    }),
  );
  let closed = false;
  sidecar = await startSidecar({
    configPath,
    stateKey: randomBytes(32),
    backendFactory: () => ({
      supportsFollowup: false,
      read: async () => {
        throw Error("no_sessions");
      },
      followup: async () => {
        throw Error("no_execution");
      },
      close: async () => {
        closed = true;
      },
    }),
  });
  const response = await fetch(`http://127.0.0.1:${port}/healthz`);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).status, "up");
  await sidecar.shutdown();
  assert.equal(closed, true);
  assert.equal(sidecar.address(), null);
  console.log(
    JSON.stringify({
      version: pkg.version,
      package_import: true,
      startup: true,
      shutdown: true,
      execution: "not_granted",
    }),
  );
} finally {
  await sidecar?.shutdown();
  rmSync(directory, { recursive: true, force: true });
}
