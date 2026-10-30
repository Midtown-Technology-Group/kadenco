// SPDX-License-Identifier: AGPL-3.0-or-later
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import assert from "node:assert/strict";

const root = resolve(process.argv[2]);
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
assert.equal(pkg.name, "kadenco");
const { startSidecar } = await import(pathToFileURL(join(root, "dist/sidecar.mjs")));
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
