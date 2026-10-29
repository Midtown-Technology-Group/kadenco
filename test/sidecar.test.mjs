// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { startSidecar } from "../dist/sidecar.mjs";

async function fixture() {
  const directory = mkdtempSync(join(tmpdir(), "kadenco-sidecar-"));
  const state = join(directory, "state");
  mkdirSync(state, { mode: 0o700 });
  const listener = createServer();
  await new Promise((r) => listener.listen(0, "127.0.0.1", r));
  const port = listener.address().port;
  const configPath = join(directory, "policy.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      port,
      stateDirectory: state,
      source: { type: "local-projection", databasePath: "synthetic-unused" },
      callbackHosts: [],
      principals: [],
      sessions: [],
    }),
  );
  let closed = 0,
    created = 0;
  const options = {
    configPath,
    stateKey: randomBytes(32),
    backendFactory: () => {
      created++;
      return {
        supportsFollowup: false,
        read: async () => {
          throw Error("No synthetic session enrolled");
        },
        followup: async () => {
          throw Error("No execution granted");
        },
        close: async () => {
          closed++;
        },
      };
    },
  };
  const cleanup = () => {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  };
  return { listener, port, options, cleanup, counts: () => ({ created, closed }) };
}

test("sidecar API owns loopback lifecycle, closes once, and installs no process signals", async () => {
  const f = await fixture();
  await new Promise((r) => f.listener.close(r));
  const signals = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
  let sidecar;
  try {
    sidecar = await startSidecar(f.options);
    assert.equal(sidecar.address().address, "127.0.0.1");
    const response = await fetch(`http://127.0.0.1:${f.port}/healthz`);
    assert.equal(response.status, 200);
    assert.equal((await response.json()).status, "up");
    assert.deepEqual([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")], signals);
    const stopping = sidecar.shutdown();
    assert.equal(sidecar.shutdown(), stopping);
    await stopping;
    assert.equal(sidecar.address(), null);
    assert.deepEqual(f.counts(), { created: 1, closed: 1 });
  } finally {
    await sidecar?.shutdown();
    f.cleanup();
  }
});

test("occupied listener refuses startup and closes the injected backend", async () => {
  const f = await fixture();
  try {
    await assert.rejects(startSidecar(f.options), { code: "EADDRINUSE" });
    assert.deepEqual(f.counts(), { created: 1, closed: 1 });
  } finally {
    await new Promise((r) => f.listener.close(r));
    f.cleanup();
  }
});

test("invalid key refuses before operator composition or listener startup", async () => {
  const f = await fixture();
  try {
    await assert.rejects(
      startSidecar({ ...f.options, stateKey: Buffer.alloc(1) }),
      /32_byte_state_key_required/,
    );
    assert.deepEqual(f.counts(), { created: 0, closed: 0 });
  } finally {
    await new Promise((r) => f.listener.close(r));
    f.cleanup();
  }
});
