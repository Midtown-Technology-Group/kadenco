// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { createServer } from "node:net";
import { randomBytes } from "node:crypto";
import { spawnSync } from "node:child_process";
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

test("environment fallback survives failed startup and same-process restart while child inheritance stays scrubbed", async () => {
  const f = await fixture(),
    old = process.env.EDDIE_T3_STATE_KEY;
  const { stateKey, ...options } = f.options,
    factory = options.backendFactory;
  let sidecar;
  process.env.EDDIE_T3_STATE_KEY = stateKey.toString("base64");
  options.backendFactory = () => {
    assert.equal(process.env.EDDIE_T3_STATE_KEY, undefined);
    const child = spawnSync(
      process.execPath,
      ["-e", 'process.stdout.write(process.env.EDDIE_T3_STATE_KEY ? "leaked" : "absent")'],
      { encoding: "utf8", windowsHide: true },
    );
    assert.equal(child.status, 0);
    assert.equal(child.stdout, "absent");
    return factory();
  };
  try {
    await assert.rejects(startSidecar(options), { code: "EADDRINUSE" });
    await new Promise((r) => f.listener.close(r));
    sidecar = await startSidecar(options);
    await sidecar.shutdown();
    sidecar = await startSidecar(options);
    await sidecar.shutdown();
    assert.deepEqual(f.counts(), { created: 3, closed: 3 });
  } finally {
    await sidecar?.shutdown();
    if (f.listener.listening) await new Promise((r) => f.listener.close(r));
    if (old === undefined) delete process.env.EDDIE_T3_STATE_KEY;
    else process.env.EDDIE_T3_STATE_KEY = old;
    f.cleanup();
  }
});

test("startup keeps the root error and separate cleanup failure, and releases its state database", async () => {
  const f = await fixture(),
    closeError = Error("synthetic close failure"),
    factory = f.options.backendFactory;
  try {
    await assert.rejects(
      startSidecar({
        ...f.options,
        backendFactory: () => ({
          ...factory(),
          close: async () => {
            throw closeError;
          },
        }),
      }),
      (error) => {
        assert.ok(error instanceof AggregateError);
        assert.equal(error.cause.code, "EADDRINUSE");
        assert.equal(error.errors[0], error.cause);
        assert.ok(error.errors[1].errors.includes(closeError));
        return true;
      },
    );
    await new Promise((r) => f.listener.close(r));
    const sidecar = await startSidecar(f.options);
    await sidecar.shutdown();
  } finally {
    if (f.listener.listening) await new Promise((r) => f.listener.close(r));
    f.cleanup();
  }
});
