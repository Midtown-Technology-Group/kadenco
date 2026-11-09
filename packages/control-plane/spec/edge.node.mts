import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { SqliteJournal } from "../src/journal.ts";
import { createEdgeRuntime, type EdgeRuntimePorts } from "../src/edge-runtime.ts";
import { centralTransport } from "../src/transport.ts";
import { consume } from "../src/edge.ts";
import {
  validateOperation,
  seal,
  unseal,
  verifyRetirement,
  type Envelope,
  type Grant,
} from "../src/authorization.ts";
import { manifestOf, signedSnapshot, verifySnapshot } from "../src/snapshot.ts";

test("central HTTP transport preserves refusals and never retries uncertain mutations", async () => {
  let calls = 0;
  const call = centralTransport({
    origin: "https://fixture.invalid",
    token: () => "test-only-identity",
    fetch: async (url, init) => {
      calls++;
      assert.equal(String(url), "https://fixture.invalid/begin");
      assert.equal(init?.redirect, "error");
      assert.equal(
        (init?.headers as Record<string, string> | undefined)?.authorization,
        "Bearer test-only-identity",
      );
      assert.deepEqual(JSON.parse(String(init?.body)), { request_id: "original" });
      return Response.json({ reason: "forbidden", may_attempt: true }, { status: 403 });
    },
  });
  assert.deepEqual(await call("begin", { request_id: "original" }), {
    reason: "forbidden",
    safe_to_resend: false,
  });
  assert.equal(calls, 1);
  const lost = centralTransport({
    origin: "https://fixture.invalid",
    token: () => "secret-not-in-errors",
    fetch: async () => {
      calls++;
      throw Error("provider echoed secret-not-in-errors");
    },
  });
  await assert.rejects(lost("begin", {}), /^Error: central_transport_uncertain$/);
  assert.equal(calls, 2);
  await assert.rejects(call("../other", {}), /invalid_central_operation/);
  await assert.rejects(call("begin", { large: "x".repeat(65536) }), /central_request_too_large/);
  assert.equal(calls, 2);
  for (const origin of [
    "http://fixture.invalid",
    "https://fixture.invalid/path",
    "https://user:secret@fixture.invalid",
    "https://fixture.invalid?token=secret",
  ]) {
    assert.throws(
      () => centralTransport({ origin, token: () => "fixture" }),
      /invalid_central_transport/,
    );
  }
});
test("central transport deadline before headers or during body remains uncertain without retry", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const phase of ["headers", "body"]) {
    let calls = 0;
    let aborted = false;
    const rows: import("../src/transport.ts").CentralDiagnostic[] = [];
    const transport = centralTransport({
      origin: "https://fixture.invalid",
      token: () => "synthetic-never-transmitted",
      timeoutMs: 10000,
      diagnostic: (row) => rows.push(row),
      fetch: async (_url, init) => {
        calls++;
        const signal = init!.signal!;
        if (phase === "headers")
          return new Promise<Response>((_resolve, reject) => {
            signal.addEventListener("abort", () => {
              aborted = true;
              reject(Error("synthetic transport stall"));
            });
          });
        return new Response(
          new ReadableStream({
            start(controller) {
              signal.addEventListener("abort", () => {
                aborted = true;
                controller.error(Error("synthetic body stall"));
              });
            },
          }),
        );
      },
    });
    const pending = transport("begin", { request_id: "original-stable-identity" });
    // Let fetch resolve and enter the body reader before advancing fake time.
    await Promise.resolve();
    await Promise.resolve();
    const rejected = assert.rejects(pending, /^Error: central_transport_uncertain$/);
    t.mock.timers.tick(9999);
    assert.equal(aborted, false);
    t.mock.timers.tick(1);
    await rejected;
    assert.equal(aborted, true);
    assert.equal(calls, 1);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].operation, "begin");
    assert.equal(rows[0].outcome, "uncertain");
    assert.equal(rows[0].http_status, phase === "headers" ? null : 200);
    assert.equal(JSON.stringify(rows).includes("synthetic"), false);
  }
});

test("central transport diagnostics retain fixed fields without secrets or outcome changes", async () => {
  const rows: import("../src/transport.ts").CentralDiagnostic[] = [];
  let calls = 0,
    status = 200;
  const transport = centralTransport({
    origin: "https://fixture.invalid",
    token: () => "SECRET",
    diagnostic: (r) => {
      rows.push(r);
      throw Error("telemetry failed SECRET");
    },
    fetch: async () => {
      calls++;
      if (status === 0) throw Error("SECRET provider body");
      return Response.json(
        status === 200 ? { stored: true } : { reason: "forbidden", secret: "SECRET" },
        { status, headers: { "x-ratelimit-remaining": "12" } },
      );
    },
  });
  assert.deepEqual(await transport("status", { secret: "SECRET" }), { stored: true });
  status = 403;
  assert.deepEqual(await transport("begin", {}), { reason: "forbidden", safe_to_resend: false });
  status = 0;
  await assert.rejects(transport("begin", {}), /central_transport_uncertain/);
  assert.equal(calls, 3);
  assert.deepEqual(
    rows.map((r) => r.outcome),
    ["ok", "refused", "uncertain"],
  );
  assert.equal(rows[0].rate_limit_remaining, 12);
  assert.equal(rows[2].http_status, null);
  assert.equal(new Set(rows.map((r) => r.correlation_id)).size, 3);
  assert.equal(JSON.stringify(rows).includes("SECRET"), false);
  assert.deepEqual(Object.keys(rows[0]).sort(), [
    "correlation_id",
    "duration_ms",
    "http_status",
    "operation",
    "outcome",
    "rate_limit_remaining",
  ]);
});

test("central HTTP transport bounds streaming responses, cancels oversized bodies and does not accept malformed success", async () => {
  let cancelled = false;
  const large = centralTransport({
    origin: "https://fixture.invalid",
    token: () => "fixture",
    fetch: async () =>
      new Response(
        new ReadableStream({
          start(c) {
            c.enqueue(new Uint8Array(65537));
          },
          cancel() {
            cancelled = true;
          },
        }),
      ),
  });
  await assert.rejects(large("status", {}), /central_response_too_large/);
  assert.equal(cancelled, true);
  const bad = centralTransport({
    origin: "https://fixture.invalid",
    token: () => "fixture",
    fetch: async () => Response.json([]),
  });
  await assert.rejects(bad("status", {}), /central_response_invalid/);
});
test("rejected async diagnostics cannot terminate a process or replace request outcomes", async () => {
  const { spawnSync } = await import("node:child_process");
  const module = new URL("../src/transport.ts", import.meta.url).href;
  const script = `import assert from 'node:assert/strict';import {centralTransport} from ${JSON.stringify(module)};
    let calls=0;const call=centralTransport({origin:'https://fixture.invalid',token:()=> 'SECRET',diagnostic:async()=>{await Promise.resolve();throw Error('SECRET telemetry');},fetch:async()=>{calls++;if(calls===2)throw Error('SECRET provider');return Response.json({stored:true});}});
    assert.deepEqual(await call('status',{}),{stored:true});await assert.rejects(call('begin',{}),/central_transport_uncertain/);
    await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,2);console.log('async-diagnostics-isolated');`;
  const child = spawnSync(
    process.execPath,
    [
      "--experimental-strip-types",
      "--unhandled-rejections=strict",
      "--input-type=module",
      "-e",
      script,
    ],
    { encoding: "utf8", windowsHide: true, timeout: 10000 },
  );
  assert.equal(child.status, 0, child.stderr);
  assert.equal(child.stdout.trim(), "async-diagnostics-isolated");
  assert.equal(child.stderr.includes("SECRET"), false);
});

test("real sidecar boots the central runtime, fences HTTP and never runs local delivery", async () => {
  const { startSidecar } = await import("../../../dist/sidecar.mjs");
  const { mkdirSync, writeFileSync } = await import("node:fs");
  const root = mkdtempSync(join(tmpdir(), "kadenco-runtime-"));
  const state = join(root, "state");
  mkdirSync(state, { mode: 0o700 });
  const configPath = join(root, "policy.json");
  writeFileSync(
    configPath,
    JSON.stringify({
      port: 41899,
      stateDirectory: state,
      source: { type: "local-projection", databasePath: "unused-fixture" },
      callbackHosts: [],
      principals: [],
      sessions: [],
    }),
  );
  // Reserve an OS-assigned port rather than relying on a free fixed port.
  const { createServer } = await import("node:net");
  const reservation = createServer();
  await new Promise<void>((r) => reservation.listen(0, "127.0.0.1", r));
  const port = (reservation.address() as { port: number }).port;
  await new Promise<void>((r) => reservation.close(() => r()));
  const config = JSON.parse((await import("node:fs")).readFileSync(configPath, "utf8"));
  writeFileSync(configPath, JSON.stringify({ ...config, port }));
  let denied = false,
    observations = 0,
    deliveries = 0;
  const generations: unknown[] = [];
  const leaseFailures: string[] = [];
  const checkpointFailures: string[] = [];
  let rejectCheckpoint = false;
  let loseLeaseDuringCheckpoint = false,
    revision = 0,
    fixtureChange = 0;
  let changeFixture: (() => void) | undefined;
  const ports: EdgeRuntimePorts = {
    epoch: 1,
    executor: "fixture-executor",
    key: randomBytes(32),
    journalPath: join(state, "attempts.db"),
    leaseFailure: (reason) => leaseFailures.push(reason),
    checkpointFailure: (reason) => checkpointFailures.push(reason),
    async executorCall(op, p) {
      if (op === "edge_lease") {
        generations.push((p as { generation?: number }).generation);
        if (denied) return { reason: "fenced" };
        return {
          holder: "fixture-executor",
          instance: (p as { instance: string }).instance,
          generation: 9,
          expires: Date.now() + 10000,
        };
      }
      if (op === "outbox_pending") return { ids: [], next: null };
      if (op === "replica_head") return { revision: 0 };
      if (op === "replica_page") return { revision: 0, records: [], next: null };
      if (op === "replica_receipt") {
        if (loseLeaseDuringCheckpoint) denied = true;
        return { committed: false };
      }
      if (op === "replica_apply")
        return rejectCheckpoint
          ? { reason: "forbidden" }
          : { committed: true, revision: ++revision };
      throw Error("unexpected_operation");
    },
    async ownerCall() {
      throw Error("no_mutation_in_fixture");
    },
    async observationOwnerCall() {
      throw Error("no_subscriptions_in_fixture");
    },
    async bind() {
      throw Error("no_mutation_in_fixture");
    },
    async currentGrant() {
      throw Error("no_mutation_in_fixture");
    },
    async observe() {
      return { state: "unknown", evidence: "fixture" };
    },
    observationBinding() {
      throw Error("no_subscriptions_in_fixture");
    },
  };
  let sidecar: Awaited<ReturnType<typeof startSidecar>> | undefined;
  try {
    sidecar = await startSidecar({
      configPath,
      stateKey: randomBytes(32),
      backendFactory: () => ({
        close: async () => {},
        supportsFollowup: false,
        read: async () => {
          throw Error("unused");
        },
        followup: async () => {
          throw Error("unused");
        },
      }),
      runtimeFactory: (bridge) => {
        changeFixture = () =>
          bridge.store.put("fixture", "checkpoint", { synthetic: true, revision: ++fixtureChange });
        bridge.observe = async () => {
          observations++;
        };
        bridge.deliver = async () => {
          deliveries++;
        };
        bridge.fleetEvents.observe = async () => {};
        return createEdgeRuntime(bridge, ports);
      },
    });
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    assert.equal(observations, 1);
    assert.equal(deliveries, 0);
    const renewals = generations.length;
    await new Promise((resolve) => setTimeout(resolve, 2750));
    assert.ok(generations.length > renewals, "idle runtime independently renews its lease");
    rejectCheckpoint = true;
    changeFixture!();
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 503);
    assert.equal(checkpointFailures.at(-1), "central_refused");
    assert.equal(leaseFailures.length, 0, "checkpoint denial is not reported as lease loss");
    rejectCheckpoint = false;
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    const reportedCheckpoints = checkpointFailures.length;
    loseLeaseDuringCheckpoint = true;
    changeFixture!();
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 503);
    assert.equal(leaseFailures.at(-1), "fenced");
    assert.equal(
      checkpointFailures.length,
      reportedCheckpoints,
      "lease loss during flush is not a second checkpoint failure",
    );
    loseLeaseDuringCheckpoint = false;
    denied = false;
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 200);
    denied = true;
    assert.equal((await fetch(`http://127.0.0.1:${port}/healthz`)).status, 503);
    assert.equal(leaseFailures.at(-1), "fenced");
    assert.equal(generations[0], undefined);
    assert.ok(generations.slice(1).every((g) => g === 9));
    await sidecar.shutdown();
    sidecar = undefined;
    // Restart under denial must refuse before exposing even the health endpoint.
    await assert.rejects(
      startSidecar({
        configPath,
        stateKey: randomBytes(32),
        backendFactory: () => ({
          close: async () => {},
          supportsFollowup: false,
          read: async () => {
            throw Error("unused");
          },
          followup: async () => {
            throw Error("unused");
          },
        }),
        runtimeFactory: (bridge) => createEdgeRuntime(bridge, ports),
      }),
      /edge_lease_unavailable/,
    );
  } finally {
    await sidecar?.shutdown();
    rmSync(root, { recursive: true, force: true });
  }
});

test("persistent journal survives reopen, concurrent handles and immutable outcome", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-journal-"));
  const path = join(dir, "journal.db");
  try {
    let a = new SqliteJournal(path);
    assert.equal(await a.reserve("id"), true);
    a.close();
    a = new SqliteJournal(path);
    const b = new SqliteJournal(path);
    assert.equal(await a.reserve("id"), false);
    assert.equal(await b.reserve("id"), false);
    const result = { state: "observed" as const, evidence: "native-receipt" };
    await a.finish("id", result);
    a.close();
    b.close();
    a = new SqliteJournal(path);
    assert.equal(a.read("id")?.outcome, JSON.stringify(result));
    await a.finish("id", result);
    await assert.rejects(a.finish("id", { state: "unknown", evidence: "changed" }));
    a.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("runtime journal encrypts evidence, authenticates reopen and retains immutable plaintext comparison", async () => {
  const { DatabaseSync } = await import("node:sqlite");
  const dir = mkdtempSync(join(tmpdir(), "kadenco-encrypted-journal-"));
  const path = join(dir, "journal.db"),
    key = randomBytes(32);
  let journal = new SqliteJournal(path, key);
  const outcome = { state: "observed" as const, evidence: "sensitive-fixture-receipt" };
  try {
    await journal.reserve("original");
    await journal.finish("original", outcome);
    await journal.finish("original", outcome);
    journal.close();
    const raw = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal(
        String(raw.prepare("SELECT outcome FROM attempts").get()!.outcome).includes(
          outcome.evidence,
        ),
        false,
      );
    } finally {
      raw.close();
    }
    journal = new SqliteJournal(path, key);
    assert.equal(journal.read("original")?.outcome, JSON.stringify(outcome));
    assert.equal(await journal.reserve("original"), false);
    await assert.rejects(journal.finish("original", { state: "unknown", evidence: "changed" }));
    const wrong = new SqliteJournal(path, randomBytes(32));
    try {
      assert.throws(() => wrong.read("original"));
    } finally {
      wrong.close();
    }
    const changed = new DatabaseSync(path);
    try {
      changed
        .prepare(
          "INSERT INTO attempts(id,outcome) SELECT 'swapped',outcome FROM attempts WHERE id='original'",
        )
        .run();
    } finally {
      changed.close();
    }
    assert.throws(() => journal.read("swapped"), "ciphertext cannot be rebound to another UUID");
  } finally {
    journal.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
test("crash windows retain persistent attempt and never reexecute", async () => {
  for (const fault of [
    "before_permit",
    "after_effect",
    "receipt",
    "journal_finish",
    "journal_reserve",
  ]) {
    const dir = mkdtempSync(join(tmpdir(), "kadenco-crash-")),
      path = join(dir, "journal.db");
    let journal = new SqliteJournal(path),
      effects = 0,
      begins = 0;
    const command = { request_id: "id", epoch: 7, host: "local", thread_id: "thread" };
    const ports = {
      journal,
      async validate() {},
      async observe() {
        return { state: "unknown" as const, evidence: "read-only" };
      },
      async execute() {
        effects++;
        if (fault === "after_effect") throw Error("crash");
        return { state: "observed" as const, evidence: "receipt" };
      },
      async call(op: string) {
        if (op === "claim")
          return { claimed: true, generation: 1, host: "local", thread: "thread" };
        if (op === "begin") {
          begins++;
          if (fault === "before_permit") throw Error("lost");
          return { may_attempt: true, request_id: "id", generation: 1 };
        }
        if (fault === "receipt") throw Error("lost");
        return {};
      },
    };
    if (fault === "journal_finish")
      ports.journal.finish = async () => {
        throw Error("disk failure");
      };
    if (fault === "journal_reserve")
      ports.journal.reserve = async () => {
        throw Error("disk failure");
      };
    try {
      await consume(command, ports);
    } catch {}
    journal.close();
    journal = new SqliteJournal(path);
    ports.journal = journal;
    // Reserve-write failure occurred before any permit or effect; a later successful write may proceed.
    const before = effects;
    await consume(command, ports).catch(() => {});
    assert.equal(effects, fault === "journal_reserve" ? 1 : before);
    assert.ok(begins <= 1);
    journal.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
const e: Envelope = {
  request_id: "12345678-1234-4234-8234-123456789abc",
  fleet: "fleet",
  principal: "owner",
  grant: "grant",
  revision: 2,
  host: "host",
  project: "project",
  provider: "provider",
  thread_id: "thread",
  run: "run",
  kind: "continue",
  expires: 200,
  payload: { text: "hello" },
};
const g: Grant = {
  ...e,
  expires: 300,
  revoked: false,
  kinds: ["continue", "create", "settings_standard", "webhook"],
};
test("operation envelopes enforce current exact authority and supported payloads", () => {
  assert.match(validateOperation(e, g, 100), /^[a-f0-9]{64}$/);
  for (const key of [
    "host",
    "project",
    "provider",
    "run",
    "principal",
    "grant",
    "revision",
  ] as const)
    assert.throws(() =>
      validateOperation({ ...e, [key]: key === "revision" ? 3 : "wrong" }, g, 100),
    );
  for (const grant of [
    { ...g, revoked: true },
    { ...g, expires: 99 },
    { ...g, revision: 3 },
  ])
    assert.throws(() => validateOperation(e, grant, 100));
  assert.throws(() => validateOperation({ ...e, expires: 99 }, g, 100));
  assert.throws(() =>
    validateOperation({ ...e, payload: { text: "hi", model: "changed" } }, g, 100),
  );
  validateOperation({ ...e, kind: "settings_standard", payload: { speed: "standard" } }, g, 100);
  assert.throws(() =>
    validateOperation({ ...e, kind: "settings_standard", payload: { speed: "fast" } }, g, 100),
  );
  validateOperation(
    { ...e, run: null, kind: "create", payload: { text: "hi", title: "title" } },
    { ...g, run: null },
    100,
  );
  validateOperation(
    { ...e, kind: "webhook", payload: { event_id: "event", body_sha256: "a".repeat(64) } },
    g,
    100,
  );
});
test("authenticated snapshots reject tampering, missing records, wrong key and provenance", () => {
  const key = randomBytes(32),
    snapshot = {
      migration_id: "m",
      source_snapshot: "s",
      encryption_provenance: "lineage",
      records: [{ kind: "receipt", id: "id", ciphertext: "opaque-original" }],
    };
  const expected = manifestOf(snapshot),
    packet = signedSnapshot(snapshot, key);
  assert.equal(verifySnapshot(packet, key, expected).authenticated, true);
  assert.throws(() => verifySnapshot({ ...packet, body: packet.body + " " }, key, expected));
  assert.throws(() => verifySnapshot(packet, randomBytes(32), expected));
  assert.throws(() =>
    verifySnapshot(signedSnapshot({ ...snapshot, records: [] }, key), key, expected),
  );
  assert.throws(() =>
    verifySnapshot(
      signedSnapshot({ ...snapshot, encryption_provenance: "wrong" }, key),
      key,
      expected,
    ),
  );
});
test("retirement proof requires all native, callback and restart routes denied", () => {
  const key = randomBytes(32),
    required = {
      migration_id: "m",
      snapshot: "s",
      routes: ["native", "signing", "restart"],
      issuer: "independent-boundary",
    };
  const proof = {
    ...required,
    issued: 100,
    expires: 200,
    denied: required.routes,
    revival_denied: true,
  };
  const verified = unseal(seal(proof, key), key) as typeof proof;
  assert.equal(verifyRetirement(verified, required, 150).activation_permitted, false);
  for (const changed of [
    { ...proof, denied: ["native"] },
    { ...proof, revival_denied: false },
    { ...proof, expires: 140 },
    { ...proof, snapshot: "wrong" },
    { ...proof, issuer: "old-writer" },
  ])
    assert.throws(() => verifyRetirement(changed, required, 150));
});

test("process exit after durable reserve retains the no-replay marker", async () => {
  const { spawnSync } = await import("node:child_process");
  const dir = mkdtempSync(join(tmpdir(), "kadenco-process-crash-")),
    path = join(dir, "journal.db");
  try {
    const moduleUrl = new URL("../src/journal.ts", import.meta.url).href;
    const script = `import {SqliteJournal} from ${JSON.stringify(moduleUrl)}; const j=new SqliteJournal(${JSON.stringify(path)}); await j.reserve('crashed'); process.exit(17);`;
    const child = spawnSync(process.execPath, [
      "--experimental-strip-types",
      "--input-type=module",
      "-e",
      script,
    ]);
    assert.equal(child.status, 17, child.stderr.toString());
    const journal = new SqliteJournal(path);
    assert.equal(await journal.reserve("crashed"), false);
    journal.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
test("authenticated runner binds central digest and revalidates policy before effect", async () => {
  const { consumeAuthorized } = await import("../src/authorization.ts");
  const key = randomBytes(32);
  let effects = 0,
    checks = 0;
  const ports = {
    journal: {
      async reserve() {
        return true;
      },
      async finish() {},
    },
    async validate() {},
    async observe() {
      return { state: "unknown" as const, evidence: "read" };
    },
    async execute() {
      effects++;
      return { state: "observed" as const, evidence: "receipt" };
    },
    async call(op: string) {
      if (op === "claim")
        return {
          claimed: true,
          generation: 1,
          host: e.host,
          thread: e.thread_id,
          kind: e.kind,
          digest: validateOperation(e, g, 100),
        };
      if (op === "begin") return { may_attempt: true, request_id: e.request_id, generation: 1 };
      return {};
    },
  };
  const current = async () => {
    checks++;
    return checks >= 5 ? { ...g, revoked: true } : g;
  };
  const result = await consumeAuthorized(seal(e, key), key, current, () => 100, 7, ports);
  assert.equal(effects, 0);
  assert.equal(result.state, "reconcile");
  await assert.rejects(
    consumeAuthorized(
      seal(e, key),
      key,
      async () => g,
      () => 100,
      7,
      {
        ...ports,
        async call() {
          return {
            claimed: true,
            generation: 1,
            host: e.host,
            thread: e.thread_id,
            kind: e.kind,
            digest: "wrong",
          };
        },
      },
    ),
    /reservation_envelope_mismatch/,
  );
});

test("quiesced synthetic Store extraction preserves ciphertext and audit and rolls back lease loss", async () => {
  const { DatabaseSync } = await import("node:sqlite");
  const { extractSnapshot } = await import("../src/migration-service.ts");
  const db = new DatabaseSync(":memory:");
  db.exec(
    "CREATE TABLE records(kind TEXT,id TEXT,value TEXT);CREATE TABLE audit(seq INTEGER,action TEXT);INSERT INTO records VALUES('subscription','standing-id','original-aes-envelope');INSERT INTO audit VALUES(1,'existing-audit')",
  );
  let checks = 0;
  assert.throws(
    () =>
      extractSnapshot(db, "m", "lineage", () => {
        if (++checks === 2) throw Error("lease_lost");
      }),
    /lease_lost/,
  );
  const snapshot = extractSnapshot(db, "m", "lineage", () => {});
  assert.equal(snapshot.records[0].ciphertext, "original-aes-envelope");
  assert.equal(snapshot.records[1].kind, "$audit");
  assert.equal(snapshot.source_snapshot.length, 64);
  db.close();
});
test("native adapter requires existing strict schemas and preserves exact settings/create options", async () => {
  const { dispatchExisting } = await import("../src/native-adapter.ts");
  const seen: unknown[] = [];
  const services = {
    async continue() {
      return {};
    },
    creation: {
      async create(owner: string, p: unknown) {
        seen.push({ owner, p });
        return { native_submitted: true };
      },
    },
    settings: {
      async standard(owner: string, p: unknown) {
        seen.push({ owner, p });
        return { state: "verified", native_submitted: true };
      },
    },
    async receipt() {
      return null;
    },
  };
  await dispatchExisting(
    {
      ...e,
      kind: "settings_standard",
      payload: { speed: "standard", expected_fingerprint: "a".repeat(64) },
    },
    services,
  );
  await dispatchExisting(
    {
      ...e,
      kind: "create",
      run: null,
      payload: {
        text: "hi",
        title: "test",
        model: "existing-model",
        options: [{ id: "speed", value: "standard" }],
        runtime_mode: "approval-required",
      },
    },
    services,
  );
  assert.equal(seen.length, 2);
  await assert.rejects(
    dispatchExisting({ ...e, kind: "create", payload: { text: "hi", title: "test" } }, services),
  );
  const unknown = await dispatchExisting(e, services);
  assert.equal(unknown.state, "unknown");
});

test("segmented migration authenticates large inventories and refuses dropped or mixed segments before writes", async () => {
  const { segmentSnapshot, importSegments } = await import("../src/import-service.ts");
  const key = randomBytes(32);
  const snapshot = {
    migration_id: "large",
    source_snapshot: "snapshot",
    encryption_provenance: "lineage",
    records: Array.from({ length: 60 }, (_, i) => ({
      kind: "receipt",
      id: String(i),
      ciphertext: "x".repeat(30000),
    })),
  };
  const packets = segmentSnapshot(snapshot, key),
    expected = manifestOf(snapshot);
  assert.ok(packets.length > 1);
  let writes = 0;
  const rows: typeof snapshot.records = [];
  const call = async (op: string, p: object) => {
    if (op === "import") {
      writes++;
      const r = p as { records: typeof rows };
      rows.push(...r.records);
      return { stored: r.records.length, active: false };
    }
    return { records: rows, next: null, active: false };
  };
  await assert.rejects(importSegments(packets.slice(1), key, expected, call));
  assert.equal(writes, 0);
  await assert.rejects(importSegments([...packets].reverse(), key, expected, call));
  assert.equal(writes, 0);
  assert.equal((await importSegments(packets, key, expected, call)).verified_records, 60);
});

import {
  bootstrap,
  quiesce,
  snapshot,
  migrate,
  rollback,
  fixtureRoot,
} from "../operator/local.mts";
test("operator fixture staging imports to real workerd and rollback exports current receipts", async () => {
  const root = bootstrap();
  try {
    assert.throws(() => snapshot(root), /fixture_not_quiesced/);
    quiesce(root);
    snapshot(root);
    assert.equal((await migrate(root)).verified_records, 3);
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(join(root, "fixture.db"));
    db.prepare("INSERT INTO records VALUES(?,?,?)").run(
      "command",
      "new-current-receipt",
      "new-current-evidence",
    );
    db.close();
    assert.equal(rollback(root).records, 4);
    const output = new DatabaseSync(join(root, "rollback-current.db"), { readOnly: true });
    assert.equal(
      output.prepare("SELECT value FROM records WHERE id=?").get("new-current-receipt")?.value,
      "new-current-evidence",
    );
    output.close();
    assert.throws(() => rollback(root), /rollback_candidate_exists/);
    assert.throws(() => fixtureRoot(tmpdir()), /fixture_path_required|ENOENT/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("coverage ledger accounts for every registered tool and disabled entry refuses all requests", async () => {
  const { readFileSync } = await import("node:fs");
  const server = readFileSync(new URL("../../../src/server.mts", import.meta.url), "utf8");
  const tools = [
    ...new Set([...server.matchAll(/register\(\s*"([a-z_]+)"/g)].map((m) => m[1])),
  ].sort();
  const coverage = JSON.parse(
    readFileSync(new URL("../deployment/coverage.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(coverage.owner_tools.map((t: { name: string }) => t.name).sort(), tools);
  assert.equal(coverage.replacement_ready, false);
  const disabled = (await import("../deployment/disabled.ts")).default;
  assert.equal(disabled.fetch().status, 503);
  const { spawnSync } = await import("node:child_process");
  const denied = spawnSync(process.execPath, [
    new URL("../operator/deny-deploy.mjs", import.meta.url).pathname.replace(
      /^\/([A-Za-z]:)/,
      "$1",
    ),
  ]);
  assert.notEqual(denied.status, 0);
});

test("edge MCP/collaboration adapters retain role authentication and deny requests when central lease fails", async () => {
  const { composeEdgeRoutes } = await import("../src/edge-routes.ts");
  const { Bridge } = await import("../../../dist/bridge.mjs");
  const { Store } = await import("../../../dist/store.mjs");
  const store = new Store(":memory:", randomBytes(32));
  let allowed = false;
  const policy = {
    sessions: [],
    principals: [{ id: "owner", tokenSha256: "a".repeat(64), sessions: [] }],
    collaboration: {
      enabled: true,
      brokerPrincipal: "owner",
      ownerSubjects: ["owner"],
      origin: "https://fixture.invalid",
    },
    callbackHosts: [],
  };
  const bridge = new Bridge({
    store,
    policy: () => policy,
    backend: {},
    post: async () => ({ status: 200 }),
  } as any);
  const routes = composeEdgeRoutes(
    bridge,
    async () => {
      if (!allowed) throw Error("fenced");
    },
    { authenticate: async () => ({ subject: "guest", email: "guest@example.test" }) } as any,
  );
  const servers = [routes.mcp.server, routes.collaboration.server];
  try {
    for (const server of servers)
      await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = (server: (typeof servers)[number]) =>
      "http://127.0.0.1:" + (server.address() as { port: number }).port;
    assert.equal((await fetch(url(servers[0]) + "/mcp")).status, 503);
    assert.equal((await fetch(url(servers[1]) + "/collaborate/api/me")).status, 503);
    allowed = true;
    assert.equal((await fetch(url(servers[0]) + "/mcp")).status, 401);
    const response = await fetch(url(servers[1]) + "/collaborate/api/me");
    assert.notEqual(response.status, 503);
    assert.equal(store.all("command").length, 0);
  } finally {
    for (const server of servers) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    routes.collaboration.inner.emit("close");
    store.close();
  }
});

test("bounded observation hands off exact events once; callback adapter rechecks pending routing and keeps signing identity", async () => {
  const { observeExisting, deliverClaimed, existingCallback } =
    await import("../src/edge-services.ts");
  const { Store } = await import("../../../dist/store.mjs");
  const store = new Store(":memory:", randomBytes(32));
  const event = {
    eventId: "preserved-event",
    name: "t3.eddie.requested",
    data: { request_id: "request", host: "local", thread_id: "thread", run_id: "run" },
  };
  const subscription = {
    id: "standing",
    owner: "owner",
    host: "local",
    threadId: "thread",
    active: true,
    expires: null,
    nonExpiring: true,
    name: event.name,
    url: "https://callback.example.test/events",
    secret: "whsec_" + randomBytes(32).toString("base64"),
  };
  store.put("subscription", subscription.id, subscription);
  store.put("delivery", "delivery", {
    id: "delivery",
    subId: subscription.id,
    status: "pending",
    event,
  });
  let posts = 0,
    pending = true,
    checks = 0;
  const bridge = {
    store,
    now: Date.now,
    async observe() {},
    fleetEvents: { async observe() {} },
    exchanges: {
      async deliverable() {
        checks++;
        if (!pending) throw Object.assign(Error("closed"), { reason: "input_request_not_pending" });
      },
    },
    async post(_url: string, headers: Record<string, string>, body: string) {
      posts++;
      assert.equal(headers["webhook-id"], event.eventId);
      assert.equal(headers["X-MCP-Subscription-Id"], subscription.id);
      assert.ok(headers["webhook-signature"]);
      assert.equal(JSON.parse(body).eventId, event.eventId);
      return { status: 204 };
    },
  } as any;
  const binding = {
    project: "project",
    provider: "provider",
    run: "run",
    grant: "grant",
    revision: 1,
    expires: 4102444800000,
  };
  const ports = {
    epoch: 7,
    async refreshLease() {},
    async ownerCall() {
      return { stored: true };
    },
    async executorCall(op: string) {
      return op === "observation_cursor" ? { cursor: 0 } : { stored: true, id: "central-delivery" };
    },
    binding: () => binding,
  };
  try {
    assert.equal((await observeExisting(bridge, ports)).length, 1);
    assert.equal((await observeExisting(bridge, ports)).length, 0);
    const post = existingCallback(bridge);
    const call = async (op: string, p: object) =>
      op === "outbox_claim"
        ? {
            claimed: true,
            generation: 1,
            callback_reference: "standing",
            callback_scope: { owner: "owner", host: "local", thread: "thread", name: event.name },
            event: { event_id: event.eventId, data: event },
          }
        : op === "outbox_begin"
          ? { may_attempt: true }
          : { ...(p as object) };
    const delivered = await deliverClaimed("central-delivery", {
      epoch: 7,
      call,
      postExisting: post,
    });
    assert.equal(delivered.http_status, 204);
    assert.equal(posts, 1);
    pending = false;
    const stopped = await deliverClaimed("central-delivery", {
      epoch: 7,
      call,
      postExisting: post,
    });
    assert.equal(stopped.source_reason, "input_request_not_pending");
    assert.equal(posts, 1);
    assert.equal(checks, 2);
    pending = true;
    const fencedPost = existingCallback(bridge, async () => {
      throw Error("fenced");
    });
    await assert.rejects(
      fencedPost("standing", {
        data: event,
        scope: { owner: "owner", host: "local", thread: "thread", name: event.name },
      }),
      /fenced/,
    );
    assert.equal(checks, 3);
    assert.equal(posts, 1);
  } finally {
    store.close();
  }
});

test("real MCP native call cannot bypass the default central mutation gate", async () => {
  const { composeEdgeRoutes } = await import("../src/edge-routes.ts");
  const { Bridge } = await import("../../../dist/bridge.mjs");
  const { Store } = await import("../../../dist/store.mjs");
  const { createHash, randomUUID } = await import("node:crypto");
  const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
  const token = "synthetic-edge-owner",
    store = new Store(":memory:", randomBytes(32));
  let effects = 0;
  const policy = {
    sessions: [],
    principals: [
      {
        id: "owner",
        tokenSha256: createHash("sha256").update(token).digest("hex"),
        sessions: [],
        commandHosts: [{ host: "local" }],
      },
    ],
    collaboration: {
      enabled: true,
      brokerPrincipal: "owner",
      ownerSubjects: ["owner"],
      origin: "https://fixture.invalid",
    },
    callbackHosts: [],
  };
  const bridge = new Bridge({
    store,
    policy: () => policy,
    backend: {},
    post: async () => ({ status: 200 }),
  } as any);
  bridge.fleetReads = {} as any;
  bridge.commands = {
    async continue() {
      effects++;
      return { native_submitted: true };
    },
    creation: {},
    settings: {},
  } as any;
  const routes = composeEdgeRoutes(bridge, async () => {}, {
    authenticate: async () => ({ subject: "owner", email: "owner@example.test" }),
  } as any);
  const server = routes.mcp.server;
  let client: InstanceType<typeof Client> | undefined;
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const url = new URL("http://127.0.0.1:" + (server.address() as { port: number }).port + "/mcp");
    client = new Client(
      { name: "fixture", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    await client.connect(
      new StreamableHTTPClientTransport(url, {
        requestInit: { headers: { authorization: "Bearer " + token } },
      }),
    );
    const result = await client.callTool({
      name: "continue_thread",
      arguments: {
        host: "local",
        thread_id: "thread",
        source_run_id: "run",
        request_id: randomUUID(),
        message: "harmless",
        execution: "allow_new_turn",
      },
    });
    assert.equal(result.isError, true);
    assert.equal(effects, 0);
  } finally {
    await client?.close();
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    routes.collaboration.inner.emit("close");
    store.close();
  }
});

test("mutation gate retains collaboration's final authorization callback and selection restrictions", async () => {
  const { gateEdgeMutations } = await import("../src/mutation-gate.ts");
  let authorized = 0,
    native = 0;
  const bridge = {
    commands: {
      async continue(
        _owner: string,
        _p: unknown,
        options: { authorize: () => void; currentSelectionOnly: boolean; collaborator: boolean },
      ) {
        assert.equal(options.currentSelectionOnly, true);
        assert.equal(options.collaborator, true);
        options.authorize();
        native++;
        return { native_submitted: true };
      },
      creation: {},
      settings: {},
    },
  } as any;
  const gated = gateEdgeMutations(bridge, async (_kind, _owner, _input, execute) => execute());
  const opts = {
    authorize: () => {
      authorized++;
    },
    currentSelectionOnly: true,
    collaborator: true,
  };
  await gated.commands!.continue("owner", {} as any, opts);
  assert.equal(authorized, 1);
  assert.equal(native, 1);
  await assert.rejects(
    gated.commands!.continue("owner", {} as any, {
      ...opts,
      authorize: () => {
        throw Error("revoked");
      },
    }),
    /revoked/,
  );
  assert.equal(native, 1);
});

test("active HTTP stream closes on lease loss instead of surviving admission forever", async () => {
  const { leaseGatedHttp } = await import("../src/edge-routes.ts");
  const { createServer } = await import("node:http");
  let checks = 0,
    closed!: () => void;
  const closing = new Promise<void>((resolve) => (closed = resolve));
  const inner = createServer((_req, res) => {
    res.writeHead(200, { "content-type": "text/event-stream" });
    res.write("data: fixture\n\n");
    res.once("close", closed);
  });
  const server = leaseGatedHttp(
    inner,
    async () => {
      if (++checks > 1) throw Error("revoked");
    },
    10,
  );
  try {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const response = await fetch("http://127.0.0.1:" + (server.address() as { port: number }).port);
    const reader = response.body!.getReader();
    await reader.read();
    await closing;
    assert.ok(checks >= 2);
    await reader.cancel().catch(() => {});
  } finally {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("authenticated legacy fixture adopts original encrypted state and unknown commands without replay", async () => {
  const { DatabaseSync } = await import("node:sqlite");
  const { Store } = await import("../../../dist/store.mjs");
  const { coreSchema } = await import("../src/core-schema.ts");
  const { adoptLegacy } = await import("../src/legacy-adoption.ts");
  const codec = new Store(":memory:", randomBytes(32)),
    db = new DatabaseSync(":memory:");
  db.exec(coreSchema);
  const sql = {
    exec(statement: string, ...args: unknown[]) {
      if (!args.length && statement.includes(";")) {
        db.exec(statement);
        return { toArray: () => [] };
      }
      const prepared = db.prepare(statement);
      if (prepared.columns().length) {
        const rows = prepared.all(...(args as any[]));
        return {
          toArray: () => rows,
          one: () => {
            assert.equal(rows.length, 1);
            return rows[0];
          },
        };
      }
      prepared.run(...(args as any[]));
      return { toArray: () => [] };
    },
  } as unknown as SqlStorage;
  const now = Date.now(),
    subscription = {
      id: "original-standing",
      owner: "owner",
      host: "local",
      threadId: "thread",
      expires: null,
      active: true,
      nonExpiring: true,
      name: "t3.thread.activity",
      secret: "test-only-not-transferred",
    };
  const entries = [
    {
      kind: "command",
      id: "old-native",
      value: {
        owner: "owner",
        request_id: "old-native",
        host: "local",
        thread_id: "thread",
        kind: "continue",
        at: now,
        submission: "outcome_unknown",
        subId: "unrelated-command-metadata",
      },
    },
    {
      kind: "settings_mutation",
      id: "unsubmitted",
      value: {
        owner: "owner",
        request_id: "unsubmitted",
        host: "local",
        thread_id: "thread",
        at: now,
        state: "noop",
      },
    },
    { kind: "subscription", id: subscription.id, value: subscription },
    {
      kind: "delivery",
      id: "original-delivery",
      value: {
        subId: subscription.id,
        status: "pending",
        attempts: 2,
        nextAt: now,
        event: {
          eventId: "preserved-original-event",
          name: subscription.name,
          data: { host: "local", thread_id: "thread", run_id: "run", kind: "completed" },
        },
      },
    },
  ];
  const snapshot = {
    migration_id: "legacy-fixture",
    source_snapshot: "quiesced",
    encryption_provenance: "fixture-codec",
    records: entries.map((r) => ({ kind: r.kind, id: r.id, ciphertext: codec.encode(r.value) })),
  };
  const key = randomBytes(32),
    packet = signedSnapshot(snapshot, key),
    verified = verifySnapshot(packet, key, manifestOf(snapshot));
  const target = {
    owner: "owner",
    host: "local",
    thread: "thread",
    binding: {
      project: "project",
      provider: "provider",
      run: "run",
      grant: "original-grant",
      revision: 1,
      expires: 4102444800000,
    },
  };
  try {
    const storage = {
      sql,
      transactionSync<T>(fn: () => T): T {
        db.exec("BEGIN IMMEDIATE");
        try {
          const result = fn();
          db.exec("COMMIT");
          return result;
        } catch (e) {
          db.exec("ROLLBACK");
          throw e;
        }
      },
    };
    assert.throws(
      () =>
        adoptLegacy(
          storage,
          verified.snapshot,
          (raw) => codec.decode(raw),
          (kind) => [{ ...target, owner: kind === "delivery" ? "wrong-owner" : target.owner }],
        ),
      /legacy_owner_mismatch/,
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM commands").get()?.n, 0);
    const missingReference = {
      ...verified.snapshot,
      records: verified.snapshot.records.map((r) =>
        r.kind === "delivery"
          ? { ...r, ciphertext: codec.encode({ ...codec.decode(r.ciphertext), subId: undefined }) }
          : r,
      ),
    };
    assert.throws(
      () =>
        adoptLegacy(
          storage,
          missingReference,
          (raw) => codec.decode(raw),
          () => [target],
        ),
      /legacy_binding_required/,
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM commands").get()?.n, 0);
    const adopted = adoptLegacy(
      storage,
      verified.snapshot,
      (raw) => codec.decode(raw),
      () => [target],
    );
    assert.deepEqual(adopted, {
      commands: 2,
      budgets: 1,
      subscriptions: 1,
      deliveries: 1,
      activation_permitted: false,
    });
    assert.equal(
      db.prepare("SELECT state FROM commands WHERE id='old-native'").get()?.state,
      "uncertain",
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM budget_reservations").get()?.n, 1);
    const sub = db.prepare("SELECT value FROM subscriptions").get()!;
    assert.equal(String(sub.value).includes("test-only-not-transferred"), false);
    assert.ok(
      String(db.prepare("SELECT event FROM outbox").get()?.event).includes(
        "preserved-original-event",
      ),
    );
    assert.throws(
      () =>
        adoptLegacy(
          storage,
          verified.snapshot,
          (raw) => codec.decode(raw),
          () => [target],
        ),
      /adoption_destination_not_empty/,
    );
  } finally {
    db.close();
    codec.close();
  }
});

test("recovery archive rejects tampered pages and stale epoch before any restore", async () => {
  const { packRecovery, verifyRecovery } = await import("../src/recovery-archive.ts");
  const { recoveryTables } = await import("../src/recovery.ts");
  const counts = Object.fromEntries(recoveryTables.map((t) => [t, t === "control" ? 1 : 0])),
    header = { epoch: 11, watermark: 9, counts },
    rows = [
      {
        table: "control" as const,
        key: 1,
        values: { id: 1, epoch: 11, mode: "quiesced", migration: null },
      },
    ];
  const key = randomBytes(32),
    archive = packRecovery(header, rows, key);
  assert.equal(verifyRecovery(archive, key, header).rows.length, 1);
  assert.throws(() => verifyRecovery({ ...archive, pages: [] }, key, header));
  assert.throws(() => verifyRecovery(archive, key, { ...header, epoch: 10 }));
  assert.throws(() =>
    verifyRecovery(
      { ...archive, pages: [{ ...archive.pages[0], body: archive.pages[0].body + " " }] },
      key,
      header,
    ),
  );
});

test("centralization quarantines one delivery but fences stop the entire pass", async () => {
  const { observeExisting } = await import("../src/edge-services.ts");
  const setup = () => {
    const deliveries = ["first", "bad", "last"].map((id) => ({
      id,
      subId: id,
      status: "pending",
      event: {
        eventId: id,
        name: "t3.thread.activity",
        data: { host: "local", thread_id: "thread", run_id: "run", kind: "completed" },
      },
    }));
    const state = new Map(deliveries.map((d) => [d.id, d as Record<string, unknown>]));
    const subscriptions = new Map(
      deliveries.map((d) => [
        d.id,
        {
          id: d.id,
          owner: "owner",
          host: "local",
          threadId: "thread",
          active: true,
          expires: null,
          nonExpiring: true,
          name: "t3.thread.activity",
        },
      ]),
    );
    const bridge = {
      now: Date.now,
      async observe() {},
      fleetEvents: { async observe() {} },
      store: {
        all: () => [...state.values()],
        get: (_kind: string, id: string) => subscriptions.get(id),
        put: (_kind: string, id: string, v: Record<string, unknown>) => state.set(id, v),
      },
    } as any;
    return { bridge, state };
  };
  const ports = {
    epoch: 7,
    async refreshLease() {},
    binding: () => ({
      project: "project",
      provider: "provider",
      run: "run",
      grant: "grant",
      revision: 1,
      expires: 4102444800000,
    }),
    async ownerCall(_op: string, p: object) {
      return (p as { external_id?: string }).external_id === "bad"
        ? { reason: "forbidden" }
        : { stored: true };
    },
    async executorCall(op: string) {
      return op === "observation_cursor" ? { cursor: 0 } : { stored: true, id: "central" };
    },
  };
  const f = setup();
  assert.deepEqual(
    (await observeExisting(f.bridge, ports)).map((r) => r.state),
    ["stored", "quarantined", "stored"],
  );
  assert.equal(f.state.get("bad")?.status, "centralization_quarantined");
  const fenced = setup();
  await assert.rejects(
    observeExisting(fenced.bridge, {
      ...ports,
      async ownerCall() {
        return { reason: "fenced" };
      },
    }),
    /fenced/,
  );
  assert.equal(fenced.state.get("first")?.status, "pending");
  for (const reason of [
    "central_transport_uncertain",
    "forwarding_failed",
    "configuration_required",
  ]) {
    const unavailable = setup();
    await assert.rejects(
      observeExisting(unavailable.bridge, {
        ...ports,
        async ownerCall() {
          if (reason === "central_transport_uncertain") throw Error(reason);
          return { reason };
        },
      }),
      new RegExp(reason),
    );
    assert.equal(unavailable.state.get("first")?.status, "pending");
  }
  const thrown = setup();
  await assert.rejects(
    observeExisting(thrown.bridge, {
      ...ports,
      async executorCall() {
        throw { reason: "fenced" };
      },
    }),
    (e) => (e as { reason: string }).reason === "fenced",
  );
  assert.equal(thrown.state.get("first")?.status, "pending");
  const inactive = setup();
  await assert.rejects(
    observeExisting(inactive.bridge, {
      ...ports,
      async ownerCall() {
        return { reason: "not_active" };
      },
    }),
    /not_active/,
  );
  assert.equal(inactive.state.get("first")?.status, "pending");
  const nonError = setup();
  assert.deepEqual(
    (
      await observeExisting(nonError.bridge, {
        ...ports,
        async ownerCall(op, p) {
          if ((p as { external_id?: string }).external_id === "bad") throw null;
          return ports.ownerCall(op, p);
        },
      })
    ).map((r) => r.state),
    ["stored", "quarantined", "stored"],
  );
  const lostLease = setup();
  await assert.rejects(
    observeExisting(lostLease.bridge, {
      ...ports,
      async refreshLease() {
        return { reason: "fenced" };
      },
    }),
    /fenced/,
  );
  assert.equal(lostLease.state.get("first")?.status, "pending");
});

test("parity runner builds a clean fixture checkout and stops on build failure", async () => {
  const { mkdirSync, writeFileSync, readFileSync, existsSync } = await import("node:fs");
  const { spawnSync } = await import("node:child_process");
  const root = mkdtempSync(join(tmpdir(), "kadenco-parity-fresh-"));
  try {
    const operator = join(root, "packages", "control-plane", "operator");
    mkdirSync(operator, { recursive: true });
    mkdirSync(join(root, "scripts"));
    mkdirSync(join(root, "test"));
    writeFileSync(
      join(operator, "parity.mjs"),
      readFileSync(new URL("../operator/parity.mjs", import.meta.url)),
    );
    writeFileSync(join(root, "scripts", "build.mjs"), "process.exit(23);");
    for (const name of ["host-callers", "collaboration", "relay-correctness", "thread-settings"])
      writeFileSync(
        join(root, "test", name + ".test.mjs"),
        "import{existsSync,writeFileSync}from'node:fs';if(!existsSync('dist/sentinel'))throw Error('not built');writeFileSync('tests-started','yes');",
      );
    const run = () =>
      spawnSync(process.execPath, [join(operator, "parity.mjs")], {
        cwd: tmpdir(),
        encoding: "utf8",
        env: { ...process.env, NODE_TEST_CONTEXT: undefined },
      });
    assert.equal(run().status, 23);
    assert.equal(existsSync(join(root, "tests-started")), false);
    writeFileSync(
      join(root, "scripts", "build.mjs"),
      "import{mkdirSync,writeFileSync}from'node:fs';mkdirSync('dist');writeFileSync('dist/sentinel','built');",
    );
    const success = run();
    assert.equal(success.status, 0, success.stderr);
    assert.equal(existsSync(join(root, "tests-started")), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

import { selectStagingConfig, selectDeploymentConfig } from "../cloudflare.config.ts";
test("explicit production profile has independent SQLite ownership and no embedded trust or preview", () => {
  const { worker } = selectDeploymentConfig("production");
  assert.equal(worker.name, "kadenco-control-plane");
  assert.equal(worker.env.FLEETS.worker, worker.name);
  assert.equal(worker.workersDev, true);
  assert.equal(worker.previewUrls, false);
  assert.deepEqual(Object.keys(worker.env), ["FLEETS"]);
  assert.throws(() => selectDeploymentConfig(undefined), /explicit_staging_mode_required/);
  assert.throws(() => selectDeploymentConfig("production", true), /preview_deployment_disabled/);
});
test("cf staging conversion has isolated SQLite lifecycle and no production credentials or ingress", () => {
  const { worker } = selectStagingConfig("staging");
  assert.equal(worker.name, "kadenco-control-plane-staging");
  assert.equal(worker.workersDev, false);
  assert.equal(worker.previewUrls, false);
  assert.deepEqual(Object.keys(worker.env), ["FLEETS"]);
  assert.deepEqual(worker.exports.FleetState, { type: "durable-object", storage: "sqlite" });
  assert.equal(worker.env.FLEETS.worker, worker.name);
  assert.equal("triggers" in worker, false);
  assert.equal("domains" in worker, false);
});
test("cf default, production and unknown modes refuse before resource provisioning", () => {
  for (const mode of [undefined, "production", "preview", "staging "])
    assert.throws(() => selectStagingConfig(mode), /explicit_staging_mode_required/);
});

test("cf Worker Preview evaluations refuse even when staging mode is selected", () => {
  assert.throws(() => selectStagingConfig("staging", true), /preview_deployment_disabled/);
});

import { sourcePreflight } from "../src/source-preflight.ts";
import { DatabaseSync } from "node:sqlite";
import { extractSnapshot } from "../src/migration-service.ts";
test("source preflight reports only aggregates and blocks oversized materialization before copying", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(
      "CREATE TABLE records(kind TEXT,id TEXT,value TEXT);CREATE TABLE audit(seq INTEGER PRIMARY KEY,at TEXT,action TEXT);CREATE TABLE diagnostics(seq INTEGER PRIMARY KEY,at TEXT,value TEXT)",
    );
    db.prepare("INSERT INTO records VALUES(?,?,?)").run(
      "command",
      "private-request",
      "PRIVATE_CIPHERTEXT",
    );
    assert.equal(sourcePreflight(db).fits_current_materialized_path, true);
    assert.equal(JSON.stringify(sourcePreflight(db)).includes("PRIVATE"), false);
    db.exec(
      "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10000) INSERT INTO audit(seq,at,action) SELECT x,'fixture','private-audit-text' FROM n",
    );
    const result = sourcePreflight(db);
    assert.equal(result.total_rows, 10001);
    assert.deepEqual(result.blockers, ["legacy_adoption_row_limit_exceeded"]);
    assert.throws(
      () => extractSnapshot(db, "fixture", "fixture-lineage", () => {}),
      /source_volume_requires_streaming_migration/,
    );
    assert.equal(db.prepare("SELECT COUNT(*) n FROM audit").get()!.n, 10000);
    assert.doesNotThrow(() => db.exec("BEGIN;ROLLBACK"));
    db.exec("UPDATE records SET value=replace(hex(zeroblob(17000)),'0','x')");
    assert.ok(sourcePreflight(db).blockers.includes("record_envelope_limit_exceeded"));
  } finally {
    db.close();
  }
});
test("source preflight refuses unknown record columns instead of claiming compatibility", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec("CREATE TABLE records(kind TEXT,id TEXT,value TEXT,unmapped TEXT)");
    assert.throws(() => sourcePreflight(db), /unsupported_source_schema/);
  } finally {
    db.close();
  }
});

test("source preflight includes exact serialized retained-history envelopes", () => {
  for (const table of ["audit", "diagnostics"]) {
    const db = new DatabaseSync(":memory:");
    try {
      db.exec(
        `CREATE TABLE records(kind TEXT,id TEXT,value TEXT);CREATE TABLE ${table}(seq INTEGER,value TEXT)`,
      );
      const put = db.prepare(`INSERT INTO ${table} VALUES(1,?)`);
      for (const value of ["x".repeat(32768), "\u0001".repeat(6000), "\u{1f600}".repeat(16384)]) {
        db.exec(`DELETE FROM ${table}`);
        put.run(value);
        const before = JSON.stringify(db.prepare(`SELECT * FROM ${table}`).get());
        assert.ok(before.length > 32768);
        const result = sourcePreflight(db);
        assert.equal(result.fits_current_materialized_path, false);
        assert.ok(result.blockers.includes("record_envelope_limit_exceeded"));
        assert.throws(
          () => extractSnapshot(db, "fixture", "fixture", () => {}),
          /source_volume_requires_streaming_migration/,
        );
        assert.equal(JSON.stringify(db.prepare(`SELECT * FROM ${table}`).get()), before);
      }
    } finally {
      db.close();
    }
  }
});

import { localArchiveReference } from "../src/local-archive.ts";
test("operational cutover retains local history reference while preserving every encrypted record", () => {
  const root = mkdtempSync(join(tmpdir(), "kadenco history archive "));
  const path = join(root, "archive.db"),
    db = new DatabaseSync(path);
  try {
    db.exec(
      "CREATE TABLE records(kind TEXT,id TEXT,value TEXT);CREATE TABLE audit(seq INTEGER PRIMARY KEY,action TEXT)",
    );
    db.prepare("INSERT INTO records VALUES(?,?,?)").run(
      "command",
      "uncertain-fixture",
      "opaque-envelope",
    );
    db.exec(
      "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<10001) INSERT INTO audit SELECT x,'retained-history' FROM n",
    );
    assert.equal(sourcePreflight(db).fits_current_materialized_path, false);
    assert.equal(sourcePreflight(db, "local_archive").fits_current_materialized_path, true);
    assert.throws(
      () => extractSnapshot(db, "fixture", "lineage", () => {}),
      /source_volume_requires_streaming_migration/,
    );
    const packet = extractSnapshot(db, "fixture", "lineage", () => {}, {
      verify: () => localArchiveReference(path),
    });
    assert.equal(packet.records.length, 2);
    assert.deepEqual(packet.records[0], {
      kind: "command",
      id: "uncertain-fixture",
      ciphertext: "opaque-envelope",
    });
    assert.equal(packet.records[1].kind, "$history_archive");
    assert.equal(JSON.parse(packet.records[1].ciphertext).audit_rows, 10001);
    assert.equal(JSON.stringify(packet).includes("retained-history"), false);
    assert.equal(db.prepare("SELECT COUNT(*) n FROM audit").get()!.n, 10001);
    const ref = localArchiveReference(path);
    assert.throws(
      () =>
        extractSnapshot(db, "fixture", "lineage", () => {}, {
          verify: () => ({ ...ref, audit_rows: 0 }),
        }),
      /local_archive_not_verified/,
    );
    let calls = 0;
    assert.throws(
      () =>
        extractSnapshot(db, "fixture", "lineage", () => {}, {
          verify: () => (calls++ ? { ...ref, archive_sha256: "b".repeat(64) } : ref),
        }),
      /local_archive_changed/,
    );
    assert.doesNotThrow(() => db.exec("BEGIN;ROLLBACK"));
  } finally {
    db.close();
    rmSync(root, { recursive: true, force: true });
  }
});

test("central callback receipts repair local views without sending, regressions or unbounded scans", async () => {
  const { reconcileCallbackReceipts } = await import("../src/edge-services.ts");
  const rows = new Map<string, any>();
  for (let n = 0; n < 102; n++) {
    const id = String(n).padStart(3, "0");
    rows.set(id, { id, status: "centralized", central_id: "central-" + id });
  }
  let calls = 0,
    mode = "pending",
    drift = false;
  const bridge = {
    store: {
      all: () => [...rows.values()],
      get: (_k: string, id: string) => rows.get(id),
      put: (_k: string, id: string, v: any) => rows.set(id, v),
    },
  } as any;
  const ports = {
    epoch: 7,
    async refreshLease() {},
    async call(op: string, p: any) {
      assert.equal(op, "outbox_receipt");
      calls++;
      if (drift) rows.set("000", { ...rows.get("000"), status: "revoked" });
      return {
        id: p.id,
        state: mode,
        attempts: 1,
        http_status: mode === "acknowledged" ? 200 : null,
        delivery_acknowledged: mode === "acknowledged",
        agent_completed: false,
      };
    },
  };
  const next = await reconcileCallbackReceipts(bridge, ports);
  assert.equal(calls, 100);
  assert.equal(next, "099");
  assert.equal(await reconcileCallbackReceipts(bridge, ports, next), undefined);
  assert.equal(calls, 102);
  assert.equal(rows.get("000").status, "centralized");
  mode = "acknowledged";
  drift = true;
  await reconcileCallbackReceipts(bridge, ports);
  assert.equal(rows.get("000").status, "revoked");
  assert.equal(rows.get("001").status, "acknowledged");
  const stable = structuredClone(rows.get("001"));
  mode = "pending";
  drift = false;
  await reconcileCallbackReceipts(bridge, ports);
  assert.deepEqual(rows.get("001"), stable);
  rows.clear();
  rows.set("one", { id: "one", status: "centralized", central_id: "central" });
  await assert.rejects(
    reconcileCallbackReceipts(bridge, {
      ...ports,
      async call() {
        return { reason: "forbidden" };
      },
    }),
    /forbidden/,
  );
  assert.equal(rows.get("one").status, "centralized");
  await assert.rejects(
    reconcileCallbackReceipts(bridge, {
      ...ports,
      async call() {
        return { id: "wrong", state: "acknowledged", agent_completed: false };
      },
    }),
    /central_receipt_invalid/,
  );
  mode = "stopped";
  await reconcileCallbackReceipts(bridge, ports);
  assert.equal(rows.get("one").status, "stopped");
});
