import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { SqliteJournal } from "../src/journal.ts";
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
  request_id: "12345678-1234-1234-1234-123456789abc",
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
