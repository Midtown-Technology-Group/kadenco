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
