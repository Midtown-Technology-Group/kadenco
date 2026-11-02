// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { Store } from "../../../dist/store.mjs";
import { openStoreReplica } from "../src/store-replica.ts";
import { durableResponse } from "../src/durable-response.ts";
import { checkpointNativeEffects } from "../src/effect-checkpoint.ts";
import { centralTransport } from "../src/transport.ts";
import { projectNativeGrant } from "../src/grant-projection.ts";
import { authorizeBinding, tightensNativeGrant } from "../src/binding.ts";
import { reconcileExisting } from "../src/native-adapter.ts";

function centralFixture() {
  let revision = 0,
    writes = 0,
    loseResponse = false;
  const records = new Map<string, { kind: string; id: string; ciphertext: string }>();
  const receipts = new Map<string, { revision: number; value: string }>();
  const call = async (op: string, body: object): Promise<Record<string, unknown>> => {
    const p = body as Record<string, unknown>;
    if (op === "replica_head") return { revision };
    if (op === "replica_page") return { revision, records: [...records.values()], next: null };
    const id = String(p.request_id);
    if (op === "replica_receipt")
      return { committed: receipts.has(id), revision: receipts.get(id)?.revision ?? null };
    if (op !== "replica_apply") throw Error("unexpected_operation");
    const value = JSON.stringify(body);
    const old = receipts.get(id);
    if (old) {
      assert.equal(old.value, value);
      return { committed: true, revision: old.revision };
    }
    if (p.expected_revision !== revision) return { reason: "fenced" };
    for (const r of p.records as { kind: string; id: string; ciphertext: string }[])
      records.set(JSON.stringify([r.kind, r.id]), r);
    writes++;
    receipts.set(id, { revision: ++revision, value });
    if (loseResponse) {
      loseResponse = false;
      throw Error("lost_response");
    }
    return { committed: true, revision };
  };
  return {
    call,
    records,
    loseNextResponse() {
      loseResponse = true;
    },
    writes: () => writes,
    advance() {
      revision++;
    },
  };
}

test("record bounds reject before cache mutation or pending persistence and do not poison later flushes", async () => {
  const store = new Store(":memory:", randomBytes(32)),
    central = centralFixture();
  try {
    const replica = await openStoreReplica(store, 7, central.call);
    assert.throws(
      () => store.put("command", "oversized", { value: "x".repeat(40000) }),
      /replica_record_exceeds_central_limit/,
    );
    assert.throws(
      () => store.put("command", "😀".repeat(1025), { value: "valid" }),
      /replica_record_exceeds_central_limit/,
    );
    assert.throws(
      () =>
        store.db
          .prepare("INSERT INTO records VALUES(?,?,?)")
          .run("command", '"'.repeat(2048), "a".repeat(32000)),
      /replica_record_exceeds_central_limit/,
    );
    assert.throws(
      () =>
        store.db
          .prepare("INSERT INTO records VALUES(?,?,?)")
          .run("command", "escaped-envelope", "\\".repeat(15000)),
      /replica_record_exceeds_central_limit/,
    );
    assert.equal(store.db.prepare("SELECT COUNT(*) n FROM records").get()!.n, 0);
    assert.equal(store.db.prepare("SELECT COUNT(*) n FROM edge_replica_pending").get()!.n, 0);
    assert.equal(store.db.prepare("SELECT COUNT(*) n FROM edge_replica_changes").get()!.n, 0);
    store.put("command", "valid", { value: "normal record" });
    await replica.flush();
    assert.equal(central.writes(), 1);
    assert.deepEqual(store.get("command", "valid"), { value: "normal record" });
  } finally {
    store.close();
  }
});

test("native grant projection preserves original scope intersection and changes identity on authority/route drift", () => {
  const policy = {
    principals: [
      {
        id: "owner",
        readHosts: [{ host: "host", projectIds: ["a", "b"] }],
        commandHosts: [
          {
            host: "host",
            projectIds: ["b", "c"],
            providerInstanceIds: ["provider"],
            expiresAt: 10000,
            maxPerDay: 3,
            creationRuntime: { allowedModes: ["approval-required"] },
          },
        ],
      },
    ],
    fleetRead: { hosts: [{ name: "host", runtime: "original-read" }] },
    nativeDelivery: { hosts: [{ name: "host", command: "original-native" }] },
  };
  const project = (p = policy, purpose: "command" | "observation" = "command") =>
    projectNativeGrant(p as never, "owner", "host", purpose, 20000, 1000);
  const scope = project();
  assert.deepEqual(scope.projects, ["b"]);
  assert.deepEqual(scope.providers, ["provider"]);
  assert.equal(scope.expires, 10000);
  const read = project(policy, "observation");
  assert.equal(read.expires, 20000);
  assert.deepEqual(read.projects, ["a", "b"]);
  assert.equal(read.providers, null);
  assert.notEqual(scope.grant, read.grant);
  const changed = structuredClone(policy);
  changed.principals[0].commandHosts[0].maxPerDay = 4;
  assert.notEqual(project(changed).grant, scope.grant);
  changed.nativeDelivery.hosts[0].command = "another-native";
  assert.notEqual(project(changed).grant, scope.grant);
  const b = {
    project: "b",
    provider: "provider",
    run: "exact-current-run",
    grant: scope.grant,
    revision: 1,
    expires: 9000,
  };
  authorizeBinding(b, [], 1000, { host: "host", purpose: "command", grants: [scope] });
  for (const binding of [
    { ...b, project: "a" },
    { ...b, provider: "other" },
    { ...b, grant: "f".repeat(64) },
  ])
    assert.throws(
      () =>
        authorizeBinding(binding, [], 1000, { host: "host", purpose: "command", grants: [scope] }),
      /forbidden/,
    );
  assert.throws(
    () => authorizeBinding(b, [], 1000, { host: "other", purpose: "command", grants: [scope] }),
    /forbidden/,
  );
  assert.throws(
    () => authorizeBinding(b, [], 1000, { host: "host", purpose: "observation", grants: [scope] }),
    /forbidden/,
  );
  assert.equal(tightensNativeGrant({ ...scope, projects: null }, scope), false);
  assert.equal(tightensNativeGrant({ ...scope, expires: 9000 }, scope), true);
});

test("existing accepted follow-up and Standard no-op reconcile without another submission", async () => {
  const services = {
    async followupReceipt() {
      return { status: "accepted", messageId: "existing-native-message" };
    },
    settings: {
      receipt() {
        return { state: "noop", reason: "already_standard", native_submitted: false };
      },
    },
    async receipt() {
      throw Error("wrong_receipt_namespace");
    },
  };
  const base = { principal: "owner", request_id: "original", host: "host", thread_id: "thread" };
  assert.equal(
    (await reconcileExisting({ ...base, kind: "verify_result" } as never, services as never)).state,
    "observed",
  );
  assert.equal(
    (await reconcileExisting({ ...base, kind: "settings_standard" } as never, services as never))
      .state,
    "observed",
  );
  const missing = {
    ...services,
    async followupReceipt() {
      return { status: "accepted", messageId: "" };
    },
  };
  assert.equal(
    (await reconcileExisting({ ...base, kind: "verify_result" } as never, missing as never)).state,
    "unknown",
  );
});

test("encrypted cache recovers an uncertain commit by receipt after restart and hydrates only current central state", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-replica-")),
    key = randomBytes(32),
    central = centralFixture();
  const path = join(dir, "edge.db");
  let store = new Store(path, key);
  try {
    let replica = await openStoreReplica(store, 7, central.call);
    store.put("command", "original", { submission: "outcome_unknown", safe_to_resend: false });
    central.loseNextResponse();
    await assert.rejects(replica.flush(), /lost_response/);
    assert.equal(central.writes(), 1);
    store.close();
    store = new Store(path, key);
    replica = await openStoreReplica(store, 7, central.call);
    assert.equal(replica.revision(), 1);
    assert.equal(central.writes(), 1);
    const wrongKey = new Store(path, randomBytes(32));
    try {
      await assert.rejects(openStoreReplica(wrongKey, 7, central.call));
    } finally {
      wrongKey.close();
    }
    store.put("command", "original", { submission: "observed", safe_to_resend: false });
    await replica.flush();
    assert.equal(replica.revision(), 2);
    const replacement = new Store(join(dir, "replacement.db"), key);
    try {
      const recovered = await openStoreReplica(replacement, 7, central.call);
      assert.equal(recovered.revision(), 2);
      assert.equal(replacement.get("command", "original").submission, "observed");
      assert.throws(
        () => replacement.db.prepare("DELETE FROM records").run(),
        /replica_delete_not_supported/,
      );
    } finally {
      replacement.close();
    }
    central.advance();
    await assert.rejects(
      openStoreReplica(store, 7, central.call),
      /replica_current_state_required/,
    );
    assert.equal(store.get("command", "original").submission, "observed");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cache refuses incomplete/tampered bootstrap and persists request identity before any central write", async () => {
  const key = randomBytes(32),
    central = centralFixture(),
    store = new Store(":memory:", key);
  try {
    central.records.set("bad", {
      kind: "command",
      id: "bad",
      ciphertext: "not-an-authenticated-envelope",
    });
    await assert.rejects(openStoreReplica(store, 7, central.call));
    assert.equal(store.all("command").length, 0);
    central.records.clear();
    const replica = await openStoreReplica(store, 7, central.call);
    store.put("command", "new", { retained: true });
    const original = store.db.prepare.bind(store.db);
    store.db.prepare = ((sql: string) => {
      if (sql.startsWith("INSERT INTO edge_replica_pending")) throw Error("fixture_disk_failure");
      return original(sql);
    }) as typeof store.db.prepare;
    await assert.rejects(replica.flush(), /fixture_disk_failure/);
    assert.equal(central.writes(), 0);
    store.db.prepare = original;
    await replica.flush();
    assert.equal(central.writes(), 1);
    assert.equal(store.get("command", "new").retained, true);
  } finally {
    store.close();
  }
});

test("HTTP headers and body wait for durable commit; failure cannot look like success", async () => {
  let release!: () => void, entered!: () => void;
  const pending = new Promise<void>((resolve) => {
    release = resolve;
  });
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let fail = false,
    commits = 0;
  const server = createServer((_req, res) => {
    durableResponse(res, async () => {
      entered();
      await pending;
      if (fail) throw Error("commit_unavailable");
      commits++;
    });
    res.writeHead(200, { "content-type": "text/plain" });
    res.write("first");
    res.end("second");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = "http://127.0.0.1:" + (server.address() as { port: number }).port;
  try {
    let answered = false;
    const request = fetch(url).then((r) => {
      answered = true;
      return r;
    });
    await started;
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(answered, false);
    release();
    const response = await request;
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "firstsecond");
    assert.equal(commits, 2);
    fail = true;
    await assert.rejects(fetch(url));
  } finally {
    release();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("implicit headers and response buffer limits retain Node HTTP behavior", async () => {
  let overflow = false;
  const server = createServer((_req, res) => {
    durableResponse(res, async () => {}, 16);
    if (overflow) res.end("x".repeat(17));
    else res.end("implicit");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = "http://127.0.0.1:" + (server.address() as { port: number }).port;
  try {
    assert.equal(await (await fetch(url)).text(), "implicit");
    overflow = true;
    await assert.rejects(fetch(url));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("native effect checkpoint retains exact routes, final authorization and pending reservation", async () => {
  const store = new Store(":memory:", randomBytes(32)),
    central = centralFixture();
  let effects = 0,
    currentAuthority = true;
  const replica = await openStoreReplica(store, 7, central.call);
  const route = {
    authorizeDispatch() {
      if (!currentAuthority) throw Error("revoked");
    },
  };
  const bridge = {
    store,
    commands: {
      session: async (
        r: typeof route,
        fn: (call: (base: string, tag: string, p: unknown) => Promise<unknown>) => Promise<unknown>,
        options: unknown,
      ) => {
        assert.equal(r, route);
        assert.equal(options, "preserved-options");
        return fn(async (_base, tag, p) => {
          if (tag === "orchestration.dispatchCommand") {
            r.authorizeDispatch();
            assert.equal(central.records.has(JSON.stringify(["command", "original"])), true);
            effects++;
          }
          return p;
        });
      },
    },
    backend: {
      async followup() {
        effects++;
        return {};
      },
    },
  };
  const original = bridge.commands.session;
  const restore = checkpointNativeEffects(bridge as never, replica.flush);
  try {
    store.put("command", "original", { submission: "outcome_unknown", safe_to_resend: false });
    const payload = { commandId: "stable-original", threadId: "exact-thread" };
    await bridge.commands.session(
      route,
      async (call) => {
        assert.equal(
          await call("http://127.0.0.1:1", "orchestration.getThreadProjection", payload),
          payload,
        );
        assert.equal(central.writes(), 0);
        assert.equal(
          await call("http://127.0.0.1:1", "orchestration.dispatchCommand", payload),
          payload,
        );
      },
      "preserved-options",
    );
    assert.equal(effects, 1);
    currentAuthority = false;
    await assert.rejects(
      bridge.commands.session(
        route,
        (call) => call("http://127.0.0.1:1", "orchestration.dispatchCommand", payload),
        "preserved-options",
      ),
      /revoked/,
    );
    assert.equal(effects, 1);
  } finally {
    restore();
    assert.equal(bridge.commands.session, original);
    store.close();
  }
});

test("real workerd central store recovers lost commit response, fresh edge hydration and current recovery archive", async () => {
  const { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const { readFileSync, writeFileSync, mkdirSync } = await import("node:fs");
  const { fileURLToPath } = await import("node:url");
  const { createHash } = await import("node:crypto");
  const { captureRecovery, verifyRecovery } = await import("../src/recovery-archive.ts");
  const dir = mkdtempSync(join(tmpdir(), "kadenco-real-replica-"));
  // Test-only initial SQL, equivalent to the Workers suite's active() fixture.
  // Exact match prevents a changed schema silently weakening the production gate.
  const bundle = readFileSync(fileURLToPath(new URL("../dist/worker.js", import.meta.url)), "utf8");
  const inert = "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)";
  assert.equal(bundle.split(inert).length, 2);
  const fixtureBundle = bundle.replace(
    inert,
    "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)",
  );
  writeFileSync(join(dir, "fixture.js"), fixtureBundle);
  const hash = (s: string) => createHash("sha256").update(s).digest("hex");
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: fixtureBundle,
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      durableObjectsPersist: join(dir, "central-state"),
      bindings: {
        AUTH_POLICY: JSON.stringify({
          revision: 1,
          fleet: "fixture",
          principals: [
            {
              id: "edge",
              role: "executor",
              stateCustodian: true,
              tokenSha256: hash("fixture-edge"),
              hosts: ["fixture"],
              expiresAt: 4102444800000,
            },
            {
              id: "owner",
              role: "owner",
              migrationAuthority: true,
              tokenSha256: hash("fixture-owner"),
              hosts: ["fixture"],
              expiresAt: 4102444800000,
            },
          ],
        }),
      },
    }),
  );
  const key = randomBytes(32),
    path = join(dir, "edge.db");
  let store = new Store(path, key),
    lost = false;
  let drop = false;
  const transport = (token: string) =>
    centralTransport({
      origin: "https://fixture.invalid",
      token: () => token,
      fetch: async (url, init) => {
        const result = await mf.dispatchFetch(
          String(url),
          init as Parameters<typeof mf.dispatchFetch>[1],
        );
        if (drop && String(url).endsWith("/replica_apply")) {
          drop = false;
          lost = true;
          await result.body?.cancel();
          throw Error("fixture_response_lost_after_commit");
        }
        return result as unknown as Response;
      },
    });
  const edge = transport("fixture-edge");
  try {
    const lease = await edge("edge_lease", { epoch: 7 });
    assert.equal(lease.holder, "edge");
    const call = (op: string, p: object) =>
      edge(op, { ...p, epoch: 7, generation: lease.generation });
    let replica = await openStoreReplica(store, 7, call);
    store.put("command", "stable-uncertain", {
      request_id: "stable-uncertain",
      submission: "outcome_unknown",
      safe_to_resend: false,
    });
    drop = true;
    await assert.rejects(replica.flush(), /central_transport_uncertain/);
    assert.equal(lost, true);
    store.close();
    store = new Store(path, key);
    replica = await openStoreReplica(store, 7, call);
    assert.equal(replica.revision(), 1);
    assert.equal(store.get("command", "stable-uncertain").safe_to_resend, false);
    const fresh = new Store(join(dir, "fresh-edge.db"), key);
    try {
      const recovered = await openStoreReplica(fresh, 7, call);
      assert.equal(recovered.revision(), 1);
      assert.equal(fresh.get("command", "stable-uncertain").submission, "outcome_unknown");
    } finally {
      fresh.close();
    }
    // Exercise the actual composed sidecar and official MCP client, with no
    // native host, task, callback or production identity in this fixture.
    const { startSidecar } = await import("../../../dist/sidecar.mjs");
    const { createEdgeRuntime } = (await import(
      new URL("../dist/edge-runtime.mjs", import.meta.url).href
    )) as typeof import("../src/edge-runtime.ts");
    const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
    const { createServer: reservePort } = await import("node:net");
    const reservation = reservePort();
    await new Promise<void>((resolve) => reservation.listen(0, "127.0.0.1", resolve));
    const port = (reservation.address() as { port: number }).port;
    await new Promise<void>((resolve) => reservation.close(() => resolve()));
    const state = join(dir, "running-edge");
    mkdirSync(state, { mode: 0o700 });
    const configPath = join(dir, "edge-policy.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        port,
        stateDirectory: state,
        source: { type: "local-projection", databasePath: "fixture-unused" },
        callbackHosts: [],
        sessions: [],
        principals: [{ id: "owner", tokenSha256: hash("fixture-mcp-owner"), sessions: [] }],
      }),
    );
    const sidecar = await startSidecar({
      configPath,
      stateKey: key,
      backendFactory: () => ({
        supportsFollowup: false,
        async close() {},
        async read() {
          throw Error("no_native_host");
        },
        async followup() {
          throw Error("no_native_effect");
        },
      }),
      runtimeFactory: (bridge) =>
        createEdgeRuntime(bridge, {
          epoch: 7,
          executor: "edge",
          key,
          journalPath: join(state, "attempts.db"),
          executorCall: edge,
          async ownerCall() {
            throw Error("no_mutations_authorized");
          },
          async observationOwnerCall() {
            throw Error("no_subscriptions_authorized");
          },
          observationBinding() {
            throw Error("no_subscriptions_authorized");
          },
          async bind() {
            throw Error("no_mutations_authorized");
          },
          async currentGrant() {
            throw Error("no_mutations_authorized");
          },
          async observe() {
            return { state: "unknown", evidence: "fixture-read-only" };
          },
        }),
    });
    const client = new Client(
      { name: "fixture-only", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    try {
      await client.connect(
        new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
          requestInit: { headers: { authorization: "Bearer fixture-mcp-owner" } },
        }),
      );
      assert.ok((await client.listTools()).tools.some((t) => t.name === "list_sessions"));
      const result = await client.callTool({ name: "list_sessions", arguments: {} });
      assert.notEqual(result.isError, true);
    } finally {
      await client.close();
      await sidecar.shutdown();
    }
    const recoveryKey = randomBytes(32);
    const archive = await captureRecovery(transport("fixture-owner"), 7, recoveryKey);
    const { unseal } = await import("../src/authorization.ts");
    const envelope = unseal(archive.header, recoveryKey) as {
      header: { epoch: number; watermark: number };
    };
    const checked = verifyRecovery(archive, recoveryKey, envelope.header);
    assert.equal(checked.rows.filter((r) => r.table === "replica_receipts").length, 1);
    assert.equal(checked.rows.filter((r) => r.table === "replica_records").length, 1);
    assert.equal(checked.activation_permitted, false);
  } finally {
    store.close();
    await mf.dispose();
    rmSync(dir, { recursive: true, force: true });
  }
});
