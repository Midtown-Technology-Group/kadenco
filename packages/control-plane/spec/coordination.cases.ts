import { env, exports } from "cloudflare:workers";
import { runInDurableObject, abortAllDurableObjects } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
const stub = () => env.FLEETS.getByName("test-fleet");
const call = async (op: string, body: object = {}, token = "synthetic-owner") => {
  const response = await exports.default.fetch(
    new Request("https://test.invalid/" + op, {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: JSON.stringify(
        op === "reserve"
          ? {
              binding: {
                project: "project",
                provider: "provider",
                run: "run",
                grant: "grant",
                revision: 1,
                expires: 4102444700000,
              },
              ...body,
            }
          : body,
      ),
    }),
  );
  return (await response.json()) as any;
};
async function active() {
  await runInDurableObject(stub(), (_obj, state) => {
    state.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
  });
}
const reserve = (id: string) =>
  call("reserve", {
    epoch: 7,
    request_id: id,
    host: "local",
    thread_id: "exact-thread",
    kind: "continue",
    payload_sha256: "a".repeat(64),
  });
const claim = (id: string) =>
  call("claim", { epoch: 7, request_id: id, lease_ms: 1000 }, "synthetic-agent");
describe("real SQLite DO coordination", () => {
  beforeEach(async () => {
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec(
        "DELETE FROM auth_policy; DELETE FROM revoked; DELETE FROM commands; DELETE FROM imported; DELETE FROM audit; UPDATE control SET epoch=0,mode='staging',migration=NULL WHERE id=1;",
      );
    });
  });
  it("stays inert by default; staged import is atomic, replayable and cannot activate", async () => {
    expect(await reserve("off")).toEqual({ reason: "not_active" });
    const batch = {
      migration_id: "migration-1",
      records: [{ kind: "subscription", id: "original-id", ciphertext: "original-envelope" }],
    };
    expect(await call("import", batch)).toMatchObject({ stored: 1, active: false });
    expect(await call("import", batch)).toMatchObject({ stored: 1 });
    expect(
      await call("import", {
        ...batch,
        records: [
          { kind: "receipt", id: "new", ciphertext: "x" },
          { ...batch.records[0], ciphertext: "changed" },
        ],
      }),
    ).toEqual({ reason: "idempotency_conflict" });
    await runInDurableObject(stub(), (_obj, state) => {
      expect(state.storage.sql.exec("SELECT * FROM imported").toArray()).toHaveLength(1);
    });
    expect(await call("activate", { expected_epoch: 0, migration_id: "migration-1" })).toEqual({
      reason: "cutover_not_implemented",
    });
  });
  it("checks auth, target bounds, roles, revocation and request identity", async () => {
    await active();
    expect(await call("status", {}, "wrong")).toEqual({ reason: "forbidden" });
    expect(
      await call("reserve", {
        epoch: 7,
        request_id: "foreign",
        host: "other",
        thread_id: "t",
        kind: "continue",
        payload_sha256: "a".repeat(64),
      }),
    ).toEqual({ reason: "forbidden" });
    await reserve("stable");
    expect(await reserve("stable")).toMatchObject({ id: "stable", state: "pending" });
    expect(
      await call("reserve", {
        epoch: 7,
        request_id: "stable",
        host: "local",
        thread_id: "different",
        kind: "continue",
        payload_sha256: "a".repeat(64),
      }),
    ).toEqual({ reason: "idempotency_conflict" });
    expect(await call("revoke", { principal_id: "owner" }, "synthetic-agent")).toEqual({
      reason: "forbidden",
    });
    await call("revoke", { principal_id: "agent" });
    expect(await claim("stable")).toEqual({ reason: "forbidden" });
  });
  it("has one winner, fences expired claims and never reassigns uncertain external effects", async () => {
    await active();
    await reserve("race");
    const results = await Promise.all([claim("race"), claim("race")]);
    expect(results.filter((r) => r.claimed)).toHaveLength(1);
    const first = results.find((r) => r.claimed);
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE commands SET lease_until=0 WHERE id='race'");
    });
    const next = await claim("race");
    expect(next.generation).toBe(first.generation + 1);
    expect(
      await call(
        "begin",
        { epoch: 7, request_id: "race", generation: first.generation },
        "synthetic-agent",
      ),
    ).toEqual({ reason: "fenced" });
    expect(
      await call(
        "begin",
        { epoch: 7, request_id: "race", generation: next.generation },
        "synthetic-agent",
      ),
    ).toMatchObject({ may_attempt: true });
    await abortAllDurableObjects();
    expect(await claim("race")).toMatchObject({ claimed: false, state: "uncertain" });
    // Crash/partition after an effect but before receipt: only exact reconciliation may complete it.
    const receipt = { native_request_id: "native-stable", outcome: "completed" };
    expect(
      await call(
        "record_receipt",
        { epoch: 7, request_id: "race", generation: next.generation, receipt },
        "synthetic-agent",
      ),
    ).toEqual({ receipt_recorded: true, native_execution_verified: false });
    expect(
      await call(
        "record_receipt",
        { epoch: 7, request_id: "race", generation: next.generation, receipt },
        "synthetic-agent",
      ),
    ).toEqual({ receipt_recorded: true, native_execution_verified: false });
    expect(
      await call(
        "record_receipt",
        {
          epoch: 7,
          request_id: "race",
          generation: next.generation,
          receipt: { outcome: "different" },
        },
        "synthetic-agent",
      ),
    ).toEqual({ reason: "immutable_outcome" });
  });
  it("old worker revival cannot mutate after epoch changes; reservations survive reconstruction", async () => {
    await active();
    await reserve("epoch");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE control SET epoch=8 WHERE id=1");
    });
    expect(await claim("epoch")).toEqual({ reason: "fenced" });
    await abortAllDurableObjects();
    expect(await call("receipt", { request_id: "epoch" })).toMatchObject({
      id: "epoch",
      safe_to_resend: false,
    });
  });
  it("revocation committed while request I/O awaits is enforced at mutation time", async () => {
    await active();
    await reserve("await-revocation");
    let controller!: ReadableStreamDefaultController<Uint8Array>;
    const body = new ReadableStream<Uint8Array>({
      start(c) {
        controller = c;
      },
    });
    const pending = exports.default.fetch(
      new Request("https://test.invalid/claim", {
        method: "POST",
        headers: { authorization: "Bearer synthetic-agent", "content-type": "application/json" },
        body,
      }),
    );
    await call("revoke", { principal_id: "agent" });
    controller.enqueue(
      new TextEncoder().encode(
        JSON.stringify({ epoch: 7, request_id: "await-revocation", lease_ms: 1000 }),
      ),
    );
    controller.close();
    expect(await (await pending).json()).toEqual({ reason: "forbidden" });
  });
  it("originator revocation before claim and before begin denies dispatch", async () => {
    await active();
    await reserve("origin-revoked");
    await reserve("origin-pending");
    const claimed = await claim("origin-revoked");
    await call("revoke", { principal_id: "owner" }, "synthetic-owner2");
    expect(await claim("origin-pending")).toEqual({ reason: "forbidden" });
    expect(await claim("origin-revoked")).toEqual({ reason: "forbidden" });
    expect(
      await call(
        "begin",
        { epoch: 7, request_id: "origin-revoked", generation: claimed.generation },
        "synthetic-agent",
      ),
    ).toEqual({ reason: "forbidden" });
  });
  it("policy tightening persists across stale bootstrap/reconstruction and applies owner expiry and host removal", async () => {
    await active();
    await reserve("tightened");
    const current = await runInDurableObject(stub(), (_obj, state) =>
      JSON.parse(
        state.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
      ),
    );
    current.revision = 2;
    current.principals.find((p: any) => p.id === "owner").expiresAt = 1;
    expect(
      await call("tighten_policy", { expected_revision: 1, policy: current }, "synthetic-owner2"),
    ).toEqual({ revision: 2 });
    await abortAllDurableObjects();
    expect(await claim("tightened")).toEqual({ reason: "forbidden" });
    current.revision = 3;
    current.principals.find((p: any) => p.id === "agent").hosts = [];
    expect(
      await call("tighten_policy", { expected_revision: 2, policy: current }, "synthetic-owner2"),
    ).toEqual({ revision: 3 });
    expect(await claim("tightened")).toEqual({ reason: "forbidden" });
    current.revision = 4;
    current.principals.find((p: any) => p.id === "agent").hosts = ["local"];
    expect(
      await call("tighten_policy", { expected_revision: 3, policy: current }, "synthetic-owner2"),
    ).toEqual({ reason: "forbidden" });
  });
  it("different executors compete once; second begin fails and recorded receipts survive restart", async () => {
    await active();
    await reserve("different-executors");
    const attempts = await Promise.all([
      claim("different-executors"),
      call(
        "claim",
        { epoch: 7, request_id: "different-executors", lease_ms: 1000 },
        "synthetic-agent2",
      ),
    ]);
    const winner = attempts.find((r) => r.claimed);
    expect(attempts.filter((r) => r.claimed)).toHaveLength(1);
    const token = winner.executor === "agent" ? "synthetic-agent" : "synthetic-agent2";
    const input = { epoch: 7, request_id: "different-executors", generation: winner.generation };
    expect(await call("begin", input, token)).toMatchObject({ may_attempt: true });
    expect(await call("begin", input, token)).toEqual({ reason: "fenced" });
    const receipt = { native_request_id: "exact-native-id", observed: "terminal" };
    await call("record_receipt", { ...input, receipt }, token);
    await abortAllDurableObjects();
    expect(await call("receipt", { request_id: input.request_id })).toMatchObject({
      state: "receipted",
      receipt,
    });
    expect(await call("record_receipt", { ...input, receipt }, token)).toMatchObject({
      receipt_recorded: true,
    });
    expect(
      await call("record_receipt", { ...input, receipt: { observed: "changed" } }, token),
    ).toEqual({ reason: "immutable_outcome" });
    expect(await call("receipt", { request_id: input.request_id }, "synthetic-owner2")).toEqual({
      reason: "forbidden",
    });
    expect(
      await call(
        "reserve",
        {
          epoch: 7,
          request_id: input.request_id,
          host: "local",
          thread_id: "exact-thread",
          kind: "continue",
          payload_sha256: "a".repeat(64),
        },
        "synthetic-owner2",
      ),
    ).toEqual({ reason: "idempotency_conflict" });
  });
  it("unauthorized streamed requests finish body transfer before response", async () => {
    const stream = new TransformStream<Uint8Array, Uint8Array>();
    const writer = stream.writable.getWriter();
    const pending = exports.default.fetch(
      new Request("https://test.invalid/claim", {
        method: "POST",
        headers: { authorization: "Bearer invalid", "content-type": "application/json" },
        body: stream.readable,
      }),
    );
    await writer.write(new TextEncoder().encode("{}"));
    await writer.close();
    expect(await (await pending).json()).toEqual({ reason: "forbidden" });
  });
  it("malformed JSON stays a client error while storage failure is a sanitized server fault", async () => {
    const malformed = await exports.default.fetch(
      new Request("https://test.invalid/status", {
        method: "POST",
        headers: { authorization: "Bearer synthetic-owner", "content-type": "application/json" },
        body: "{",
      }),
    );
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ reason: "invalid_request" });
    await call("status");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("DROP TABLE commands");
    });
    const response = await stub().fetch(
      new Request("https://test.invalid/status", {
        method: "POST",
        headers: { authorization: "Bearer synthetic-owner", "content-type": "application/json" },
        body: "{}",
      }),
    );
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ reason: "internal_error", safe_to_resend: false });
    await abortAllDurableObjects();
  });
  it("forwarding rejection yields an uncertain controlled response without exposing failure text", async () => {
    await call("status");
    const config = await runInDurableObject(
      stub(),
      (_obj, state) =>
        state.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
    );
    const handler = (await import("../src/worker")).default;
    const response = await handler.fetch(
      new Request("https://test.invalid/status", {
        method: "POST",
        headers: { authorization: "Bearer synthetic-owner", "content-type": "application/json" },
        body: "{}",
      }),
      {
        AUTH_POLICY: config,
        FLEETS: {
          getByName: () => ({
            fetch: async () => {
              throw Error("sensitive detail");
            },
          }),
        },
      } as any,
    );
    expect(response.status).toBe(503);
    expect(await response.json()).toEqual({ reason: "forwarding_failed", safe_to_resend: false });
  });
});
import { consume, type EdgePorts } from "../src/edge";
import { verifyMigration } from "../src/migration";

describe("inert edge and migration preparation", () => {
  const command = { request_id: "stable-id", epoch: 7, host: "local", thread_id: "exact-thread" };
  function fixture() {
    const attempts = new Set<string>();
    let executions = 0,
      begins = 0,
      loseBegin = false,
      loseReceipt = false;
    const ports: EdgePorts = {
      journal: {
        async reserve(id) {
          if (attempts.has(id)) return false;
          attempts.add(id);
          return true;
        },
        async finish() {},
      },
      async validate() {},
      async execute() {
        executions++;
        return { state: "observed", evidence: "native-receipt" };
      },
      async observe() {
        return { state: "unknown", evidence: "read-only" };
      },
      async call(op) {
        if (op === "receipt") return { state: "pending" };
        if (op === "claim")
          return { claimed: true, generation: 1, host: command.host, thread: command.thread_id };
        if (op === "begin") {
          begins++;
          if (loseBegin) throw Error("partition");
          return { may_attempt: true, request_id: command.request_id, generation: 1 };
        }
        if (loseReceipt) throw Error("partition");
        return { receipt_recorded: true };
      },
    };
    return {
      ports,
      counts: () => ({ executions, begins }),
      loseBegin: () => {
        loseBegin = true;
      },
      loseReceipt: () => {
        loseReceipt = true;
      },
    };
  }
  it("lost begin and reconstructed consumer never replay the native effect", async () => {
    const f = fixture();
    f.loseBegin();
    expect((await consume(command, f.ports)).state).toBe("reconcile");
    await consume(command, { ...f.ports });
    expect(f.counts()).toEqual({ executions: 0, begins: 1 });
  });
  it("lost receipt and duplicate input execute once", async () => {
    const f = fixture();
    f.loseReceipt();
    await consume(command, f.ports);
    await consume(command, f.ports);
    expect(f.counts()).toEqual({ executions: 1, begins: 1 });
  });
  it("revocation at final validation prevents begin", async () => {
    const f = fixture();
    let checks = 0;
    f.ports.validate = async () => {
      if (++checks === 2) throw Error("revoked");
    };
    await expect(consume(command, f.ports)).rejects.toThrow("revoked");
    expect(f.counts()).toEqual({ executions: 0, begins: 0 });
  });
  it("competing consumers use atomic durable attempt reservation", async () => {
    const f = fixture();
    await Promise.all([consume(command, f.ports), consume(command, f.ports)]);
    expect(f.counts()).toEqual({ executions: 1, begins: 1 });
  });
  it("manifest compares exact identities and rejects revival, gaps and uncertain effects", () => {
    const manifest = {
      migration_id: "migration",
      source_snapshot: "snapshot",
      encryption_provenance: "key-lineage",
      records: [{ kind: "receipt", id: "id", sha256: "a".repeat(64) }],
    };
    const quiet = {
      snapshot: "snapshot",
      pending_native_effects: 0,
      old_writer_retirement: "externally_enforced" as const,
    };
    expect(verifyMigration(manifest, manifest, quiet)).toEqual({
      consistent: true,
      errors: [],
      activation_permitted: false,
    });
    expect(verifyMigration(manifest, { ...manifest, records: [] }, quiet).consistent).toBe(false);
    expect(
      verifyMigration(manifest, manifest, {
        ...quiet,
        old_writer_retirement: "unverified",
        pending_native_effects: 1,
      }).errors,
    ).toEqual(["unreconciled_effects", "old_writer_not_retired"]);
    expect(
      verifyMigration(
        manifest,
        { ...manifest, records: [...manifest.records, ...manifest.records] },
        quiet,
      ).consistent,
    ).toBe(false);
  });
});

describe("edge runner against real DO", () => {
  it("records one synthetic effect and reconnect reads its immutable receipt", async () => {
    await call("status");
    await active();
    const id = "edge-real-" + crypto.randomUUID();
    await reserve(id);
    let effects = 0;
    const seen = new Set<string>();
    const ports: EdgePorts = {
      call: (op, body) => call(op, body, "synthetic-agent"),
      journal: {
        async reserve(key) {
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        },
        async finish() {},
      },
      async validate() {},
      async execute() {
        effects++;
        return { state: "observed", evidence: "synthetic-only" };
      },
      async observe() {
        return { state: "unknown", evidence: "read-only" };
      },
    };
    const command = { request_id: id, epoch: 7, host: "local", thread_id: "exact-thread" };
    expect((await consume(command, ports)).state).toBe("recorded");
    expect((await consume(command, ports)).state).toBe("receipted");
    expect(effects).toBe(1);
  });
});

import { importVerified } from "../src/import-service.ts";
import { signedSnapshot, manifestOf } from "../src/snapshot.ts";
import {
  consumeAuthorized,
  seal,
  validateOperation,
  type Envelope,
  type Grant,
} from "../src/authorization.ts";
import { dispatchExisting } from "../src/native-adapter.ts";
import { randomBytes } from "node:crypto";
describe("integrated local source acceptance", () => {
  it("signed inventory roundtrip rejects partial import and keeps activation closed", async () => {
    await runInDurableObject(stub(), (_o, s) => {
      s.storage.sql.exec("DELETE FROM imported");
      s.storage.sql.exec("UPDATE control SET mode='staging',migration=NULL WHERE id=1");
    });
    const snapshot = {
      migration_id: "roundtrip",
      source_snapshot: "quiesced-fixture",
      encryption_provenance: "test-key-lineage",
      records: Array.from({ length: 105 }, (_, i) => ({
        kind: "receipt",
        id: String(i).padStart(3, "0"),
        ciphertext: "original-" + i,
      })),
    };
    const key = randomBytes(32),
      packet = signedSnapshot(snapshot, key),
      expected = manifestOf(snapshot);
    await expect(
      importVerified(packet, key, expected, async (op, p) =>
        op === "import" ? { stored: 0, active: false } : call(op, p),
      ),
    ).rejects.toThrow("partial_import");
    expect(await importVerified(packet, key, expected, call)).toEqual({
      verified_records: 105,
      activation_permitted: false,
    });
    expect(await call("activate", { expected_epoch: 7, migration_id: "roundtrip" })).toHaveProperty(
      "reason",
    );
  });
  it("central bound reservation through persistent SQLite edge journal and exact mock native service", async () => {
    await active();
    const key = randomBytes(32);
    const e: Envelope = {
      request_id: crypto.randomUUID(),
      fleet: "test-fleet",
      principal: "owner",
      host: "local",
      project: "project",
      provider: "provider",
      thread_id: "exact-thread",
      run: "run",
      grant: "grant",
      revision: 1,
      expires: 4102444700000,
      kind: "continue",
      payload: { text: "harmless fixture" },
    };
    const g: Grant = { ...e, expires: 4102444800000, revoked: false, kinds: ["continue"] };
    const binding = {
      project: e.project,
      provider: e.provider,
      run: e.run,
      grant: e.grant,
      revision: e.revision,
      expires: e.expires,
    };
    expect(
      await call("reserve", {
        epoch: 7,
        request_id: e.request_id,
        host: e.host,
        thread_id: e.thread_id,
        kind: e.kind,
        payload_sha256: validateOperation(e, g, Date.now()),
        binding,
      }),
    ).toHaveProperty("state", "pending");
    const observed: unknown[] = [];
    const services = {
      async continue(owner: string, p: unknown) {
        observed.push({ owner, p });
        return { native_submitted: true, request_id: e.request_id };
      },
      creation: {
        async create() {
          throw Error("unexpected");
        },
      },
      settings: {
        async standard() {
          throw Error("unexpected");
        },
      },
      async receipt() {
        return null;
      },
    };
    const ports = {
      call: (op: string, p: object) => call(op, p, "synthetic-agent"),
      journal: {
        async reserve(id: string) {
          return runInDurableObject(stub(), (_o, s) => {
            s.storage.sql.exec(
              "CREATE TABLE IF NOT EXISTS edge_attempts(id TEXT PRIMARY KEY,outcome TEXT)",
            );
            return (
              s.storage.sql
                .exec("INSERT OR IGNORE INTO edge_attempts VALUES(?,NULL) RETURNING id", id)
                .toArray().length === 1
            );
          });
        },
        async finish(id: string, outcome: unknown) {
          await runInDurableObject(stub(), (_o, s) => {
            s.storage.sql.exec(
              "UPDATE edge_attempts SET outcome=? WHERE id=?",
              JSON.stringify(outcome),
              id,
            );
          });
        },
      },
      async validate() {},
      execute: () => dispatchExisting(e, services),
      async observe() {
        return { state: "unknown" as const, evidence: "read-only" };
      },
    };
    expect(
      (await consumeAuthorized(seal(e, key), key, async () => g, Date.now, 7, ports)).state,
    ).toBe("recorded");
    await abortAllDurableObjects();
    expect(
      (await consumeAuthorized(seal(e, key), key, async () => g, Date.now, 7, ports)).state,
    ).toBe("receipted");
    expect(observed).toEqual([
      {
        owner: "owner",
        p: {
          host: "local",
          thread_id: "exact-thread",
          request_id: e.request_id,
          source_run_id: "run",
          message: "harmless fixture",
          execution: "allow_new_turn",
        },
      },
    ]);
  });
  it("central operation scope drift and stale origin policy block dispatch", async () => {
    await active();
    for (const field of ["project", "provider", "run", "grant", "revision"]) {
      const binding = {
        project: "project",
        provider: "provider",
        run: "run",
        grant: "grant",
        revision: 1,
        expires: 4102444700000,
        [field]: field === "revision" ? 2 : "wrong",
      };
      expect(
        await call("reserve", {
          epoch: 7,
          request_id: crypto.randomUUID(),
          host: "local",
          thread_id: "exact-thread",
          kind: "continue",
          payload_sha256: "a".repeat(64),
          binding,
        }),
      ).toEqual({ reason: "forbidden" });
    }
  });
});

describe("persisted operation scope revocation", () => {
  it("removing a grant after reserve denies begin without effect", async () => {
    await active();
    await reserve("scope-revoked");
    const c = await claim("scope-revoked");
    expect(c.claimed).toBe(true);
    await runInDurableObject(stub(), (_o, s) => {
      const row = s.storage.sql
        .exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1")
        .one();
      const p = JSON.parse(row.value);
      p.principals.find((a: { id: string }) => a.id === "owner").scopes = [];
      p.revision++;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    expect(
      await call(
        "begin",
        { epoch: 7, request_id: "scope-revoked", generation: c.generation },
        "synthetic-agent",
      ),
    ).toEqual({ reason: "forbidden" });
  });
});

describe("central observation, outbox and shared budgets", () => {
  const binding = {
    project: "project",
    provider: "provider",
    run: "run",
    grant: "grant",
    revision: 1,
    expires: 4102444700000,
  };
  async function reset() {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const table of [
        "subscriptions",
        "observations",
        "outbox",
        "edge_lease",
        "budget_reservations",
        "commands",
        "revoked",
        "auth_policy",
      ])
        s.storage.sql.exec(`DELETE FROM ${table}`);
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
  }
  const subscribe = (id = "standing") =>
    call("subscribe_central", {
      epoch: 7,
      id,
      host: "local",
      thread_id: "thread",
      binding,
      expires: null,
      name: "t3.thread.activity",
      callback_reference: "existing-signer-reference",
    });
  const observe = (id = "standing", cursor = 1) =>
    call(
      "observe_central",
      {
        epoch: 7,
        subscription_id: id,
        expected_cursor: cursor - 1,
        cursor,
        run: "run",
        kind: "completed",
        native_request_id: "native-event",
        event: {
          eventId: "existing-event-id",
          name: "t3.thread.activity",
          data: { result: "harmless" },
        },
      },
      "synthetic-agent",
    );
  it("preserves subscription identity/null expiry; duplicate observation and cursor race do not duplicate delivery", async () => {
    await reset();
    expect(await subscribe()).toMatchObject({ id: "standing", expires: null });
    const first = await observe();
    expect(first.duplicate).toBe(false);
    expect(await observe()).toMatchObject({ duplicate: true, id: first.id });
    expect(
      await call("subscribe_central", {
        epoch: 7,
        id: "standing",
        host: "local",
        thread_id: "other",
        binding,
        expires: null,
        name: "t3.thread.activity",
        callback_reference: "existing-signer-reference",
      }),
    ).toEqual({ reason: "idempotency_conflict" });
    const claims = await Promise.all([
      call("outbox_claim", { epoch: 7, id: first.id }, "synthetic-agent"),
      call("outbox_claim", { epoch: 7, id: first.id }, "synthetic-agent2"),
    ]);
    expect(claims.filter((v) => v.claimed)).toHaveLength(1);
  });
  it("callback retry retains event ID, HTTP ack is not agent completion, and revocation denies dispatch", async () => {
    await reset();
    await subscribe();
    const event = await observe();
    const claim = await call("outbox_claim", { epoch: 7, id: event.id }, "synthetic-agent");
    const args = { epoch: 7, id: event.id, generation: claim.generation };
    const first = await call("outbox_begin", args, "synthetic-agent");
    expect(first.may_attempt).toBe(true);
    expect(
      await call("outbox_result", { ...args, http_status: 503 }, "synthetic-agent"),
    ).toMatchObject({ state: "pending", agent_completed: false });
    await runInDurableObject(stub(), (_o, s) =>
      s.storage.sql.exec("UPDATE outbox SET next=0,lease=NULL WHERE id=?", event.id),
    );
    const retry = await call("outbox_claim", { epoch: 7, id: event.id }, "synthetic-agent2");
    const second = await call(
      "outbox_begin",
      { epoch: 7, id: event.id, generation: retry.generation },
      "synthetic-agent2",
    );
    expect(second.event_id).toBe(first.event_id);
    expect(
      await call(
        "outbox_result",
        { epoch: 7, id: event.id, generation: retry.generation, http_status: 204 },
        "synthetic-agent2",
      ),
    ).toMatchObject({ delivery_acknowledged: true, agent_completed: false });
    expect(await call("outbox_claim", { epoch: 7, id: event.id }, "synthetic-agent")).toMatchObject(
      { claimed: false, state: "acknowledged" },
    );
    await call("revoke", { principal_id: "owner" });
    expect(await observe()).toEqual({ reason: "forbidden" });
  });
  it("expired subscription and another owner's scope cannot deliver", async () => {
    await reset();
    await subscribe();
    const event = await observe();
    await runInDurableObject(stub(), (_o, s) =>
      s.storage.sql.exec("UPDATE subscriptions SET expires=1 WHERE id='standing'"),
    );
    expect(await call("outbox_claim", { epoch: 7, id: event.id }, "synthetic-agent")).toEqual({
      reason: "forbidden",
    });
    expect(
      await call("unsubscribe_central", { epoch: 7, id: "standing" }, "synthetic-owner2"),
    ).toEqual({ reason: "forbidden" });
  });
  it("atomic host budget covers different command kinds and duplicates retain spent uncertainty", async () => {
    await reset();
    await runInDurableObject(stub(), (_o, s) => {
      const raw = s.storage.sql
        .exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1")
        .one();
      const p = JSON.parse(raw.value);
      p.principals.find((v: { id: string }) => v.id === "owner").maxPerDay = 1;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    const first = await reserve("budget-one");
    expect(first.state).toBe("pending");
    expect((await reserve("budget-one")).state).toBe("pending");
    expect(
      await call("reserve", {
        epoch: 7,
        request_id: "budget-two",
        host: "local",
        thread_id: "exact-thread",
        kind: "settings_standard",
        payload_sha256: "a".repeat(64),
      }),
    ).toEqual({ reason: "command_budget_exhausted" });
    await abortAllDurableObjects();
    expect((await reserve("budget-one")).state).toBe("pending");
    expect(await reserve("budget-three")).toEqual({ reason: "command_budget_exhausted" });
  });
  it("cooperating edge lease fences another executor and stale renewal", async () => {
    await reset();
    const lease = await call("edge_lease", { epoch: 7 }, "synthetic-agent");
    expect(lease.holder).toBe("agent");
    expect(await call("edge_lease", { epoch: 7 }, "synthetic-agent2")).toEqual({
      reason: "fenced",
    });
    expect(
      await call("edge_lease", { epoch: 7, generation: lease.generation + 1 }, "synthetic-agent"),
    ).toEqual({ reason: "fenced" });
  });
});

describe("central per-thread provider caps", () => {
  it("shares the thread/provider cap across continue and settings without changing host unlimited policy", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      s.storage.sql.exec("DELETE FROM auth_policy");
      s.storage.sql.exec("DELETE FROM commands");
      s.storage.sql.exec("DELETE FROM budget_reservations");
      s.storage.sql.exec("DELETE FROM revoked");
    });
    await call("status");
    await active();
    await runInDurableObject(stub(), (_o, s) => {
      const raw = s.storage.sql
        .exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1")
        .one();
      const p = JSON.parse(raw.value);
      p.principals.find((v: { id: string }) => v.id === "owner").threadBudgets = [
        { thread: "exact-thread", provider: "provider", maxPerDay: 1, expiresAt: 4102444800000 },
      ];
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    expect((await reserve("thread-budget-one")).state).toBe("pending");
    expect(
      await call("reserve", {
        epoch: 7,
        request_id: "thread-budget-two",
        host: "local",
        thread_id: "exact-thread",
        kind: "settings_standard",
        payload_sha256: "a".repeat(64),
      }),
    ).toEqual({ reason: "command_budget_exhausted" });
  });
});

import { observeExisting, deliverClaimed, existingCallback } from "../src/edge-services.ts";
describe("real central outbox with existing edge service adapters", () => {
  it("observes, claims and signs one original callback without starting native work", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const table of ["auth_policy", "revoked", "subscriptions", "observations", "outbox"])
        s.storage.sql.exec(`DELETE FROM ${table}`);
    });
    await call("status");
    await active();
    const event = {
      eventId: "original-callback-id",
      name: "t3.eddie.requested",
      data: { request_id: "native-request", host: "local", thread_id: "thread", run_id: "run" },
    };
    const sub = {
      id: "original-standing-sub",
      owner: "owner",
      host: "local",
      threadId: "thread",
      active: true,
      expires: null,
      nonExpiring: true,
      name: event.name,
      url: "https://fixture.invalid/callback",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    };
    const records = new Map<string, any>([
      ["subscription:" + sub.id, sub],
      ["delivery:queued", { id: "queued", subId: sub.id, status: "pending", event }],
    ]);
    let posts = 0;
    const bridge = {
      now: Date.now,
      store: {
        get: (kind: string, id: string) => records.get(kind + ":" + id),
        all: (kind: string) =>
          [...records].filter(([key]) => key.startsWith(kind + ":")).map(([, v]) => v),
        put: (kind: string, id: string, v: unknown) => records.set(kind + ":" + id, v),
      },
      async observe() {},
      fleetEvents: { async observe() {} },
      exchanges: { async deliverable() {} },
      async post(_url: string, headers: Record<string, string>, body: string) {
        posts++;
        expect(headers["webhook-id"]).toBe(event.eventId);
        expect(headers["X-MCP-Subscription-Id"]).toBe(sub.id);
        expect(JSON.parse(body)).toEqual(event);
        return { status: 204 };
      },
    } as any;
    const results = await observeExisting(bridge, {
      epoch: 7,
      async refreshLease() {},
      ownerCall: call,
      executorCall: (op, p) => call(op, p, "synthetic-agent"),
      binding: () => ({
        project: "project",
        provider: "provider",
        run: "run",
        grant: "grant",
        revision: 1,
        expires: 4102444700000,
      }),
    });
    expect(results).toHaveLength(1);
    const result = await deliverClaimed(results[0].id, {
      epoch: 7,
      call: (op, p) => call(op, p, "synthetic-agent"),
      postExisting: existingCallback(bridge),
    });
    expect(result).toMatchObject({ state: "acknowledged", agent_completed: false });
    expect(posts).toBe(1);
    expect(
      (
        await deliverClaimed(results[0].id, {
          epoch: 7,
          call: (op, p) => call(op, p, "synthetic-agent2"),
          postExisting: existingCallback(bridge),
        })
      ).state,
    ).toBe("blocked");
    expect(posts).toBe(1);
  });
});

import { centralCoordinator } from "../src/coordinator.ts";
import { gateEdgeMutations } from "../src/mutation-gate.ts";
describe("MCP/collaboration native mutation gate uses central protocol", () => {
  it("central reservation and durable attempt precede exact existing service execution; replay returns original receipt", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const table of ["auth_policy", "revoked", "commands", "budget_reservations"])
        s.storage.sql.exec(`DELETE FROM ${table}`);
    });
    await call("status");
    await active();
    const e: Envelope = {
      request_id: crypto.randomUUID(),
      fleet: "test-fleet",
      principal: "owner",
      host: "local",
      project: "project",
      provider: "provider",
      thread_id: "exact-thread",
      run: "run",
      grant: "grant",
      revision: 1,
      expires: 4102444700000,
      kind: "continue",
      payload: { text: "exact harmless input" },
    };
    const g: Grant = { ...e, expires: 4102444800000, revoked: false, kinds: ["continue"] };
    let effects = 0;
    const coordinate = centralCoordinator({
      epoch: 7,
      key: randomBytes(32),
      journal: {
        async reserve(id) {
          return runInDurableObject(stub(), (_o, s) => {
            s.storage.sql.exec(
              "CREATE TABLE IF NOT EXISTS routed_attempts(id TEXT PRIMARY KEY,outcome TEXT)",
            );
            return (
              s.storage.sql
                .exec("INSERT OR IGNORE INTO routed_attempts VALUES(?,NULL) RETURNING id", id)
                .toArray().length === 1
            );
          });
        },
        async finish(id, value) {
          await runInDurableObject(stub(), (_o, s) => {
            s.storage.sql.exec(
              "UPDATE routed_attempts SET outcome=? WHERE id=?",
              JSON.stringify(value),
              id,
            );
          });
        },
      },
      ownerCall: (_owner, op, p) => call(op, p),
      executorCall: (op, p) => call(op, p, "synthetic-agent"),
      async bind() {
        return { envelope: e, grant: g };
      },
      async currentGrant() {
        return g;
      },
      async observe() {
        return { state: "unknown", evidence: "read-only" };
      },
    });
    const fakeBridge = {
      commands: {
        async continue(_owner: string, p: unknown) {
          effects++;
          return { native_submitted: true, result: p };
        },
        creation: {},
        settings: {},
      },
    } as any;
    const gated = gateEdgeMutations(fakeBridge, coordinate),
      p = {
        host: e.host,
        thread_id: e.thread_id,
        request_id: e.request_id,
        source_run_id: "run",
        message: "exact harmless input",
        execution: "allow_new_turn",
      };
    const first = await gated.commands!.continue("owner", p);
    expect(first.native_submitted).toBe(true);
    expect(await gated.commands!.continue("owner", p)).toEqual(first);
    expect(effects).toBe(1);
    await expect(gated.commands!.continue("owner", { ...p, message: "altered" })).rejects.toThrow(
      "binding_mismatch",
    );
    expect(effects).toBe(1);
    await expect(gated.followup("owner", {} as any)).rejects.toThrow("binding_mismatch");
  });
});

describe("subscription lifetime CAS and identity preservation", () => {
  it("renews within original temporary ceiling, refuses extension/revival, and ignores transport epoch in identity", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const table of ["auth_policy", "revoked", "subscriptions"])
        s.storage.sql.exec(`DELETE FROM ${table}`);
    });
    await call("status");
    await active();
    const now = Date.now(),
      base = {
        epoch: 7,
        id: "temporary-lifetime",
        host: "local",
        thread_id: "thread",
        binding: {
          project: "project",
          provider: "provider",
          run: "run",
          grant: "grant",
          revision: 1,
          expires: 4102444700000,
        },
        expires: now + 60000,
        lease_expires: now + 90000,
        name: "t3.thread.activity",
        callback_reference: "existing",
      };
    expect(await call("subscribe_central", base)).toMatchObject({ stored: true });
    expect(
      await call("subscribe_central", {
        ...base,
        expected_expires: base.expires,
        expires: now + 80000,
      }),
    ).toMatchObject({ stored: true });
    expect(
      await call("subscribe_central", {
        ...base,
        expected_expires: now + 80000,
        expires: now + 120000,
      }),
    ).toEqual({ reason: "invalid_request" });
    expect(
      await call("subscription_snapshot", { epoch: 7, id: base.id }, "synthetic-owner2"),
    ).toEqual({ reason: "forbidden" });
    await call("unsubscribe_central", { epoch: 7, id: base.id });
    expect(await call("subscribe_central", base)).toEqual({ reason: "forbidden" });
    const { lease_expires: _lease, ...standing } = base;
    standing.id = "standing-epoch";
    const persistent = { ...standing, expires: null };
    expect(await call("subscribe_central", persistent)).toMatchObject({ stored: true });
    await runInDurableObject(stub(), (_o, s) =>
      s.storage.sql.exec("UPDATE control SET epoch=8 WHERE id=1"),
    );
    expect(await call("subscribe_central", { ...persistent, epoch: 8 })).toMatchObject({
      stored: true,
      expires: null,
    });
  });
});

import { recoveryTables, restoreInert, type RecoveryRow } from "../src/recovery.ts";
import { serviceSchema } from "../src/services.ts";
describe("current-state recovery and safe quota release", () => {
  async function clean() {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      s.storage.sql.exec("DROP TABLE IF EXISTS edge_attempts");
      s.storage.sql.exec("DROP TABLE IF EXISTS routed_attempts");
      for (const t of ["commands", "budget_reservations", "revoked", "auth_policy"])
        s.storage.sql.exec(`DELETE FROM ${t}`);
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
  }
  it("releases only reservations with no begin permit; uncertain effects cannot refund quota", async () => {
    await clean();
    await reserve("cancel-before-permit");
    const claimed = await claim("cancel-before-permit");
    expect(
      await call("cancel_reserved", {
        epoch: 7,
        request_id: "cancel-before-permit",
        reason: "already_standard",
        receipt: { state: "noop", reason: "already_standard" },
      }),
    ).toMatchObject({ cancelled: true });
    expect(
      await call(
        "begin",
        { epoch: 7, request_id: "cancel-before-permit", generation: claimed.generation },
        "synthetic-agent",
      ),
    ).toEqual({ reason: "fenced" });
    await reserve("unknown-after-permit");
    const c = await claim("unknown-after-permit");
    await call(
      "begin",
      { epoch: 7, request_id: "unknown-after-permit", generation: c.generation },
      "synthetic-agent",
    );
    expect(
      await call("cancel_reserved", {
        epoch: 7,
        request_id: "unknown-after-permit",
        reason: "preflight_denied",
        receipt: { state: "rejected" },
      }),
    ).toEqual({ reason: "fenced" });
    await runInDurableObject(stub(), (_o, s) => {
      expect(
        s.storage.sql.exec<{ n: number }>("SELECT COUNT(*) n FROM budget_reservations").one().n,
      ).toBe(1);
    });
  });
  it("exports CURRENT receipts/counters and restores inertly; incomplete archive and stale export fail closed", async () => {
    await clean();
    await reserve("receipt-after-original-snapshot");
    const c = await claim("receipt-after-original-snapshot");
    const p = { epoch: 7, request_id: "receipt-after-original-snapshot", generation: c.generation };
    await call("begin", p, "synthetic-agent");
    await call(
      "record_receipt",
      { ...p, receipt: { native_request_id: "new-current-receipt", safe_to_resend: false } },
      "synthetic-agent",
    );
    await reserve("unresolved-current");
    const u = await claim("unresolved-current");
    await call(
      "begin",
      { epoch: 7, request_id: "unresolved-current", generation: u.generation },
      "synthetic-agent",
    );
    expect(await call("freeze_recovery", { expected_epoch: 7 }, "synthetic-owner2")).toEqual({
      reason: "forbidden",
    });
    const header = await call("freeze_recovery", { expected_epoch: 7 });
    expect(await call("freeze_recovery", { expected_epoch: 7 })).toEqual(header);
    const rows: RecoveryRow[] = [];
    let cursor: { table: number; after: number } | null = { table: 0, after: 0 };
    while (cursor) {
      const page = await call("export_recovery", {
        epoch: header.epoch,
        watermark: header.watermark,
        ...cursor,
      });
      rows.push(...page.rows);
      cursor = page.next;
    }
    expect(
      rows.some(
        (r) => r.table === "commands" && String(r.values.receipt).includes("new-current-receipt"),
      ),
    ).toBe(true);
    const destination = () => env.FLEETS.getByName("recovery-destination");
    await runInDurableObject(destination(), (_o, s) => {
      serviceSchema(s.storage.sql);
      expect(() => restoreInert(s.storage, rows.slice(1), header)).toThrow("incomplete_recovery");
      expect(s.storage.sql.exec<{ n: number }>("SELECT COUNT(*) n FROM commands").one().n).toBe(0);
      const duplicate = rows.find((r) => r.table === "commands")!;
      expect(() =>
        restoreInert(s.storage, [...rows, { ...duplicate, key: duplicate.key + 100000 }], {
          ...header,
          counts: { ...header.counts, commands: header.counts.commands + 1 },
        }),
      ).toThrow();
      expect(s.storage.sql.exec<{ n: number }>("SELECT COUNT(*) n FROM commands").one().n).toBe(0);
      restoreInert(s.storage, rows, header);
    });
    await abortAllDurableObjects();
    await runInDurableObject(destination(), (_o, s) => {
      expect(s.storage.sql.exec<{ mode: string }>("SELECT mode FROM control").one().mode).toBe(
        "quiesced",
      );
      expect(
        s.storage.sql
          .exec<{ state: string }>("SELECT state FROM commands WHERE id='unresolved-current'")
          .one().state,
      ).toBe("uncertain");
      expect(
        s.storage.sql.exec<{ n: number }>("SELECT COUNT(*) n FROM budget_reservations").one().n,
      ).toBe(2);
    });
    await call("revoke", { principal_id: "agent" });
    expect(
      await call("export_recovery", {
        epoch: header.epoch,
        watermark: header.watermark,
        table: 0,
        after: 0,
      }),
    ).toEqual({ reason: "fenced" });
    expect(recoveryTables).toContain("outbox");
    expect(recoveryTables).toContain("subscriptions");
  });
});

describe("non-Error unexpected rejection", () => {
  it("returns sanitized 500 rather than a client conflict", async () => {
    const result = await runInDurableObject(stub(), async (obj) => {
      const original = obj.apply;
      obj.apply = () => {
        throw "synthetic-non-error";
      };
      try {
        const response = await obj.fetch(
          new Request("https://fixture.invalid/status", {
            method: "POST",
            headers: {
              authorization: "Bearer synthetic-owner",
              "content-type": "application/json",
            },
            body: "{}",
          }),
        );
        return { status: response.status, body: await response.json() };
      } finally {
        obj.apply = original;
      }
    });
    expect(result).toEqual({
      status: 500,
      body: { reason: "internal_error", safe_to_resend: false },
    });
  });
});

describe("settings no-op quota parity", () => {
  it("records no-effect preflight even with zero quota and retains original receipt", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const t of ["commands", "budget_reservations", "revoked", "auth_policy"])
        s.storage.sql.exec(`DELETE FROM ${t}`);
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      const p = JSON.parse(
        s.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
      );
      p.principals.find((v: { id: string }) => v.id === "owner").maxPerDay = 0;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    const input = {
      epoch: 7,
      request_id: "zero-quota-noop",
      host: "local",
      thread_id: "exact-thread",
      kind: "settings_standard",
      payload_sha256: "a".repeat(64),
      binding: {
        project: "project",
        provider: "provider",
        run: "run",
        grant: "grant",
        revision: 1,
        expires: 4102444700000,
      },
      reason: "already_standard",
      receipt: { state: "noop", reason: "already_standard", native_submitted: false },
    };
    expect(await call("record_preflight", input)).toMatchObject({
      preflight_recorded: true,
      native_attempted: false,
    });
    expect(
      await call("record_preflight", {
        ...input,
        receipt: { ...input.receipt, extra: "changed readback" },
      }),
    ).toMatchObject({ receipt: input.receipt });
    await runInDurableObject(stub(), (_o, s) =>
      expect(
        s.storage.sql.exec<{ n: number }>("SELECT COUNT(*) n FROM budget_reservations").one().n,
      ).toBe(0),
    );
    expect(await claim("zero-quota-noop")).toMatchObject({ claimed: false, state: "cancelled" });
  });
});

import { coordinatorForBridge } from "../src/coordinator.ts";
describe("existing settings service preflight", () => {
  it("zero quota still permits a proven no-op without a journal attempt or native dispatch", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const t of ["commands", "budget_reservations", "revoked", "auth_policy"])
        s.storage.sql.exec(`DELETE FROM ${t}`);
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      const p = JSON.parse(
        s.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
      );
      p.principals.find((v: { id: string }) => v.id === "owner").maxPerDay = 0;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    const e: Envelope = {
      request_id: crypto.randomUUID(),
      fleet: "test-fleet",
      principal: "owner",
      host: "local",
      project: "project",
      provider: "provider",
      thread_id: "exact-thread",
      run: "run",
      grant: "grant",
      revision: 1,
      expires: 4102444700000,
      kind: "settings_standard",
      payload: { speed: "standard", expected_fingerprint: "a".repeat(64) },
    };
    const g: Grant = { ...e, expires: 4102444800000, revoked: false, kinds: ["settings_standard"] };
    let effects = 0;
    const coordinate = coordinatorForBridge(
      {
        commands: {
          settings: {
            async read() {
              return { classification: "standard", fingerprint: "a".repeat(64) };
            },
          },
        },
      } as any,
      {
        epoch: 7,
        key: randomBytes(32),
        journal: {
          async reserve() {
            throw Error("must_not_begin");
          },
          async finish() {
            throw Error("must_not_begin");
          },
        },
        ownerCall: (_owner, op, p) => call(op, p),
        async executorCall() {
          throw Error("must_not_dispatch");
        },
        async bind() {
          return { envelope: e, grant: g };
        },
        async currentGrant() {
          return g;
        },
        async observe() {
          return { state: "unknown", evidence: "read-only" };
        },
      },
    );
    const result = await coordinate(
      "settings_standard",
      "owner",
      {
        host: e.host,
        thread_id: e.thread_id,
        request_id: e.request_id,
        speed: "standard",
        expected_fingerprint: "a".repeat(64),
      },
      async () => {
        effects++;
        return {};
      },
    );
    expect(result).toMatchObject({ state: "noop", native_submitted: false, preflight_only: true });
    expect(effects).toBe(0);
  });
});

describe("executor and receipt scope tightening", () => {
  it("does not let host access substitute for the executor's project/provider/run grant", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      for (const t of ["commands", "budget_reservations", "revoked", "auth_policy"])
        s.storage.sql.exec(`DELETE FROM ${t}`);
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
    await reserve("executor-scope-bound");
    await runInDurableObject(stub(), (_o, s) => {
      const p = JSON.parse(
        s.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
      );
      p.principals.find((v: { id: string }) => v.id === "agent").scopes = [];
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    expect(await claim("executor-scope-bound")).toEqual({ reason: "forbidden" });
    expect(
      (
        await call(
          "claim",
          { epoch: 7, request_id: "executor-scope-bound", lease_ms: 1000 },
          "synthetic-agent2",
        )
      ).claimed,
    ).toBe(true);
  });
});

describe("budget tightening tri-state semantics", () => {
  it("cannot turn absent/deny into finite/unlimited, but numeric can tighten to absent", async () => {
    await call("status");
    await runInDurableObject(stub(), (_o, s) => {
      s.storage.sql.exec("DELETE FROM auth_policy");
      s.storage.sql.exec("DELETE FROM revoked");
      s.storage.sql.exec("DELETE FROM commands");
      s.storage.sql.exec("DELETE FROM budget_reservations");
      s.storage.sql.exec("UPDATE control SET mode='active',epoch=7 WHERE id=1");
    });
    await call("status");
    const original = await runInDurableObject(stub(), (_o, s) =>
      JSON.parse(
        s.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
      ),
    );
    const change = (value: number | null | undefined) => {
      const p = structuredClone(original);
      p.revision = 2;
      const a = p.principals.find((a: { id: string }) => a.id === "owner");
      if (value === undefined) delete a.maxPerDay;
      else a.maxPerDay = value;
      return p;
    };
    await runInDurableObject(stub(), (_o, s) => {
      const p = structuredClone(original);
      delete p.principals.find((a: { id: string }) => a.id === "owner").maxPerDay;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    expect(await call("tighten_policy", { expected_revision: 1, policy: change(null) })).toEqual({
      reason: "forbidden",
    });
    expect(await call("tighten_policy", { expected_revision: 1, policy: change(1) })).toEqual({
      reason: "forbidden",
    });
    expect(
      await call("tighten_policy", { expected_revision: 1, policy: change(undefined) }),
    ).toEqual({ revision: 2 });
    await runInDurableObject(stub(), (_o, s) => {
      const p = structuredClone(original);
      p.principals.find((a: { id: string }) => a.id === "owner").maxPerDay = 1;
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(p));
    });
    expect((await reserve("before-policy-denial")).state).toBe("pending");
    expect(await call("tighten_policy", { expected_revision: 1, policy: change(null) })).toEqual({
      reason: "forbidden",
    });
    expect(await call("tighten_policy", { expected_revision: 1, policy: change(2) })).toEqual({
      reason: "forbidden",
    });
    expect(
      await call("tighten_policy", { expected_revision: 1, policy: change(undefined) }),
    ).toEqual({ revision: 2 });
    expect(await claim("before-policy-denial")).toEqual({ reason: "forbidden" });
    await runInDurableObject(stub(), (_o, s) =>
      s.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(original)),
    );
    expect(await call("tighten_policy", { expected_revision: 1, policy: change(1) })).toEqual({
      revision: 2,
    });
  });
});

describe("caller policy validation", () => {
  it("rejects malformed policy shapes without changing persisted authority", async () => {
    await call("status");
    const before = await runInDurableObject(
      stub(),
      (_obj, state) =>
        state.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
          .value,
    );
    for (const policy of [null, { revision: 2, fleet: "test-fleet", principals: [null] }, {}]) {
      const response = await exports.default.fetch(
        new Request("https://test.invalid/tighten_policy", {
          method: "POST",
          headers: { authorization: "Bearer synthetic-owner", "content-type": "application/json" },
          body: JSON.stringify({ expected_revision: 1, policy }),
        }),
      );
      expect(response.status).toBe(409);
      expect(await response.json()).toEqual({ reason: "invalid_request" });
    }
    expect(
      await runInDurableObject(
        stub(),
        (_obj, state) =>
          state.storage.sql
            .exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1")
            .one().value,
      ),
    ).toBe(before);
    expect(
      await call("tighten_policy", { expected_revision: 1, policy: null }, "synthetic-agent"),
    ).toEqual({ reason: "forbidden" });
  });
});
