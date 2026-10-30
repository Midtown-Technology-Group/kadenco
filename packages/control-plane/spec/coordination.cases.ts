import { env, exports } from "cloudflare:workers";
import { runInDurableObject, abortAllDurableObjects } from "cloudflare:test";
import { describe, it, expect, beforeEach } from "vitest";
const stub = () => env.FLEETS.getByName("test-fleet");
const call = async (op: string, body: object = {}, token = "synthetic-owner") => {
  const response = await exports.default.fetch(
    new Request("https://test.invalid/" + op, {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: JSON.stringify(body),
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
