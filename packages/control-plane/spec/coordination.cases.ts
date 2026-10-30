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
  it("old worker revival cannot mutate after epoch changes; persisted receipts survive reconstruction", async () => {
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
    const pending = stub().fetch(
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
});
