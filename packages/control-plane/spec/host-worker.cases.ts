// SPDX-License-Identifier: AGPL-3.0-or-later
import { env, exports } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { it, expect } from "vitest";
const call = async (op: string, p: object, token = "synthetic-agent") => {
  const r = await exports.default.fetch(
    new Request("https://fixture/" + op, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer " + token },
      body: JSON.stringify({ epoch: 7, ...p }),
    }),
  );
  return (await r.json()) as any;
};
it("authenticated Worker host permit fences legacy dispatch, stale processes, cross-host claims and uncertain thread successors", async () => {
  await runInDurableObject(env.FLEETS.getByName("test-fleet"), (_o, s) => {
    s.storage.sql.exec(
      "DELETE FROM host_link_attempts; DELETE FROM host_link_refs; DELETE FROM host_link_sessions; DELETE FROM host_links; DELETE FROM commands; DELETE FROM budget_reservations; DELETE FROM auth_policy; DELETE FROM revoked; UPDATE control SET mode='active',epoch=7 WHERE id=1",
    );
  });
  const binding = {
    project: "project",
    provider: "provider",
    run: "run",
    grant: "grant",
    revision: 1,
    expires: 4102444700000,
  };
  for (const request_id of ["original-arbitrary-id", "successor"]) {
    expect(
      await call(
        "reserve",
        {
          request_id,
          host: "local",
          thread_id: "exact-thread",
          kind: "continue",
          payload_sha256: "a".repeat(64),
          binding,
        },
        "synthetic-owner",
      ),
    ).toMatchObject({ state: "pending" });
    expect(
      await call("link_publish", { request_id, ciphertext: "opaque-fixture" }, "synthetic-owner"),
    ).toMatchObject({ existing: false });
  }
  const connection = crypto.randomUUID();
  const session = await call("link_open", { host: "local", connection });
  expect(session.generation).toBe(1);
  const base = { host: "local", connection, generation: 1, request_id: "original-arbitrary-id" };
  expect(await call("link_claim", { ...base, host: "foreign" })).toMatchObject({
    reason: "forbidden",
  });
  expect(await call("claim", { request_id: base.request_id, lease_ms: 10000 })).toMatchObject({
    reason: "fenced",
  });
  const claim = await call("link_claim", base);
  expect(claim).toMatchObject({ claimed: true, id: base.request_id });
  expect(
    await call("link_begin", {
      ...base,
      connection: crypto.randomUUID(),
      command_generation: claim.generation,
    }),
  ).toMatchObject({ reason: "fenced" });
  expect(await call("link_begin", { ...base, command_generation: claim.generation })).toMatchObject(
    { may_attempt: true },
  );
  expect(await call("link_claim", { ...base, request_id: "successor" })).toMatchObject({
    claimed: false,
    state: "thread_held",
  });
  expect(
    await call("record_receipt", {
      request_id: base.request_id,
      generation: claim.generation,
      receipt: {},
    }),
  ).toMatchObject({ reason: "fenced" });
  const receipt = {
    request_id: base.request_id,
    host: "local",
    thread_id: "exact-thread",
    safe_to_resend: false,
    native_submitted: true,
    completed: false,
    message_id: "native-message",
    run_status: "queued",
  };
  expect(
    await call("link_observe", { ...base, command_generation: claim.generation, receipt }),
  ).toMatchObject({ observation_recorded: true });
  expect(
    await call("link_record_receipt", { ...base, command_generation: claim.generation, receipt }),
  ).toMatchObject({ reason: "invalid_request" });
  const terminal = {
    ...receipt,
    run_status: "completed",
    completed: true,
    terminal: true,
    run_status_fresh: true,
    message_observation_fresh: true,
    message_id: "native-message",
    run_id: "native-run",
    native_message_observation: {
      message_id: "native-message",
      run_id: "native-run",
      run_status: "completed",
    },
  };
  expect(
    await call("link_record_receipt", {
      ...base,
      command_generation: claim.generation,
      receipt: terminal,
    }),
  ).toMatchObject({ receipt_recorded: true, native_execution_verified: false });
  expect(
    await call("link_record_receipt", {
      ...base,
      command_generation: claim.generation,
      receipt: { ...terminal, message_id: "foreign" },
    }),
  ).toMatchObject({ reason: "immutable_outcome" });
  expect(await call("link_claim", { ...base, request_id: "successor" })).toMatchObject({
    claimed: true,
  });
  // Revoking the origin after claim is checked at the actual begin transaction.
  await runInDurableObject(env.FLEETS.getByName("test-fleet"), (_o, s) => {
    s.storage.sql.exec("INSERT INTO revoked VALUES('owner')");
  });
  expect(
    await call("link_begin", { ...base, request_id: "successor", command_generation: 1 }),
  ).toMatchObject({ reason: "forbidden" });
});
