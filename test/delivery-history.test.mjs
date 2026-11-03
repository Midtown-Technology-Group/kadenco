// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, createHash, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../dist/store.mjs";
import { deliveryHistory, relayDiagnostics } from "../dist/delivery-history.mjs";
import { httpServer } from "../dist/server.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
const event_id = "evt_" + "a".repeat(64),
  subscription_id = "owned",
  id = subscription_id + ":" + event_id;
function fixture(store = new Store(":memory:", randomBytes(32))) {
  const policy = {
    principals: [
      {
        id: "owner",
        sessions: ["session"],
        tokenSha256: createHash("sha256").update("fixture-token").digest("hex"),
      },
    ],
    sessions: [],
  };
  store.put("subscription", subscription_id, {
    id: subscription_id,
    owner: "owner",
    name: "t3.task.finished",
    sessionId: "session",
    active: true,
    expires: null,
    nonExpiring: true,
    url: "https://private.invalid/?token=SECRET",
    secret: "SECRET",
  });
  store.put("delivery", id, {
    id,
    subId: subscription_id,
    status: "pending",
    attempts: 0,
    nextAt: Date.now(),
    event: { eventId: event_id, name: "t3.task.finished", data: { result: "SECRET" } },
  });
  return {
    store,
    policy: () => policy,
    now: Date.now,
    sessions: () => [],
    grant(owner, session) {
      if (owner !== "owner" || session !== "session" || policy.principals[0].enabled === false)
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
      return { id: session };
    },
  };
}
test("exact event history paginates retained results across reopen without exposing secrets or performing effects", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-history-")),
    path = join(dir, "state.db"),
    key = randomBytes(32);
  let store = new Store(path, key),
    b = fixture(store);
  store.audit("webhook.delivery", id, "pending:503");
  store.audit("webhook.delivery", "other", "acknowledged:204");
  store.audit("webhook.delivery", id, "acknowledged:204");
  store.db
    .prepare("UPDATE audit SET at=? WHERE subject=? AND outcome='acknowledged:204'")
    .run(new Date(Date.now() - 60000).toISOString(), id);
  store.put("delivery", id, {
    ...store.get("delivery", id),
    attempts: 2,
    status: "acknowledged",
    httpStatus: 204,
  });
  const first = await deliveryHistory(b, "owner", { subscription_id, event_id, limit: 1 });
  assert.equal(first.items[0].http_status, 503);
  assert.ok(first.next_cursor);
  assert.deepEqual(
    (await deliveryHistory(b, "owner", { subscription_id, event_id, limit: 1 })).items,
    first.items,
    "replayed reads do not append or duplicate evidence",
  );
  store.close();
  store = new Store(path, key);
  b = { ...b, store };
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const second = await deliveryHistory(b, "owner", {
    subscription_id,
    event_id,
    cursor: first.next_cursor,
    limit: 1,
  });
  assert.equal(second.items[0].http_status, 204);
  assert.ok(
    Date.parse(second.items[0].at) < Date.parse(first.items[0].at),
    "audit sequence, not a misleading wall-clock sort, orders out-of-order timestamps",
  );
  assert.equal(second.next_cursor, null);
  assert.equal(second.delivery_acknowledged, true);
  assert.equal(second.agent_execution, "not_checked");
  assert.equal(JSON.stringify(second).includes("SECRET"), false);
  assert.equal(store.all("command").length, 0);
});
test("history rejects foreign owners, revoked grants, expired subscriptions and rebound cursor identity", async (t) => {
  const b = fixture();
  t.after(() => b.store.close());
  await assert.rejects(deliveryHistory(b, "other", { subscription_id, event_id }), /forbidden/);
  await assert.rejects(
    deliveryHistory(b, "owner", {
      subscription_id,
      event_id,
      cursor: { source: "central_audit", delivery_id: id, after_sequence: 0 },
    }),
    /history_source_changed/,
  );
  b.store.put("subscription", subscription_id, {
    ...b.store.get("subscription", subscription_id),
    expires: 1,
  });
  await assert.rejects(deliveryHistory(b, "owner", { subscription_id, event_id }), /forbidden/);
  b.store.put("subscription", subscription_id, {
    ...b.store.get("subscription", subscription_id),
    expires: null,
  });
  b.policy().principals[0].enabled = false;
  await assert.rejects(deliveryHistory(b, "owner", { subscription_id, event_id }), /forbidden/);
});
test("central history keeps permits distinct from current receipt, validates ordering and rechecks revocation after await", async (t) => {
  const b = fixture();
  t.after(() => b.store.close());
  b.store.put("delivery", id, {
    ...b.store.get("delivery", id),
    status: "centralized",
    central_id: "central-exact",
  });
  let revoke = false,
    badOrder = false,
    calls = 0;
  b.deliveryHistory = async (owner, central, after, limit) => {
    assert.equal(owner, "owner");
    assert.equal(central, "central-exact");
    assert.equal(limit, 50);
    calls++;
    if (revoke) b.policy().principals[0].enabled = false;
    return {
      id: central,
      subscription_id,
      event_id,
      state: "acknowledged",
      attempts: 1,
      http_status: 204,
      next_at: null,
      items: [
        {
          sequence: badOrder ? after : 8,
          at: Date.now(),
          operation: "outbox_begin",
          principal_id: "executor",
        },
      ],
      next_sequence: null,
      delivery_acknowledged: true,
      agent_completed: false,
      secret: "SECRET",
    };
  };
  const r = await deliveryHistory(b, "owner", { subscription_id, event_id });
  assert.equal(r.items[0].evidence, "dispatch_permitted");
  assert.equal(r.agent_execution, "not_checked");
  assert.equal(JSON.stringify(r).includes("SECRET"), false);
  badOrder = true;
  await assert.rejects(
    deliveryHistory(b, "owner", { subscription_id, event_id }),
    /source_unavailable/,
  );
  badOrder = false;
  revoke = true;
  await assert.rejects(deliveryHistory(b, "owner", { subscription_id, event_id }), /forbidden/);
  assert.equal(calls, 3);
});
test("relay diagnostics are principal-scoped, redact arbitrary fields and advance across empty pages", async (t) => {
  const b = fixture();
  t.after(() => b.store.close());
  b.deliveryHistory = async () => ({});
  b.relayDiagnosticAccess = async () => {};
  const row = {
    at: new Date().toISOString(),
    host: "@central_http",
    kind: "central_http",
    principal_id: "other",
    initiator_id: null,
    parent_correlation_id: null,
    correlation_id: randomUUID(),
    operation: "status",
    duration_ms: 4,
    outcome: "ok",
    http_status: 200,
    headers: { authorization: "SECRET" },
  };
  b.store.diagnostic(row);
  b.store.diagnostic({ ...row, principal_id: "owner", correlation_id: randomUUID() });
  const first = await relayDiagnostics(b, "owner", { limit: 1 });
  assert.equal(first.items.length, 0);
  assert.ok(first.next_cursor);
  const next = await relayDiagnostics(b, "owner", { limit: 1, after_sequence: first.next_cursor });
  assert.equal(next.items.length, 1);
  assert.equal(next.next_cursor, null);
  assert.equal(JSON.stringify(next).includes("SECRET"), false);
  b.policy().principals[0].enabled = false;
  await assert.rejects(relayDiagnostics(b, "owner", {}), /forbidden/);
});
test("MCP exposes read-only history and scoped request diagnostics through the existing authenticated owner surface", async (t) => {
  const b = fixture();
  b.deliveryHistory = async () => ({});
  b.relayDiagnosticAccess = async () => {};
  const server = httpServer(b);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const client = new Client(
    { name: "fixture", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  t.after(async () => {
    await client.close();
    await new Promise((r) => server.close(r));
    b.store.close();
  });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer fixture-token" } },
    }),
  );
  const tools = (await client.listTools()).tools;
  for (const name of ["get_event_delivery_history", "get_relay_request_diagnostics"])
    assert.equal(tools.find((tool) => tool.name === name).annotations.readOnlyHint, true);
  assert.equal(
    (
      await client.callTool({
        name: "get_event_delivery_history",
        arguments: { subscription_id, event_id },
      })
    ).structuredContent.current.attempts,
    0,
  );
  assert.equal(
    (await client.callTool({ name: "get_relay_request_diagnostics", arguments: {} }))
      .structuredContent.items.length,
    0,
  );
  assert.equal(b.store.all("command").length, 0);
});
