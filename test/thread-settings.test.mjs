// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { Store } from "../dist/store.mjs";
import { ThreadSettings, standardSpeedArgs } from "../dist/thread-settings.mjs";
function fixture(t) {
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  let revoked = false,
    writes = 0,
    reads = 0,
    drift = false,
    uncertain = false;
  let selection = {
    instanceId: "codex",
    model: "model",
    options: [
      { id: "reasoningEffort", value: "high" },
      { id: "serviceTier", value: "priority" },
    ],
  };
  const client = {
    readThread: async () => ({
      thread: {
        threadId: "t",
        projectId: "p",
        providerInstanceId: selection.instanceId,
        model: selection.model,
        activeRunId: "running",
      },
    }),
    currentOptions: async () => {
      if (drift && ++reads === 2) selection.options[0].value = "low";
      return {
        threadId: "t",
        modelSelection: structuredClone(selection),
        runtimeMode: "approval-required",
        interactionMode: "plan",
      };
    },
    providerOptions: async () => ({
      providers: [
        {
          providerInstanceId: "codex",
          driverKind: "codex",
          models: [
            {
              id: "model",
              options: [{ id: "serviceTier", values: ["default", "priority"], default: "default" }],
            },
          ],
        },
      ],
    }),
    configure: async (_t, s) => {
      writes++;
      selection = structuredClone(s);
      if (uncertain) throw Error("lost");
      return { sequence: 17 };
    },
  };
  const grant = () => {
    if (revoked) throw Object.assign(Error("forbidden"), { reason: "forbidden" });
    return { grant: { providerInstanceIds: ["codex"] } };
  };
  const commands = {
    store,
    grant,
    now: Date.now,
    reader: { grant, withHost: async (_o, _h, _p, fn) => fn(client) },
  };
  const settings = new ThreadSettings(commands);
  return {
    settings,
    client,
    commands,
    selection,
    get writes() {
      return writes;
    },
    revoke: () => (revoked = true),
    drift: () => {
      drift = true;
      reads = 0;
    },
    uncertain: () => (uncertain = true),
  };
}
const args = async (f) => ({
  host: "h",
  thread_id: "t",
  speed: "standard",
  request_id: randomUUID(),
  expected_fingerprint: (await f.settings.read("owner", { host: "h", thread_id: "t" })).fingerprint,
});
test("standard update preserves unrelated options and modes, never sends or restarts the active run", async (t) => {
  const f = fixture(t),
    p = await args(f),
    r = await f.settings.standard("owner", p);
  assert.equal(r.state, "verified");
  assert.equal(
    r.after.model_selection.options.find((o) => o.id === "reasoningEffort").value,
    "high",
  );
  assert.equal(r.after.runtime_mode, "approval-required");
  assert.equal(r.after.interaction_mode, "plan");
  assert.equal(r.active_run_id_after, "running");
  assert.equal(r.active_run_speed_verified, false);
  assert.equal(r.native_compare_and_swap, false);
  assert.equal((await f.settings.standard("owner", p)).state, "verified");
  assert.equal(f.writes, 1);
});
test("stale fingerprint and concurrent preflight drift refuse writes", async (t) => {
  const f = fixture(t),
    p = await args(f);
  f.drift();
  const r = await f.settings.standard("owner", p);
  assert.equal(r.state, "rejected");
  assert.equal(r.reason, "settings_changed");
  assert.equal(f.writes, 0);
});
test("revocation during discovery refuses dispatch", async (t) => {
  const f = fixture(t),
    p = await args(f);
  f.client.providerOptions = async () => {
    f.revoke();
    return { providers: [] };
  };
  await assert.rejects(f.settings.standard("owner", p), /forbidden/);
  assert.equal(f.writes, 0);
});
test("lost response reconciles the same UUID without another write", async (t) => {
  const f = fixture(t),
    p = await args(f);
  f.uncertain();
  assert.equal((await f.settings.standard("owner", p)).state, "uncertain");
  const r = await f.settings.standard("owner", p);
  assert.equal(r.state, "observed_after_uncertainty");
  assert.equal(r.safe_to_resend, false);
  assert.equal(f.writes, 1);
  await assert.rejects(
    f.settings.standard("owner", { ...p, expected_fingerprint: "0".repeat(64) }),
    /request_id_conflict/,
  );
});
test("invalid speed cannot reach native configuration; Standard and unknown are no-ops", async (t) => {
  const f = fixture(t),
    p = await args(f);
  assert.equal(standardSpeedArgs.safeParse({ ...p, speed: "fast" }).success, false);
  f.selection.options[1].value = "default";
  const standard = await args(f);
  assert.equal((await f.settings.standard("owner", standard)).state, "noop");
  f.selection.options[1].value = "mystery";
  const unknown = await args(f);
  assert.equal((await f.settings.standard("owner", unknown)).reason, "unknown");
  assert.equal(f.writes, 0);
});
test("unsupported provider does not imply a flash model is Fast; one failure does not affect another target", async (t) => {
  const f = fixture(t);
  f.selection.instanceId = "flash-provider";
  f.selection.model = "glm-flash";
  const p = await args(f);
  await assert.rejects(f.settings.standard("owner", p), /provider_not_authorized/);
  f.selection.instanceId = "codex";
  f.selection.model = "model";
  const valid = await args(f);
  assert.equal((await f.settings.standard("owner", valid)).state, "verified");
  assert.equal(f.writes, 1);
});

test("settings consume the existing shared command budget and preserve uncertain reservations", async (t) => {
  const f = fixture(t),
    p = await args(f);
  f.commands.grant = () => ({ grant: { providerInstanceIds: ["codex"], maxPerDay: 1 } });
  assert.equal((await f.settings.standard("owner", p)).state, "verified");
  assert.equal(f.commands.store.commandBudgetRecords().length, 1);
  f.client.currentOptions = async () => ({
    threadId: "t",
    modelSelection: {
      instanceId: "codex",
      model: "model",
      options: [{ id: "serviceTier", value: "priority" }],
    },
    runtimeMode: "approval-required",
    interactionMode: "plan",
  });
  const second = await args(f);
  await assert.rejects(f.settings.standard("owner", second), /command_budget_exhausted/);
  assert.equal(f.writes, 1);
});

test("receipt readback is exact-target bound and works without native I/O but not after revocation", async (t) => {
  const f = fixture(t),
    p = await args(f);
  await f.settings.standard("owner", p);
  f.client.readThread = async () => {
    throw Error("offline");
  };
  const input = { host: p.host, thread_id: p.thread_id, request_id: p.request_id };
  assert.equal(f.settings.receipt("owner", input).state, "verified");
  assert.equal(f.settings.receipt("owner", input).current_state_checked, false);
  assert.throws(
    () => f.settings.receipt("owner", { ...input, thread_id: "other" }),
    /receipt_not_found/,
  );
  assert.throws(() => f.settings.receipt("other", input), /receipt_not_found/);
  f.revoke();
  assert.throws(() => f.settings.receipt("owner", input), /forbidden/);
});

test("final drift and observed-after-uncertainty receipts retain original evidence on replay", async (t) => {
  const f = fixture(t),
    p = await args(f),
    read = f.client.currentOptions,
    configure = f.client.configure;
  let submitted = false;
  f.client.configure = async (...a) => {
    const result = await configure(...a);
    submitted = true;
    return result;
  };
  f.client.currentOptions = async () => {
    const r = await read();
    if (submitted) r.modelSelection.options[0].value = "low";
    return r;
  };
  const first = await f.settings.standard("owner", p);
  assert.equal(first.state, "drift_after_submission");
  f.client.currentOptions = read;
  const replay = await f.settings.standard("owner", p);
  assert.equal(replay.state, "drift_after_submission");
  assert.deepEqual(replay.after, first.after);
  assert.equal(f.writes, 1);
  const g = fixture(t),
    q = await args(g);
  g.uncertain();
  await g.settings.standard("owner", q);
  const observed = await g.settings.standard("owner", q);
  assert.equal(observed.state, "observed_after_uncertainty");
  g.client.currentOptions = async () => ({
    threadId: "t",
    modelSelection: {
      instanceId: "codex",
      model: "model",
      options: [{ id: "serviceTier", value: "priority" }],
    },
    runtimeMode: "approval-required",
    interactionMode: "plan",
  });
  const duplicate = await g.settings.standard("owner", q);
  assert.equal(duplicate.state, "observed_after_uncertainty");
  assert.deepEqual(duplicate.after, observed.after);
  assert.equal(g.writes, 1);
});

test("budget rejection remains a proven pre-submission rejection across UUID replay", async (t) => {
  const f = fixture(t),
    p = await args(f);
  f.commands.grant = () => ({ grant: { providerInstanceIds: ["codex"], maxPerDay: 0 } });
  await assert.rejects(f.settings.standard("owner", p), /command_budget_exhausted/);
  const r = f.settings.receipt("owner", {
    host: p.host,
    thread_id: p.thread_id,
    request_id: p.request_id,
  });
  assert.equal(r.state, "rejected");
  assert.equal(r.submission_not_attempted, true);
  assert.equal(r.submitted_at, undefined);
  assert.equal((await f.settings.standard("owner", p)).state, "rejected");
  assert.equal(f.writes, 0);
});

test("MCP settings failures preserve safe reasons and denied-operation audit", async (t) => {
  const { Bridge } = await import("../dist/bridge.mjs");
  const { httpServer } = await import("../dist/server.mjs");
  const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
  const { createHash } = await import("node:crypto");
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  const token = randomBytes(24).toString("hex");
  const policy = {
    principals: [
      {
        id: "owner",
        tokenSha256: createHash("sha256").update(token).digest("hex"),
        sessions: [],
        commandHosts: [{ host: "h" }],
      },
    ],
    sessions: [],
  };
  const bridge = new Bridge({ store, backend: {}, policy: () => policy });
  let reason = "request_id_conflict";
  const deny = () => {
    throw Object.assign(Error("PRIVATE"), { reason });
  };
  bridge.commands = { settings: { read: deny, standard: deny, receipt: deny } };
  const server = httpServer(bridge);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = new Client(
    { name: "test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  t.after(() => client.close());
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer " + token } },
    }),
  );
  const base = { host: "h", thread_id: "t" };
  for (const [name, r, args] of [
    [
      "set_thread_speed_standard",
      "request_id_conflict",
      {
        ...base,
        speed: "standard",
        request_id: randomUUID(),
        expected_fingerprint: "a".repeat(64),
      },
    ],
    ["get_thread_speed_receipt", "receipt_not_found", { ...base, request_id: randomUUID() }],
    ["read_thread_options", "invalid_native_options", base],
    ["read_thread_options", "settings_unsupported", base],
  ]) {
    reason = r;
    const result = await client.callTool({ name, arguments: args });
    assert.equal(result.isError, true);
    assert.equal(result.structuredContent.reason, r);
    assert.equal(JSON.stringify(result).includes("PRIVATE"), false);
  }
  const rows = store.db.prepare("SELECT outcome FROM audit WHERE action='command.denied'").all();
  assert.equal(rows.length, 4);
  assert.ok(rows.some((r) => r.outcome.includes("set_thread_speed_standard:request_id_conflict")));
});
