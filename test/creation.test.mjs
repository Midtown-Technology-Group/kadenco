// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Store } from "../dist/store.mjs";
import { Commands } from "../dist/commands.mjs";
import { createArgs } from "../dist/creation.mjs";
import { configSchema } from "../dist/config.mjs";
import { httpServer } from "../dist/server.mjs";
import { Exchanges } from "../dist/exchange.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

function fixture(t) {
  let now = Date.now(),
    hook = async () => {},
    errorStage;
  const writes = [],
    projections = new Map(),
    key = randomBytes(32);
  const dir = mkdtempSync(join(tmpdir(), "eddie-create-")),
    path = join(dir, "state.db");
  let store = new Store(path, key);
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const grant = {
    host: "local",
    expiresAt: now + 60000,
    maxPerDay: 10,
    providerInstanceIds: ["codex"],
    creationRuntime: {
      allowedModes: ["approval-required", "full-access"],
      defaultMode: "full-access",
      authorization: "Explicit test owner grant",
    },
  };
  const policy = {
    principals: [{ id: "eddie", commandHosts: [grant], sessions: [] }],
    nativeDelivery: { hosts: [{ name: "local" }] },
  };
  const p = {
    host: "local",
    project_id: "project",
    provider_instance_id: "codex",
    model: "gpt-6.1-sol",
    options: [
      { id: "reasoningEffort", value: "medium" },
      { id: "serviceTier", value: "default" },
    ],
    runtime_mode: "approval-required",
    title: "Harmless creation",
    message: "Do not use tools. Reply OK.",
    request_id: randomUUID(),
    execution: "allow_new_thread",
  };
  const config = {
    providers: [
      {
        instanceId: "codex",
        driver: "codex",
        enabled: true,
        installed: true,
        status: "ready",
        supportedRuntimeModes: ["approval-required", "full-access"],
        models: [
          {
            slug: p.model,
            name: p.model,
            capabilities: {
              optionDescriptors: p.options.map((o) => ({
                id: o.id,
                type: "select",
                options: [{ id: o.value }],
              })),
            },
          },
        ],
      },
    ],
    settings: { projectSettingsOverrides: {} },
  };
  const reader = {
    grant(owner, host, project) {
      if (owner !== "eddie" || host !== "local" || (project && project !== "project"))
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
    },
    async withHost(owner, host, project, fn) {
      this.grant(owner, host, project);
      return fn({
        base: "http://127.0.0.1:3773",
        listProjects: async () => ({
          projects: [{ id: "project", title: "Project" }],
          nextCursor: null,
        }),
      });
    },
  };
  const session = async (route, fn) =>
    fn(async (base, method, args) => {
      await hook(method, args);
      if (method === "server.getConfig") return structuredClone(config);
      if (method === "orchestration.getThreadProjection") {
        const v = projections.get(args.threadId);
        if (!v) throw Object.assign(Error("not found"), { reason: "native_rejected" });
        return structuredClone(v);
      }
      writes.push(structuredClone(args));
      if (args.type === "thread.create")
        projections.set(args.threadId, {
          thread: { ...args, id: args.threadId },
          runs: [],
          messages: [],
        });
      else {
        const v = projections.get(args.threadId);
        v.runs.push({
          id: "exact-run",
          userMessageId: args.messageId,
          status: "completed",
          modelSelection: args.modelSelection,
        });
        v.messages.push(
          { id: args.messageId, role: "user", text: args.text },
          { id: "assistant", role: "assistant", runId: "exact-run", text: "OK" },
        );
      }
      if (errorStage === args.type)
        throw Object.assign(Error("lost"), { reason: "native_outcome_unknown" });
      return { sequence: writes.length };
    });
  const commands = () =>
    new Commands({ policy: () => policy, store, reader, session, now: () => now });
  return {
    get store() {
      return store;
    },
    grant,
    policy,
    p,
    config,
    reader,
    session,
    writes,
    projections,
    commands,
    hook: (f) => (hook = f),
    error: (s) => (errorStage = s),
    advance: (n) => (now += n),
    restart() {
      store.close();
      store = new Store(path, key);
      return commands();
    },
  };
}

test("explicit root creation preserves Codex selection/options and reconciles exact initial run/result", async (t) => {
  const f = fixture(t),
    c = f.commands();
  const options = await c.creation.options("eddie", { host: "local", project_id: "project" });
  assert.equal(options.providers[0].models[0].model, f.p.model);
  assert.equal(f.writes.length, 0);
  const submitted = await c.creation.create("eddie", f.p);
  assert.equal(submitted.create_submission, "accepted");
  assert.equal(submitted.start_submission, "accepted");
  assert.equal(submitted.completed, false);
  assert.equal(f.writes.length, 2);
  assert.deepEqual(
    f.writes.map((x) => x.type),
    ["thread.create", "message.dispatch"],
  );
  for (const w of f.writes)
    assert.deepEqual(w.modelSelection, {
      instanceId: "codex",
      model: f.p.model,
      options: f.p.options,
    });
  assert.equal(f.writes[0].runtimeMode, "approval-required");
  assert.equal(f.writes[0].branch, null);
  assert.equal(f.writes[0].worktreePath, null);
  assert.deepEqual(f.writes[1].dispatchMode, { type: "start_immediately" });
  const receipt = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.run_id, "exact-run");
  assert.equal(receipt.result, "OK");
  assert.equal(receipt.completed, true);
  assert.equal(receipt.run_status_fresh, true);
  assert.equal(receipt.agent_acknowledged, false);
  assert.equal(receipt.safe_to_resend, false);
  await c.creation.create("eddie", f.p);
  assert.equal(f.writes.length, 2);
});

test("explicit full-access creation preserves selection and runtime in durable receipts and restart replay", async (t) => {
  const f = fixture(t);
  f.p.runtime_mode = "full-access";
  const c = f.commands();
  const options = await c.creation.options("eddie", { host: "local", project_id: "project" });
  assert.equal(options.default_runtime_mode, "full-access");
  assert.deepEqual(options.providers[0].runtime_modes, ["approval-required", "full-access"]);
  const r = await c.creation.create("eddie", f.p);
  assert.equal(r.runtime_mode, "full-access");
  assert.equal(f.writes[0].runtimeMode, "full-access");
  assert.deepEqual(f.writes[0].modelSelection.options, f.p.options);
  const restarted = f.restart(),
    receipt = await restarted.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.observed_runtime_mode, "full-access");
  assert.equal(receipt.runtime_matches_request, true);
  assert.equal(receipt.execution_authorization.runtimeMode, "full-access");
  await restarted.creation.create("eddie", f.p);
  assert.equal(f.writes.length, 2);
  await assert.rejects(
    restarted.creation.create("eddie", { ...f.p, runtime_mode: "approval-required" }),
    /idempotency_conflict/,
  );
});

test("runtime must be explicit, granted and natively supported; absent grants never imply full access", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    { runtime_mode: _runtimeMode, ...missing } = f.p;
  await assert.rejects(c.creation.create("eddie", missing));
  delete f.grant.creationRuntime;
  await assert.rejects(c.creation.create("eddie", f.p), /runtime_mode_not_authorized/);
  assert.equal(
    (await c.creation.options("eddie", { host: "local", project_id: "project" }))
      .default_runtime_mode,
    null,
  );
  f.grant.creationRuntime = {
    allowedModes: ["approval-required"],
    defaultMode: "approval-required",
    authorization: "owner",
  };
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, runtime_mode: "full-access" }),
    /runtime_mode_not_authorized/,
  );
  f.grant.creationRuntime.allowedModes.push("full-access");
  f.config.providers[0].supportedRuntimeModes = ["approval-required"];
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, runtime_mode: "full-access" }),
    /runtime_mode_unavailable/,
  );
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});

test("native omitted/empty runtime metadata means unrestricted, matching installed Codex semantics", async (t) => {
  const f = fixture(t);
  f.p.runtime_mode = "full-access";
  delete f.config.providers[0].supportedRuntimeModes;
  assert.equal((await f.commands().creation.create("eddie", f.p)).runtime_mode, "full-access");
  f.config.providers[0].supportedRuntimeModes = [];
  await f.commands().creation.create("eddie", { ...f.p, request_id: randomUUID() });
  assert.equal(f.writes.length, 4);
  f.config.providers[0].supportedRuntimeModes = ["future-mode"];
  await assert.rejects(
    f.commands().creation.create("eddie", { ...f.p, request_id: randomUUID() }),
    /runtime_mode_unavailable/,
  );
});

test("full-access partial creation never starts on replay and revocation at final dispatch prevents mutation", async (t) => {
  const f = fixture(t);
  f.p.runtime_mode = "full-access";
  f.error("thread.create");
  await f.commands().creation.create("eddie", f.p);
  const c = f.restart();
  await c.creation.create("eddie", f.p);
  assert.equal(f.writes.length, 1);
  assert.equal(
    (await c.receipt("eddie", { request_id: f.p.request_id })).runtime_mode,
    "full-access",
  );
  const g = fixture(t);
  g.p.runtime_mode = "full-access";
  const guarded = new Commands({
    policy: () => g.policy,
    store: g.store,
    reader: g.reader,
    session: async (route, fn) =>
      g.session(route, async (call) =>
        fn(async (...args) => {
          if (args[2]?.type === "thread.create") {
            g.grant.creationRuntime.allowedModes = ["approval-required"];
            route.authorizeDispatch();
          }
          return call(...args);
        }),
      ),
  });
  const result = await guarded.creation.create("eddie", g.p);
  assert.equal(result.failure_reason, "runtime_mode_not_authorized");
  assert.equal(g.writes.length, 0);
});

test("runtime revocation after creation leaves an unstarted thread; later owner mode changes are reported, not repaired", async (t) => {
  const f = fixture(t);
  f.p.runtime_mode = "full-access";
  let reads = 0;
  f.hook(async (method) => {
    if (method === "server.getConfig" && ++reads === 2)
      f.grant.creationRuntime = {
        allowedModes: ["approval-required"],
        defaultMode: "approval-required",
        authorization: "owner revoked full-access",
      };
  });
  const r = await f.commands().creation.create("eddie", f.p);
  assert.equal(r.create_submission, "accepted");
  assert.equal(r.start_submission, "not_attempted");
  assert.equal(f.writes.length, 1);
  await f.restart().creation.create("eddie", f.p);
  assert.equal(f.writes.length, 1);
  const g = fixture(t);
  g.p.runtime_mode = "full-access";
  const c = g.commands(),
    created = await c.creation.create("eddie", g.p);
  g.projections.get(created.thread_id).thread.runtimeMode = "approval-required";
  const receipt = await c.receipt("eddie", { request_id: g.p.request_id });
  assert.equal(receipt.runtime_mode, "full-access");
  assert.equal(receipt.observed_runtime_mode, "approval-required");
  assert.equal(receipt.runtime_matches_request, false);
  assert.equal(g.writes.length, 2);
});

test("legacy stored creations retain approval-required receipt meaning without acquiring new runtime authority", async (t) => {
  const f = fixture(t),
    c = f.commands();
  await c.creation.create("eddie", f.p);
  const record = f.store.get("command", f.p.request_id);
  delete record.runtime_mode;
  f.store.put("command", f.p.request_id, record);
  delete f.grant.creationRuntime;
  const receipt = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.runtime_mode, "approval-required");
  assert.equal(receipt.completed, true);
  assert.equal(f.writes.length, 2);
});

test("runtime configuration rejects an unauthorized default, duplicate modes and unproven authorization", async (t) => {
  const f = fixture(t),
    schema = configSchema.shape.principals.element.shape.commandHosts.unwrap().element;
  assert.equal(schema.safeParse(f.grant).success, true);
  for (const creationRuntime of [
    { allowedModes: ["approval-required"], defaultMode: "full-access", authorization: "owner" },
    {
      allowedModes: ["full-access", "full-access"],
      defaultMode: "full-access",
      authorization: "owner",
    },
    { allowedModes: ["full-access"], defaultMode: "full-access", authorization: "" },
    { allowedModes: ["auto"], defaultMode: "auto", authorization: "owner" },
  ])
    assert.equal(schema.safeParse({ ...f.grant, creationRuntime }).success, false);
});

test("concurrent callers reserve one durable request before dispatch; replay after actual SQLite restart cannot duplicate", async (t) => {
  const f = fixture(t),
    a = f.commands(),
    b = f.commands();
  await Promise.all(
    Array.from({ length: 8 }, (_, i) => (i % 2 ? a : b).creation.create("eddie", f.p)),
  );
  assert.equal(f.writes.length, 2);
  assert.equal(f.projections.size, 1);
  const restarted = f.restart();
  await restarted.creation.create("eddie", f.p);
  const r = await restarted.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.completed, true);
  assert.equal(f.writes.length, 2);
});

test("lost create response leaves an observed unstarted thread and never dispatches a start on replay/restart", async (t) => {
  const f = fixture(t);
  f.error("thread.create");
  const r = await f.commands().creation.create("eddie", f.p);
  assert.equal(r.create_submission, "outcome_unknown");
  assert.equal(r.start_submission, "not_attempted");
  assert.equal(f.writes.length, 1);
  const c = f.restart(),
    observed = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(observed.thread_observed, true);
  assert.equal(observed.run_id, null);
  assert.equal(observed.create_submission, "accepted");
  assert.equal(observed.start_submission, "not_attempted");
  await c.creation.create("eddie", f.p);
  assert.equal(f.writes.length, 1);
});

test("lost start response reconciles exact native message/run without resend, including after restart", async (t) => {
  const f = fixture(t);
  f.error("message.dispatch");
  const r = await f.commands().creation.create("eddie", f.p);
  assert.equal(r.start_submission, "outcome_unknown");
  const c = f.restart();
  await c.creation.create("eddie", f.p);
  const receipt = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.start_submission, "accepted");
  assert.equal(receipt.completed, true);
  assert.equal(f.writes.length, 2);
});

test("crash after reservation before create retains unknown receipt across restart and never invents an execution", async (t) => {
  const f = fixture(t);
  f.hook(async (method, args) => {
    if (args.type === "thread.create") throw Error("socket lost before any native proof");
  });
  await f.commands().creation.create("eddie", f.p);
  const c = f.restart();
  await c.creation.create("eddie", f.p);
  const r = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.stored, true);
  assert.equal(r.create_submission, "outcome_unknown");
  assert.equal(r.source_status, "unavailable");
  assert.equal(r.safe_to_resend, false);
  assert.equal(f.writes.length, 0);
});

test("wrong owner/host/project, missing/expired/disabled grants and ungranted providers cannot dispatch", async (t) => {
  const f = fixture(t),
    c = f.commands();
  for (const [owner, p] of [
    ["reader", f.p],
    ["eddie", { ...f.p, host: "remote" }],
    ["eddie", { ...f.p, project_id: "private" }],
    ["eddie", { ...f.p, provider_instance_id: "other" }],
  ])
    await assert.rejects(c.creation.create(owner, p));
  f.policy.principals[0].enabled = false;
  await assert.rejects(c.creation.create("eddie", f.p), /forbidden/);
  f.policy.principals[0].enabled = true;
  f.advance(60001);
  await assert.rejects(c.creation.create("eddie", f.p), /forbidden/);
  assert.equal(f.writes.length, 0);
});

test("catalog model/options, driver, runtime support and native project provider exclusion fail closed", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    provider = f.config.providers[0];
  for (const p of [
    { ...f.p, model: "unknown" },
    { ...f.p, options: [{ id: "unsupported", value: true }] },
    { ...f.p, options: [{ id: "serviceTier", value: "other" }] },
  ])
    await assert.rejects(c.creation.create("eddie", p));
  for (const key of ["enabled", "installed"]) {
    provider[key] = false;
    await assert.rejects(c.creation.create("eddie", f.p), /provider_not_authorized/);
    provider[key] = true;
  }
  provider.driver = "unknown";
  await assert.rejects(c.creation.create("eddie", f.p));
  provider.driver = "codex";
  provider.supportedRuntimeModes = ["full-access"];
  await assert.rejects(c.creation.create("eddie", f.p), /runtime_mode_unavailable/);
  delete provider.supportedRuntimeModes;
  f.config.settings.projectSettingsOverrides.project = {
    providerInstances: { codex: { enabled: false } },
  };
  await assert.rejects(c.creation.create("eddie", f.p), /provider_not_authorized/);
  assert.equal(f.writes.length, 0);
  assert.equal(createArgs.safeParse({ ...f.p, runtime_mode: "full-access" }).success, true);
  assert.equal(createArgs.safeParse({ ...f.p, runtime_mode: "auto" }).success, false);
  assert.equal(createArgs.safeParse({ ...f.p, execution: "allow_new_turn" }).success, false);
  assert.equal(
    createArgs.safeParse({ ...f.p, options: [f.p.options[0], f.p.options[0]] }).success,
    false,
  );
});

test("grant revocation during preflight creates nothing; revocation after creation cannot start execution", async (t) => {
  const f = fixture(t),
    c = f.commands();
  let count = 0;
  f.hook(async (method) => {
    if (method === "server.getConfig" && ++count === 1) f.policy.principals[0].enabled = false;
  });
  await assert.rejects(c.creation.create("eddie", f.p), /forbidden/);
  assert.equal(f.writes.length, 0);
  f.policy.principals[0].enabled = true;
  count = 0;
  f.hook(async (method) => {
    if (method === "server.getConfig" && ++count === 2) f.policy.principals[0].enabled = false;
  });
  await assert.rejects(c.creation.create("eddie", f.p), /forbidden/);
  assert.equal(f.writes.length, 1);
  assert.equal(f.store.get("command", f.p.request_id).startSubmission, "not_attempted");
});

test("shared command cap counts creation once; changed payload/kind/owner cannot reuse UUID", async (t) => {
  const f = fixture(t),
    c = f.commands();
  f.grant.maxPerDay = 1;
  await c.creation.create("eddie", f.p);
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, message: "changed" }),
    /idempotency_conflict/,
  );
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, request_id: randomUUID() }),
    /command_budget_exhausted/,
  );
  await assert.rejects(
    c.continue("eddie", {
      host: "local",
      thread_id: "t",
      source_run_id: "r",
      message: "x",
      request_id: f.p.request_id,
      execution: "allow_new_turn",
    }),
    /idempotency_conflict/,
  );
  assert.equal(f.writes.length, 2);
});

test("readback identity mismatch never binds a different project, model, message or run", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    r = await c.creation.create("eddie", f.p),
    v = f.projections.get(r.thread_id);
  v.thread.projectId = "other";
  await assert.rejects(c.receipt("eddie", { request_id: f.p.request_id }), /identity_mismatch/);
  v.thread.projectId = "project";
  v.runs.push({ id: "unrelated", userMessageId: "other-message", status: "completed" });
  v.messages.push({ role: "assistant", runId: "unrelated", text: "WRONG" });
  assert.equal((await c.receipt("eddie", { request_id: f.p.request_id })).result, "OK");
  v.runs[0].userMessageId = "wrong";
  await assert.rejects(c.receipt("eddie", { request_id: f.p.request_id }), /identity_mismatch/);
  assert.equal(f.writes.length, 2);
});

test("late observation cannot overwrite newer terminal evidence; cached completion is marked stale on outage", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    r = await c.creation.create("eddie", f.p);
  await c.receipt("eddie", { request_id: f.p.request_id });
  const v = f.projections.get(r.thread_id);
  v.runs[0].status = "running";
  const regressed = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(regressed.completed, true);
  assert.equal(regressed.run_status_fresh, false);
  f.hook(async (method) => {
    if (method === "orchestration.getThreadProjection") throw Error("SECRET unavailable");
  });
  const unavailable = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(unavailable.completed, true);
  assert.equal(unavailable.run_status_fresh, false);
  assert.equal(unavailable.safe_to_resend, false);
  assert.equal(JSON.stringify(unavailable).includes("SECRET"), false);
});

test("concurrent observation uses a revision fence and preserves accepted sequence/acknowledgement", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    r = await c.creation.create("eddie", f.p);
  let first = true,
    release,
    entered;
  const held = new Promise((resolve) => (release = resolve)),
    ready = new Promise((resolve) => (entered = resolve)),
    original = f.session;
  const delayed = new Commands({
    policy: () => f.policy,
    store: f.store,
    reader: f.reader,
    session: async (route, fn) =>
      original(route, (call) =>
        fn(async (...args) => {
          const result = await call(...args);
          if (args[1] === "orchestration.getThreadProjection" && first) {
            first = false;
            entered();
            await held;
          }
          return result;
        }),
      ),
  });
  f.projections.get(r.thread_id).runs[0].status = "running";
  const pending = delayed.receipt("eddie", { request_id: f.p.request_id });
  await ready;
  f.projections.get(r.thread_id).runs[0].status = "completed";
  await c.receipt("eddie", { request_id: f.p.request_id });
  const record = f.store.get("command", f.p.request_id);
  record.ackAt = Date.now();
  f.store.put("command", f.p.request_id, record);
  release();
  const old = await pending;
  assert.equal(old.completed, true);
  assert.equal(old.run_status_fresh, false);
  assert.equal(old.agent_acknowledged, true);
  assert.equal(old.sequence, 2);
  assert.equal(old.result, "OK");
  assert.equal(f.writes.length, 2);
});

test("receipt identity survives a later authorized title/model/workspace change without misattributing another run", async (t) => {
  const f = fixture(t),
    c = f.commands(),
    r = await c.creation.create("eddie", f.p),
    v = f.projections.get(r.thread_id);
  v.thread.title = "Renamed";
  v.thread.modelSelection = { instanceId: "codex", model: "other" };
  v.thread.branch = "later";
  const receipt = await c.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.run_id, "exact-run");
  assert.equal(receipt.result, "OK");
  assert.equal(receipt.model_selection.model, f.p.model);
});

test("project registration follows empty advancing pages and refuses malformed or absent targets", async (t) => {
  const f = fixture(t),
    c = f.commands();
  let pages = 0;
  f.reader.withHost = async (owner, host, project, fn) =>
    fn({
      base: "http://127.0.0.1:3773",
      listProjects: async ({ cursor }) => {
        pages++;
        return cursor === 0
          ? { projects: [], nextCursor: 100 }
          : { projects: [{ id: "project" }], nextCursor: null };
      },
    });
  await c.creation.create("eddie", f.p);
  assert.equal(pages, 2);
  f.reader.withHost = async (owner, host, project, fn) =>
    fn({ listProjects: async () => ({ projects: [], nextCursor: 0 }) });
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, request_id: randomUUID() }),
    /invalid_source_pagination/,
  );
  f.reader.withHost = async (owner, host, project, fn) =>
    fn({ listProjects: async () => ({ projects: [], nextCursor: null }) });
  await assert.rejects(
    c.creation.create("eddie", { ...f.p, request_id: randomUUID() }),
    /project_not_found/,
  );
  assert.equal(f.writes.length, 2);
});

test("official MCP discovery exposes creation only to command principals and does not leak native config", async (t) => {
  const f = fixture(t),
    tokens = { eddie: "creation-eddie-token", reader: "creation-reader-token" };
  f.policy.principals[0].tokenSha256 = createHash("sha256").update(tokens.eddie).digest("hex");
  f.policy.principals.push({
    id: "reader",
    sessions: [],
    tokenSha256: createHash("sha256").update(tokens.reader).digest("hex"),
  });
  const bridge = {
    policy: () => f.policy,
    store: f.store,
    sessions: () => [],
    fleetReads: f.reader,
    commands: f.commands(),
  };
  const server = httpServer(bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const clients = [];
  t.after(async () => {
    await Promise.all(clients.map((c) => c.close()));
    await new Promise((r) => server.close(r));
  });
  const connect = async (owner) => {
    const c = new Client(
      { name: "creation-test", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    clients.push(c);
    await c.connect(
      new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
        requestInit: { headers: { Authorization: "Bearer " + tokens[owner] } },
      }),
    );
    return c;
  };
  const eddie = await connect("eddie"),
    reader = await connect("reader"),
    tool = (await eddie.listTools()).tools.find((t) => t.name === "create_thread");
  assert.ok(tool);
  assert.ok(tool.inputSchema.required.includes("runtime_mode"));
  f.grant.creationRuntime.allowedModes = ["approval-required"];
  const denied = await eddie.callTool({
    name: "create_thread",
    arguments: { ...f.p, runtime_mode: "full-access" },
  });
  assert.equal(denied.structuredContent.reason, "runtime_mode_not_authorized");
  assert.equal(f.writes.length, 0);
  f.grant.creationRuntime.allowedModes = ["approval-required", "full-access"];
  assert.equal(
    (await reader.listTools()).tools.some((t) => t.name === "create_thread"),
    false,
  );
  assert.equal(
    (await eddie.callTool({ name: "create_thread", arguments: f.p })).structuredContent
      .start_submission,
    "accepted",
  );
  await assert.rejects(reader.callTool({ name: "create_thread", arguments: f.p }));
  assert.equal(f.writes.length, 2);
});

test("existing exact-bound caller acknowledges creation through MCP; wrong thread/run, expired caller and host-wide caller cannot", async (t) => {
  const f = fixture(t),
    commands = f.commands(),
    created = await commands.creation.create("eddie", f.p),
    v = f.projections.get(created.thread_id);
  v.runs[0].status = "running";
  const token = "bound-creation-ack",
    binding = {
      host: "local",
      threadId: created.thread_id,
      reviewer: "eddie",
      expiresAt: Date.now() + 60000,
    };
  f.policy.principals[0].eddieInbox = true;
  f.policy.principals.push({
    id: "bound",
    tokenSha256: createHash("sha256").update(token).digest("hex"),
    sessions: [],
    eddieCaller: binding,
  });
  f.reader.read = async () => ({
    thread: { threadId: created.thread_id, projectId: "project", activeRunId: "exact-run" },
  });
  const bridge = {
    policy: () => f.policy,
    now: Date.now,
    store: f.store,
    sessions: () => [],
    fleetReads: f.reader,
    commands,
  };
  bridge.exchanges = new Exchanges(bridge);
  const server = httpServer(bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const client = new Client(
    { name: "creation-ack", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  t.after(async () => {
    await client.close();
    await new Promise((r) => server.close(r));
  });
  await client.connect(
    new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
      requestInit: { headers: { Authorization: "Bearer " + token } },
    }),
  );
  const ack = (run_id) =>
    client.callTool({
      name: "acknowledge_thread_delivery",
      arguments: { request_id: f.p.request_id, run_id },
    });
  assert.equal((await ack("wrong-run")).isError, true);
  assert.equal(f.store.get("command", f.p.request_id).ackAt, undefined);
  binding.threadId = "wrong-thread";
  assert.equal((await ack("exact-run")).isError, true);
  binding.threadId = created.thread_id;
  const accepted = (await ack("exact-run")).structuredContent;
  assert.equal(accepted.agent_acknowledged, true);
  assert.equal(accepted.completed, false);
  assert.equal(accepted.run_id, "exact-run");
  assert.equal(f.writes.length, 2);
  binding.expiresAt = Date.now() - 1;
  assert.equal((await ack("exact-run")).isError, true);
  // Host-wide passive callers retain their existing five-tool surface.
  assert.match(
    (await commands.receipt("eddie", { request_id: f.p.request_id })).acknowledgement_support,
    /host-wide passive caller does not expose/,
  );
});

test("deployed acceptance CLI preserves immutable request input, gates exact success, and never resends after corrupted observations or no owned record", async (t) => {
  const f = fixture(t),
    token = "acceptance-cli-test";
  f.policy.principals[0].tokenSha256 = createHash("sha256").update(token).digest("hex");
  const commands = f.commands(),
    bridge = {
      policy: () => f.policy,
      store: f.store,
      sessions: () => [],
      fleetReads: f.reader,
      commands,
    },
    server = httpServer(bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => new Promise((r) => server.close(r)));
  const dir = mkdtempSync(join(tmpdir(), "eddie-acceptance-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const proof = join(dir, "request.json"),
    script = fileURLToPath(new URL("../scripts/verify-thread-creation.mjs", import.meta.url));
  const run = async (mode) => {
    try {
      return {
        code: 0,
        ...(await promisify(execFile)(process.execPath, [script, mode, proof, "project"], {
          env: {
            ...process.env,
            EDDIE_T3_MCP_AUTH: "Bearer " + token,
            EDDIE_T3_ACCEPTANCE_PORT: String(server.address().port),
          },
        })),
      };
    } catch (e) {
      return e;
    }
  };
  assert.equal((await run("prepare")).code, 0);
  const original = readFileSync(proof, "utf8"),
    request = JSON.parse(original).input;
  f.hook(async (method) => {
    if (method === "orchestration.getThreadProjection")
      for (const v of f.projections.values())
        for (const m of v.messages) if (m.role === "assistant") m.text = "EDDIE_T3_CREATE_OK";
  });
  const created = await run("create");
  assert.equal(created.code, 0, created.stdout);
  assert.equal(JSON.parse(created.stdout).acceptance, "passed");
  assert.equal(f.writes.length, 2);
  assert.equal(readFileSync(proof, "utf8"), original);
  assert.equal(
    JSON.parse(readFileSync(proof + ".attempted", "utf8")).input.request_id,
    request.request_id,
  );
  writeFileSync(proof + ".observation.json", "partial corrupted observation");
  assert.equal((await run("create")).code, 0);
  assert.equal(readFileSync(proof, "utf8"), original);
  assert.equal(f.writes.length, 2);
  const v = [...f.projections.values()][0];
  v.runs[0].status = "failed";
  assert.equal((await run("read")).code, 1);
  assert.equal(f.writes.length, 2);
  f.store.db.prepare("DELETE FROM records WHERE kind='command' AND id=?").run(request.request_id);
  assert.equal((await run("create")).code, 2);
  assert.equal(f.writes.length, 2);
  assert.equal(readFileSync(proof, "utf8"), original);
});
