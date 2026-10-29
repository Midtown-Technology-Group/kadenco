// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { Store } from "../dist/store.mjs";
import { Commands, resolveArgs, continueArgs } from "../dist/commands.mjs";
import { nativeSession } from "../dist/native-session.mjs";
import { configSchema } from "../dist/config.mjs";
import { httpServer } from "../dist/server.mjs";
import { Bridge } from "../dist/bridge.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
function fixture(t) {
  let now = Date.now(),
    dispatchError,
    hook = () => {};
  const writes = [];
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  const grant = {
    host: "local",
    expiresAt: now + 60000,
    maxPerDay: 10,
    providerInstanceIds: ["opencode"],
  };
  const policy = {
    principals: [{ id: "eddie", commandHosts: [grant] }],
    nativeDelivery: { hosts: [{ name: "local" }] },
  };
  const p = {
    host: "local",
    thread_id: "t",
    source_run_id: "r",
    request_id: randomUUID(),
    message: "Report progress.",
    execution: "allow_new_turn",
  };
  const projection = {
    thread: { id: "t", projectId: "p", modelSelection: { instanceId: "opencode", model: "model" } },
    runs: [
      {
        id: "r",
        status: "completed",
        providerThreadId: "pt",
        modelSelection: { instanceId: "opencode", model: "model" },
        userMessageId: "m",
      },
    ],
    providerThreads: [{ id: "pt", driver: "opencode" }],
    messages: [],
    nodes: [{ id: "node", runId: "r" }],
    runtimeRequests: [
      {
        id: "question",
        nodeId: "node",
        kind: "user_input",
        status: "pending",
        responseCapability: { type: "live" },
      },
    ],
  };
  const reader = {
    grant(owner, host, project) {
      if (owner !== "eddie" || host !== "local" || (project && project !== "p"))
        throw new Error("forbidden");
    },
    async withHost(owner, host, _, fn) {
      this.grant(owner, host);
      return fn({ base: "http://127.0.0.1:3773" });
    },
    async read() {
      return { thread: { threadId: "t", projectId: "p", activeRunId: "new-run" } };
    },
    async inventory() {
      return {
        threads: [
          { threadId: "a", title: "Same" },
          { threadId: "b", title: "Same" },
          { threadId: "c", title: "same" },
        ],
        next_cursor: "next",
        complete: false,
      };
    },
  };
  const session = async (route, fn) =>
    fn(async (base, method, args) => {
      if (method === "orchestration.getThreadProjection") {
        await hook();
        return projection;
      }
      writes.push(args);
      if (dispatchError) throw Object.assign(new Error(), { reason: dispatchError });
      return { sequence: 42 };
    });
  const commands = new Commands({ policy: () => policy, store, reader, now: () => now, session });
  return {
    store,
    grant,
    policy,
    p,
    projection,
    writes,
    commands,
    reader,
    session,
    advance: (ms) => {
      now += ms;
    },
    error: (e) => {
      dispatchError = e;
    },
    hook: (f) => {
      hook = f;
    },
  };
}

test("busy and idle preflight never advertises atomic steering or dispatches a probe", async (t) => {
  const f = fixture(t);
  for (const status of ["running", "waiting", "completed"]) {
    f.projection.runs[0].status = status;
    const r = await f.commands.capabilities("eddie", {
      host: "local",
      thread_id: "t",
      source_run_id: "r",
    });
    assert.equal(r.capabilities.strict_steer, false);
    assert.equal(r.capabilities.strict_steer_denial_reason, "native_atomic_steer_unavailable");
  }
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});

test("cancelled queued run and exact message merged into another run are distinct durable observations", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const messageId = f.writes[0].messageId;
  f.projection.runs.push({ id: "queued", userMessageId: messageId, status: "cancelled" });
  f.projection.runs[0].status = "running";
  f.projection.messages = [{ id: messageId, role: "user", runId: "r" }];
  f.projection.turnItems = [
    { type: "user_message", messageId, runId: "r", inputIntent: "promoted_queued_to_steer" },
  ];
  let r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.run_id, "queued");
  assert.equal(r.run_status, "cancelled");
  assert.equal(r.native_submitted, true);
  assert.equal(r.native_message_observation.run_id, "r");
  assert.equal(r.native_message_observation.run_status, "running");
  assert.equal(r.native_message_observation.input_intent, "promoted_queued_to_steer");
  assert.equal(r.message_observation_fresh, true);
  assert.equal(r.agent_acknowledged, false);
  assert.equal(r.completed, false);
  f.projection.runs[0].status = "completed";
  r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.native_message_observation.run_status, "completed");
  assert.equal(r.completed, false);
  assert.equal(r.agent_acknowledged, false);
  f.projection.messages = [];
  f.projection.turnItems = [];
  r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.native_message_observation.run_id, "r");
  assert.equal(r.message_observation_fresh, false);
  await f.commands.continue("eddie", f.p);
  assert.equal(f.writes.length, 1);
  f.grant.expiresAt = 0;
  await assert.rejects(f.commands.receipt("eddie", { request_id: f.p.request_id }), /forbidden/);
  assert.equal(f.writes.length, 1);
});

test("uncertain send reconciles an exact merged message without claiming a run binding or retrying", async (t) => {
  const f = fixture(t);
  f.error("native_outcome_unknown");
  let r = await f.commands.continue("eddie", f.p);
  assert.equal(r.stored, true);
  assert.equal(r.native_submitted, null);
  const messageId = f.writes[0].messageId;
  f.projection.turnItems = [{ type: "user_message", messageId, runId: "r", inputIntent: "steer" }];
  r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.native_message_status, "observed");
  assert.equal(r.native_message_observation.run_id, "r");
  assert.equal(r.submission, "outcome_unknown");
  assert.equal(r.run_bound, false);
  assert.equal(r.agent_acknowledged, false);
  assert.equal(r.safe_to_resend, false);
  await f.commands.continue("eddie", f.p);
  assert.equal(f.writes.length, 1);
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, message: "changed" }),
    /idempotency_conflict/,
  );
  f.hook(() => {
    throw Object.assign(Error(), { reason: "native_auth_unavailable" });
  });
  r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.message_observation_fresh, false);
  assert.equal(r.native_message_observation.run_id, "r");
  assert.equal(f.writes.length, 1);
});

test("contradictory message and item run attribution fails closed without redispatch", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const messageId = f.writes[0].messageId;
  f.projection.messages = [{ id: messageId, role: "user", runId: "r" }];
  f.projection.turnItems = [
    { type: "user_message", messageId, runId: "other", inputIntent: "steer" },
  ];
  await assert.rejects(
    f.commands.receipt("eddie", { request_id: f.p.request_id }),
    /identity_mismatch/,
  );
  assert.equal(f.writes.length, 1);
  f.projection.turnItems = [];
  f.projection.messages[0].threadId = "foreign";
  await assert.rejects(
    f.commands.receipt("eddie", { request_id: f.p.request_id }),
    /identity_mismatch/,
  );
  assert.equal(f.writes.length, 1);
});

test("receipt observes only the exact message and preserves concurrent delivery evidence", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  f.projection.messages = [{ id: "unrelated", role: "user", runId: "r" }];
  let r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.native_message_observation, null);
  const messageId = f.writes[0].messageId;
  f.projection.messages = [{ id: messageId, role: "user", runId: "r" }];
  f.hook(() => {
    const latest = f.store.get("command", f.p.request_id);
    latest.messageObservation = { message_id: messageId, run_id: "newer", run_status: "completed" };
    latest.observationRevision = 1;
    f.store.put("command", f.p.request_id, latest);
  });
  r = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(r.native_message_observation.run_id, "newer");
  assert.equal(r.message_observation_fresh, false);
  assert.equal(f.writes.length, 1);
});
test("collaboration guard prevents stale source/model selection and rechecks permission before reservation", async (t) => {
  const f = fixture(t);
  f.projection.runs[0].ordinal = 1;
  f.projection.runs.push({ ...f.projection.runs[0], id: "newer", ordinal: 2 });
  await assert.rejects(
    f.commands.continue("eddie", f.p, { currentSelectionOnly: true }),
    /source_changed/,
  );
  assert.equal(f.writes.length, 0);
  f.projection.runs.pop();
  f.projection.thread.modelSelection.model = "changed";
  await assert.rejects(
    f.commands.continue("eddie", f.p, { currentSelectionOnly: true }),
    /source_changed/,
  );
  assert.equal(f.writes.length, 0);
  f.projection.thread.modelSelection.model = "model";
  let allowed = true;
  f.hook(() => {
    allowed = false;
  });
  await assert.rejects(
    f.commands.continue("eddie", f.p, {
      authorize: () => {
        if (!allowed)
          throw Object.assign(Error("permissions_changed"), { reason: "permissions_changed" });
      },
    }),
    /permissions_changed/,
  );
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});
test("continuation explicitly authorizes a new queued turn and pins original provider/model without a steer fallback", async (t) => {
  const f = fixture(t),
    r = await f.commands.continue("eddie", f.p);
  assert.equal(r.submission, "accepted");
  assert.equal(r.completed, false);
  assert.equal(r.agent_acknowledged, false);
  assert.equal(r.run_id, null);
  assert.deepEqual(f.writes[0].dispatchMode, { type: "queue_after_active" });
  assert.equal(f.writes[0].deliveryIntent, undefined);
  assert.deepEqual(f.writes[0].modelSelection, { instanceId: "opencode", model: "model" });
  assert.match(f.writes[0].text, new RegExp(f.p.request_id));
  assert.deepEqual(await f.commands.continue("eddie", f.p), r);
  assert.equal(f.writes.length, 1);
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, message: "changed" }),
    /idempotency_conflict/,
  );
  assert.equal(continueArgs.safeParse({ ...f.p, execution: "steer_only" }).success, false);
});

test("a subscription-created lane carries a native question and exact answer back into the same run", async (t) => {
  const f = fixture(t),
    posts = [];
  f.policy.principals[0].sessions = [];
  f.policy.sessions = [];
  f.policy.callbackHosts = ["callbacks.example.com"];
  f.projection.runs[0].status = "waiting";
  f.projection.turnItems = [
    {
      type: "user_input_request",
      requestId: "question",
      questions: [{ id: "q", question: "What should I verify?" }],
    },
  ];
  f.reader.read = async () => ({
    thread: {
      threadId: "t",
      projectId: "p",
      pendingRequestCount: f.projection.runtimeRequests[0].status === "pending" ? 1 : 0,
      activeRunId: f.projection.runs[0].status === "waiting" ? "r" : null,
    },
    runs: f.projection.runs.map((r) => ({ ...r, runId: r.id })),
    items: [],
    hasMore: false,
  });
  const b = new Bridge({
    store: f.store,
    policy: () => f.policy,
    backend: {
      read: async () => {
        throw new Error("unexpected_legacy_source");
      },
    },
    post: async (_u, _h, body) => {
      const e = JSON.parse(body);
      posts.push(e);
      return { status: 200, body: JSON.stringify({ challenge: e.challenge }) };
    },
  });
  b.commands = f.commands;
  b.fleetReads = f.reader;
  const p = {
    name: "t3.thread.activity",
    arguments: { host: "local", thread_id: "t" },
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/event",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  };
  await b.subscribe("eddie", p);
  assert.equal(f.writes.length, 0);
  posts.length = 0;
  assert.equal(f.policy.sessions.length, 0);
  assert.equal(b.sessions("eddie").length, 1);
  await b.observe();
  await b.deliver();
  assert.equal(posts[0].data.native_request_id, "question");
  const answer = {
    host: "local",
    thread_id: "t",
    native_request_id: "question",
    request_id: randomUUID(),
    answers: { q: "Verify the evidence against the current source." },
  };
  assert.equal((await f.commands.answer("eddie", answer)).submission, "accepted");
  await f.commands.answer("eddie", answer);
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].type, "runtime-request.respond");
  f.projection.runtimeRequests[0].status = "responded";
  f.projection.runs[0].status = "completed";
  f.projection.runs[0].completedAt = new Date(Date.now() + 1).toISOString();
  f.projection.messages.push({ runId: "r", role: "assistant", text: "Review refined." });
  await b.observe();
  await b.deliver();
  assert.equal(posts[1].data.kind, "task_finished");
  assert.equal(posts[1].data.run_id, "r");
  const receipt = await f.commands.receipt("eddie", { request_id: answer.request_id });
  assert.equal(receipt.run_id, "r");
  assert.equal(receipt.completed, true);
  assert.equal(receipt.result, "Review refined.");
  assert.equal(f.writes.length, 1);
  assert.equal(f.projection.runs.length, 1);
  await f.commands.continue("eddie", f.p);
  assert.match(f.writes[1].text, /existing native question\/user-input tool/);
});

test("nonexpiring standing subscriptions cannot extend a native execution grant or deliver after its expiry", async (t) => {
  const f = fixture(t),
    posts = [];
  f.policy.principals[0].sessions = [];
  f.policy.sessions = [];
  f.policy.callbackHosts = ["callbacks.example.com"];
  f.reader.read = async () => ({
    thread: { threadId: "t", projectId: "p", pendingRequestCount: 1, activeRunId: "r" },
    runs: [],
    items: [],
    hasMore: false,
  });
  const b = new Bridge({
    store: f.store,
    policy: () => f.policy,
    now: f.commands.now,
    backend: {},
    post: async (_u, _h, body) => {
      const e = JSON.parse(body);
      posts.push(e);
      return { status: 200, body: JSON.stringify({ challenge: e.challenge }) };
    },
  });
  b.commands = f.commands;
  b.fleetReads = f.reader;
  const p = {
    name: "t3.thread.activity",
    arguments: { host: "local", thread_id: "t" },
    ttlMs: null,
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/standing",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  };
  const expiry = f.grant.expiresAt;
  assert.equal((await b.subscribe("eddie", p)).refreshBefore, null);
  posts.length = 0;
  await b.observe();
  assert.equal(f.store.all("delivery").length, 1);
  f.advance(61000);
  await b.deliver();
  assert.equal(posts.length, 0);
  assert.equal(b.lanes.sessions("eddie").length, 0);
  await assert.rejects(f.commands.continue("eddie", f.p), /forbidden/);
  assert.equal(f.grant.expiresAt, expiry);
  assert.equal(f.writes.length, 0);
});
test("lost response is persisted across restart; readback reconciles exact native message and result without resending", async (t) => {
  const f = fixture(t);
  f.error("native_outcome_unknown");
  const r = await f.commands.continue("eddie", f.p);
  assert.equal(r.submission, "outcome_unknown");
  const resumed = new Commands({
    policy: () => f.policy,
    store: f.store,
    reader: f.reader,
    session: f.session,
  });
  await resumed.continue("eddie", f.p);
  assert.equal(f.writes.length, 1);
  const messageId = f.writes[0].messageId;
  f.projection.runs.push({ id: "new-run", userMessageId: messageId, status: "completed" });
  f.projection.messages.push(
    { runId: "unrelated", role: "assistant", text: "WRONG" },
    { runId: "new-run", role: "assistant", text: "EXACT_RESULT" },
  );
  const receipt = await resumed.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.submission, "accepted");
  assert.equal(receipt.run_id, "new-run");
  assert.equal(receipt.result, "EXACT_RESULT");
  assert.equal(receipt.completed, true);
  assert.equal(receipt.agent_acknowledged, false);
  assert.equal(f.writes.length, 1);
});
test("live question response is exact, one-shot and cannot answer approvals or message-based questions", async (t) => {
  const f = fixture(t),
    p = {
      host: "local",
      thread_id: "t",
      request_id: randomUUID(),
      native_request_id: "question",
      answers: { q: "yes" },
    };
  const r = await f.commands.answer("eddie", p);
  assert.equal(r.submission, "accepted");
  assert.equal(f.writes[0].type, "runtime-request.respond");
  assert.equal(f.writes[0].requestId, "question");
  await f.commands.answer("eddie", p);
  assert.equal(f.writes.length, 1);
  for (const mutate of [
    (r) => (r.kind = "approval"),
    (r) => (r.status = "resolved"),
    (r) => (r.responseCapability.type = "message"),
  ]) {
    const request = f.projection.runtimeRequests[0];
    Object.assign(request, {
      kind: "user_input",
      status: "pending",
      responseCapability: { type: "live" },
    });
    mutate(request);
    await assert.rejects(
      f.commands.answer("eddie", { ...p, request_id: randomUUID() }),
      /live_request_required/,
    );
  }
  assert.equal(f.writes.length, 1);
});
test("read permission alone, wrong host/project, expired/revoked grants and unsupported drivers cannot execute", async (t) => {
  const f = fixture(t);
  await assert.rejects(f.commands.continue("reader", f.p), /forbidden/);
  await assert.rejects(f.commands.continue("eddie", { ...f.p, host: "other" }), /forbidden/);
  f.projection.thread.projectId = "secret";
  await assert.rejects(f.commands.continue("eddie", f.p), /forbidden/);
  f.projection.thread.projectId = "p";
  f.hook(() => {
    f.policy.principals[0].enabled = false;
  });
  await assert.rejects(f.commands.continue("eddie", f.p), /forbidden/);
  f.hook(() => {});
  f.policy.principals[0].enabled = true;
  for (const driver of ["unknown", undefined]) {
    f.projection.providerThreads[0].driver = driver;
    await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
  }
  f.projection.providerThreads[0].driver = "opencode";
  f.advance(60001);
  await assert.rejects(f.commands.continue("eddie", f.p), /forbidden/);
  assert.equal(f.writes.length, 0);
});

test("a readable source omitted from the command projection never substitutes the latest run or reserves/replays a continuation", async (t) => {
  const f = fixture(t);
  f.projection.runs[0].id = "different-latest-run";
  f.reader.read = async () => ({
    thread: { threadId: "t", projectId: "p" },
    runs: [{ runId: f.p.source_run_id, status: "completed" }],
  });
  await assert.rejects(f.commands.continue("eddie", f.p), /source_run_not_found/);
  const receipt = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.state, "no_owned_record");
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(f.writes.length, 0);
});
test("unknown/rejected submissions reserve budget and conflicting kinds or UUID owners cannot replay", async (t) => {
  const f = fixture(t);
  f.grant.maxPerDay = 1;
  f.error("native_rejected");
  assert.equal((await f.commands.continue("eddie", f.p)).submission, "rejected");
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /command_budget_exhausted/,
  );
  await assert.rejects(
    f.commands.answer("eddie", {
      host: "local",
      thread_id: "t",
      request_id: f.p.request_id,
      native_request_id: "question",
      answers: { q: "a" },
    }),
    /idempotency_conflict/,
  );
  assert.equal(f.writes.length, 1);
});
test("agent acknowledgement is bound to the exact recipient thread and delivered run and never proves completion", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  f.projection.runs.push({
    id: "new-run",
    userMessageId: f.writes[0].messageId,
    status: "running",
  });
  // Acknowledgement consumes retained native evidence, never mints an RPC
  // credential to discover a run. The reviewer reconciles placement first.
  await f.commands.receipt("eddie", { request_id: f.p.request_id });
  f.commands.session = async () => {
    throw Error("ack_must_not_issue_credentials");
  };
  await assert.rejects(
    f.commands.acknowledge("caller", "eddie", "local", "wrong", {
      request_id: f.p.request_id,
      run_id: "new-run",
    }),
    /forbidden/,
  );
  await assert.rejects(
    f.commands.acknowledge("caller", "eddie", "local", "t", {
      request_id: f.p.request_id,
      run_id: "wrong",
    }),
    /identity_mismatch/,
  );
  const ack = await f.commands.acknowledge("caller", "eddie", "local", "t", {
    request_id: f.p.request_id,
    run_id: "new-run",
  });
  assert.equal(ack.agent_acknowledged, true);
  assert.equal(ack.completed, false);
  assert.equal(f.writes.length, 1);
});
test("native send-boundary guard rechecks broker expiry after ticket acquisition", async (t) => {
  const f = fixture(t);
  f.commands.session = async (route, fn) =>
    f.session(route, (call) =>
      fn(async (base, method, args) => {
        if (method === "orchestration.dispatchCommand") {
          f.advance(61000);
          route.authorizeDispatch();
        }
        return call(base, method, args);
      }),
    );
  const result = await f.commands.continue("eddie", f.p);
  assert.equal(result.submission, "rejected");
  assert.equal(f.writes.length, 0);
});

test("title resolution preserves duplicate matches and continuation even on incomplete pages", async (t) => {
  const f = fixture(t),
    r = await f.commands.resolve("eddie", { host: "local", title: "Same" });
  assert.deepEqual(
    r.matches.map((m) => m.threadId),
    ["a", "b"],
  );
  assert.equal(r.next_cursor, "next");
  assert.equal(r.complete, false);
  assert.equal(f.writes.length, 0);
  assert.equal(
    resolveArgs.safeParse({ title: "Same", thread_id: "a", host: "local" }).success,
    false,
  );
});
test("native question discovery paginates, excludes approvals and identifies non-live answers without exposing provider internals", async (t) => {
  const f = fixture(t);
  f.projection.runtimeRequests = Array.from({ length: 30 }, (_, i) => ({
    id: "q" + String(i).padStart(2, "0"),
    kind: "user_input",
    status: "pending",
    responseCapability: { type: i === 0 ? "message" : "live", providerSessionId: "private" },
  }));
  f.projection.runtimeRequests.push({ id: "approval", kind: "approval", status: "pending" });
  const first = await f.commands.requests("eddie", { host: "local", thread_id: "t" });
  assert.equal(first.requests.length, 25);
  assert.equal(first.requests[0].live_answer_allowed, false);
  assert.equal(first.next_cursor, "q24");
  assert.match(first.instruction, /continue_thread/);
  assert.match(first.instruction, /does not resolve the native request/);
  const last = await f.commands.requests("eddie", {
    host: "local",
    thread_id: "t",
    after_request_id: first.next_cursor,
  });
  assert.equal(last.requests.length, 5);
  assert.equal(last.next_cursor, null);
  assert.equal(JSON.stringify(first).includes("private"), false);
  assert.equal(f.writes.length, 0);
});

test("question readback supplies exact live/async reply contracts without granting execution or guessing missing runs", async (t) => {
  const f = fixture(t);
  f.projection.runtimeRequests = ["live", "message", "future"].map((type) => ({
    id: type,
    nodeId: "node",
    kind: "user_input",
    status: "pending",
    responseCapability: { type },
  }));
  f.projection.runtimeRequests.push({
    id: "missing-run",
    nodeId: "absent",
    kind: "user_input",
    status: "pending",
    responseCapability: { type: "message" },
  });
  const page = await f.commands.requests("eddie", { host: "local", thread_id: "t" }),
    byId = Object.fromEntries(page.requests.map((r) => [r.native_request_id, r]));
  assert.deepEqual(byId.live.reply_contract, {
    tool: "answer_thread_request",
    starts_new_turn: false,
    requires_task_authorization: true,
  });
  assert.deepEqual(byId.message.reply_contract, {
    tool: "continue_thread",
    source_run_id: "r",
    execution: "allow_new_turn",
    starts_new_turn: true,
    requires_task_authorization: true,
  });
  assert.deepEqual(byId.future.reply_contract, {
    tool: null,
    reason: "unsupported_response_mode",
    requires_task_authorization: true,
  });
  assert.equal(byId.future.response_mode, "unknown");
  assert.deepEqual(byId["missing-run"].reply_contract, {
    tool: null,
    reason: "source_run_unavailable",
    requires_task_authorization: true,
  });
  f.projection.runs = [];
  const omitted = await f.commands.requests("eddie", { host: "local", thread_id: "t" });
  const message = omitted.requests.find((r) => r.native_request_id === "message");
  assert.equal(message.run_id, "r");
  assert.equal(message.reply_contract.tool, null);
  assert.equal(message.reply_contract.reason, "source_run_unavailable");
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
  f.grant.expiresAt = 0;
  await assert.rejects(
    f.commands.requests("eddie", { host: "local", thread_id: "t" }),
    /forbidden/,
  );
});

test("exact pending-question lookup bypasses page position, excludes resolved/approval requests and refuses mixed cursors", async (t) => {
  const f = fixture(t);
  f.projection.runtimeRequests = Array.from({ length: 30 }, (_, i) => ({
    id: "q" + String(i).padStart(2, "0"),
    nodeId: "node",
    kind: "user_input",
    status: "pending",
    responseCapability: { type: "message" },
  }));
  f.projection.runtimeRequests.push(
    { id: "approval", kind: "approval", status: "pending" },
    { id: "resolved", kind: "user_input", status: "resolved" },
  );
  const input = { host: "local", thread_id: "t", native_request_id: "q29" };
  const exact = await f.commands.requests("eddie", input);
  assert.deepEqual(
    exact.requests.map((r) => r.native_request_id),
    ["q29"],
  );
  assert.equal(exact.next_cursor, null);
  for (const native_request_id of ["approval", "resolved", "absent"])
    assert.equal(
      (await f.commands.requests("eddie", { ...input, native_request_id })).requests.length,
      0,
    );
  await assert.rejects(
    f.commands.requests("eddie", { ...input, after_request_id: "q01" }),
    /either an exact/,
  );
  await assert.rejects(f.commands.requests("other", input), /forbidden/);
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});
test("separate native credential has bounded expiry, refuses redirected auth and revokes on failure", async () => {
  const calls = [];
  await assert.rejects(
    nativeSession(
      { name: "local", command: "t3" },
      (call) =>
        call("http://127.0.0.1:3773", "orchestration.getThreadProjection", { threadId: "t" }),
      {
        execute: async (exe, args) => {
          calls.push(args);
          return {
            stdout: args.includes("issue")
              ? JSON.stringify({ sessionId: "s", subject: "eddie-t3-delivery", token: "secret" })
              : "",
          };
        },
        fetchImpl: async (url, init) => {
          assert.equal(init.redirect, "error");
          assert.equal(init.headers.authorization, "Bearer secret");
          throw new Error("redirect");
        },
      },
    ),
    /native_auth_unavailable/,
  );
  assert.ok(calls[0].includes("2m"));
  assert.deepEqual(calls[1], ["auth", "session", "revoke", "s"]);
});
test("native dispatch rechecks collaboration authority after ticket acquisition, before WebSocket send", async () => {
  let allowed = true,
    sent = 0;
  const calls = [];
  class Socket extends EventTarget {
    constructor() {
      super();
      queueMicrotask(() => this.dispatchEvent(new Event("open")));
    }
    send() {
      sent++;
    }
    close() {}
  }
  await assert.rejects(
    nativeSession(
      {
        name: "local",
        command: "t3",
        authorizeDispatch() {
          if (!allowed)
            throw Object.assign(Error("permissions_changed"), { reason: "permissions_changed" });
        },
      },
      (call) =>
        call("http://127.0.0.1:3773", "orchestration.dispatchCommand", {
          type: "message.dispatch",
        }),
      {
        execute: async (exe, args) => {
          calls.push(args);
          return {
            stdout: args.includes("issue")
              ? JSON.stringify({ sessionId: "s", subject: "eddie-t3-delivery", token: "secret" })
              : "",
          };
        },
        fetchImpl: async () => {
          allowed = false;
          return new Response(JSON.stringify({ ticket: "ticket" }));
        },
        Socket,
      },
    ),
    /permissions_changed/,
  );
  assert.equal(sent, 0);
  assert.deepEqual(calls.at(-1), ["auth", "session", "revoke", "s"]);
});

test("late WebSocket open after a failed native call cannot dispatch a command", async () => {
  let instance,
    sent = 0;
  class Socket extends EventTarget {
    constructor() {
      super();
      instance = this;
      queueMicrotask(() => this.dispatchEvent(new Event("error")));
    }
    send() {
      sent++;
    }
    close() {}
  }
  await assert.rejects(
    nativeSession(
      { name: "local", command: "t3" },
      (call) =>
        call("http://127.0.0.1:3773", "orchestration.dispatchCommand", {
          type: "message.dispatch",
        }),
      {
        execute: async (exe, args) => ({
          stdout: args.includes("issue")
            ? JSON.stringify({ sessionId: "s", subject: "eddie-t3-delivery", token: "secret" })
            : "",
        }),
        fetchImpl: async () => new Response(JSON.stringify({ ticket: "ticket" })),
        Socket,
      },
    ),
    /native_outcome_unknown/,
  );
  instance.dispatchEvent(new Event("open"));
  assert.equal(sent, 0);
});

test("policy accepts Codex host enrollment and rejects unreadable or ambiguous command routes", () => {
  const base = {
    source: { type: "local-projection", databasePath: "x" },
    stateDirectory: "x",
    callbackHosts: [],
    sessions: [],
    fleetRead: { hosts: [{ name: "local" }] },
    nativeDelivery: { hosts: [{ name: "local", command: "t3" }] },
    principals: [
      {
        id: "eddie",
        tokenSha256: "a".repeat(64),
        sessions: [],
        readHosts: [{ host: "local" }],
        commandHosts: [
          {
            host: "local",
            providerInstanceIds: ["opencode"],
            expiresAt: Date.now() + 60000,
            maxPerDay: 1,
          },
        ],
      },
    ],
  };
  assert.equal(configSchema.safeParse(base).success, true);
  const codex = structuredClone(base);
  codex.principals[0].commandHosts[0].providerInstanceIds = ["codex"];
  assert.equal(configSchema.safeParse(codex).success, true);
  for (const change of [
    (p) => (p.principals[0].readHosts = []),
    (p) => p.nativeDelivery.hosts.push({ ...p.nativeDelivery.hosts[0] }),
  ]) {
    const p = structuredClone(base);
    change(p);
    assert.equal(configSchema.safeParse(p).success, false);
  }
});
test("official MCP client discovers authorized delivery tools and read-only principals cannot invoke continuation", async (t) => {
  const f = fixture(t),
    tokens = { eddie: "eddie-test-token", reader: "reader-test-token" };
  f.policy.principals[0].tokenSha256 = createHash("sha256").update(tokens.eddie).digest("hex");
  f.policy.principals.push({
    id: "reader",
    tokenSha256: createHash("sha256").update(tokens.reader).digest("hex"),
  });
  const bridge = {
    policy: () => f.policy,
    store: f.store,
    sessions: () => [],
    fleetReads: f.reader,
    commands: f.commands,
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
      { name: "test", version: "1" },
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
    reader = await connect("reader");
  assert.ok((await eddie.listTools()).tools.some((t) => t.name === "continue_thread"));
  f.projection.runtimeRequests[0].responseCapability.type = "message";
  const question = await eddie.callTool({
    name: "read_thread_requests",
    arguments: { host: "local", thread_id: "t", native_request_id: "question" },
  });
  assert.equal(question.structuredContent.requests[0].reply_contract.tool, "continue_thread");
  assert.equal(question.structuredContent.requests[0].reply_contract.source_run_id, "r");
  assert.equal(f.writes.length, 0);
  assert.equal(
    (await reader.listTools()).tools.some((t) => t.name === "continue_thread"),
    false,
  );
  assert.equal(
    (await eddie.callTool({ name: "continue_thread", arguments: f.p })).structuredContent
      .submission,
    "accepted",
  );
  await assert.rejects(reader.callTool({ name: "continue_thread", arguments: f.p }));
  assert.equal(f.writes.length, 1);
  f.projection.providerThreads[0].driver = "codex";
  f.projection.runs[0].modelSelection = { instanceId: "codex", model: "gpt-6.1-sol" };
  const request_id = randomUUID(),
    denied = await eddie.callTool({ name: "continue_thread", arguments: { ...f.p, request_id } });
  assert.equal(denied.structuredContent.reason, "provider_not_authorized");
  assert.equal(denied.structuredContent.request_id, request_id);
  assert.equal(denied.structuredContent.backend_version, "0.11.0");
  assert.equal(f.store.get("command", request_id), undefined);
  assert.equal(
    f.store.db
      .prepare("SELECT subject FROM audit WHERE action='command.denied' AND subject=?")
      .get(request_id).subject,
    request_id,
  );
  assert.equal(
    (await eddie.callTool({ name: "get_delivery_receipt", arguments: { request_id } }))
      .structuredContent.state,
    "no_owned_record",
  );
});

function codexFixture(t) {
  const f = fixture(t);
  f.projection.providerThreads[0].driver = "codex";
  f.projection.runs[0].modelSelection = { instanceId: "codex", model: "gpt-6.1-sol" };
  f.grant.codexExceptions = [
    {
      threadId: "t",
      projectId: "p",
      providerInstanceId: "codex",
      model: "gpt-6.1-sol",
      expiresAt: f.grant.expiresAt,
      maxPerDay: 1,
      authorization: "the owner explicitly authorized this exact Codex thread",
    },
  ];
  return f;
}
test("exact Codex exception allows continuation and records authorization, budget and provider selection", async (t) => {
  const f = codexFixture(t),
    r = await f.commands.continue("eddie", f.p);
  assert.equal(r.submission, "accepted");
  assert.equal(r.execution_authorization.driver, "codex");
  assert.equal(r.execution_authorization.maxPerDay, 1);
  assert.match(r.execution_authorization.authorization, /the owner/);
  assert.deepEqual(f.writes[0].modelSelection, { instanceId: "codex", model: "gpt-6.1-sol" });
  await f.commands.continue("eddie", f.p);
  assert.equal(f.writes.length, 1);
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /command_budget_exhausted/,
  );
  assert.equal(f.writes.length, 1);
});
test("Codex exception cannot authorize another thread, project, model, provider, owner or driver; expiry and revocation fail closed", async (t) => {
  const f = codexFixture(t),
    e = f.grant.codexExceptions[0];
  for (const [key, value] of [
    ["threadId", "other"],
    ["projectId", "other"],
    ["model", "other"],
    ["providerInstanceId", "alias"],
    ["expiresAt", 1],
    ["maxPerDay", 0],
    ["authorization", ""],
  ]) {
    const old = e[key];
    e[key] = value;
    await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
    e[key] = old;
  }
  await assert.rejects(f.commands.continue("other", f.p), /forbidden/);
  f.projection.providerThreads[0].driver = "chatgpt";
  await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
  f.projection.providerThreads[0].driver = "codex";
  f.grant.codexExceptions = [];
  await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
  assert.equal(f.writes.length, 0);
});
test("Codex exception supports native lane preflight and same-run question answers with the same budget", async (t) => {
  const f = codexFixture(t);
  const page = await f.commands.requests(
    "eddie",
    { host: "local", thread_id: "t" },
    { forLane: true },
  );
  assert.equal(page.requests.length, 1);
  assert.equal(f.writes.length, 0);
  const r = await f.commands.answer("eddie", {
    host: "local",
    thread_id: "t",
    request_id: randomUUID(),
    native_request_id: "question",
    answers: { q: "Continue the authorized work." },
  });
  assert.equal(r.execution_authorization.driver, "codex");
  assert.equal(f.writes[0].type, "runtime-request.respond");
  await assert.rejects(f.commands.continue("eddie", f.p), /command_budget_exhausted/);
  assert.equal(f.writes.length, 1);
});
test("Codex authorization is rechecked after durable reservation before native dispatch", async (t) => {
  const f = codexFixture(t),
    audit = f.store.audit.bind(f.store);
  f.store.audit = (action, ...args) => {
    audit(action, ...args);
    if (action === "command.stored") f.grant.codexExceptions = [];
  };
  const r = await f.commands.continue("eddie", f.p);
  assert.equal(r.submission, "rejected");
  assert.equal(f.writes.length, 0);
});

test("explicitly uncapped commands continue past old host and Codex allowances while retries remain one-shot", async (t) => {
  const f = codexFixture(t);
  f.grant.maxPerDay = null;
  f.grant.codexExceptions[0].maxPerDay = null;
  // Retained daily attempts from before the policy change must not block work.
  for (let i = 0; i < 10; i++)
    f.store.put("command", "historical-" + i, {
      owner: "eddie",
      host: "local",
      thread_id: "t",
      at: Date.now(),
      executionAuthorization: { driver: "codex" },
    });
  for (let i = 0; i < 12; i++) {
    const p = { ...f.p, request_id: randomUUID() };
    const r = await f.commands.continue("eddie", p);
    assert.equal(r.submission, "accepted");
    assert.equal(r.execution_authorization.maxPerDay, null);
    assert.equal(r.execution_authorization.budgetUnit, "unlimited_commands");
    await f.commands.continue("eddie", p);
  }
  const answer = {
    host: "local",
    thread_id: "t",
    request_id: randomUUID(),
    native_request_id: "question",
    answers: { q: "Authorized answer" },
  };
  assert.equal((await f.commands.answer("eddie", answer)).submission, "accepted");
  await f.commands.answer("eddie", answer);
  assert.equal(f.writes.length, 13);
  f.grant.codexExceptions = [];
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /provider_not_authorized/,
  );
});

test("uncapped non-Codex commands retain idempotency across rejected and unknown deliveries", async (t) => {
  const f = fixture(t);
  f.grant.maxPerDay = null;
  for (const reason of ["native_rejected", "native_outcome_unknown"]) {
    f.error(reason);
    const p = { ...f.p, request_id: randomUUID() };
    const r = await f.commands.continue("eddie", p);
    assert.equal(r.submission, reason === "native_rejected" ? "rejected" : "outcome_unknown");
    await f.commands.continue("eddie", p);
    await assert.rejects(
      f.commands.continue("eddie", { ...p, message: "changed" }),
      /idempotency_conflict/,
    );
  }
  assert.equal(f.writes.length, 2);
  f.grant.expiresAt = 1;
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /forbidden/,
  );
});

test("uncapped host can retain a separately limited Codex exception", async (t) => {
  const f = codexFixture(t);
  f.grant.maxPerDay = null;
  await f.commands.continue("eddie", f.p);
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /command_budget_exhausted/,
  );
  assert.equal(f.writes.length, 1);
});

test("legacy exact-thread Codex grants remain validated alongside ordinary host grants", () => {
  const exception = {
    threadId: "00000000-0000-4000-8000-000000000003",
    projectId: "p",
    providerInstanceId: "codex",
    model: "gpt-6.1-sol",
    expiresAt: 100,
    maxPerDay: 2,
    authorization: "Explicit user authorization",
  };
  const base = {
    source: { type: "local-projection", databasePath: "x" },
    stateDirectory: "x",
    callbackHosts: [],
    sessions: [],
    fleetRead: { hosts: [{ name: "local" }] },
    nativeDelivery: { hosts: [{ name: "local", command: "t3" }] },
    principals: [
      {
        id: "eddie",
        tokenSha256: "a".repeat(64),
        sessions: [],
        readHosts: [{ host: "local", projectIds: ["p"] }],
        commandHosts: [
          {
            host: "local",
            providerInstanceIds: ["opencode"],
            expiresAt: 100,
            maxPerDay: 2,
            codexExceptions: [exception],
          },
        ],
      },
    ],
  };
  assert.equal(configSchema.safeParse(base).success, true);
  const uncapped = structuredClone(base),
    g = uncapped.principals[0].commandHosts[0];
  g.maxPerDay = null;
  g.codexExceptions[0].maxPerDay = null;
  assert.equal(configSchema.safeParse(uncapped).success, true);
  g.maxPerDay = 2;
  assert.equal(configSchema.safeParse(uncapped).success, false);
  g.maxPerDay = null;
  g.codexExceptions[0].maxPerDay = 2;
  assert.equal(configSchema.safeParse(uncapped).success, true);
  for (const mutate of [
    (b) => b.principals[0].commandHosts[0].codexExceptions.push({ ...exception }),
    (b) => (b.principals[0].commandHosts[0].codexExceptions[0].expiresAt = 101),
    (b) => (b.principals[0].commandHosts[0].codexExceptions[0].maxPerDay = 3),
    (b) => (b.principals[0].commandHosts[0].codexExceptions[0].projectId = "other"),
    (b) => (b.principals[0].commandHosts[0].codexExceptions[0].authorization = ""),
  ]) {
    const copy = structuredClone(base);
    mutate(copy);
    assert.equal(configSchema.safeParse(copy).success, false);
  }
});

test("read-only preflight explains provider, grant, expiry and budget boundaries without writing or granting", async (t) => {
  const f = fixture(t),
    target = { host: "local", thread_id: "t" };
  const yes = await f.commands.capabilities("eddie", target);
  assert.equal(yes.execution.allowed, true);
  assert.equal(yes.preflight_only, true);
  f.projection.providerThreads[0].driver = "codex";
  f.projection.runs[0].modelSelection = { instanceId: "codex", model: "gpt-6.1-sol" };
  const no = await f.commands.capabilities("eddie", target);
  assert.equal(no.read, true);
  assert.equal(no.execution.reason, "provider_not_authorized");
  assert.equal(no.capabilities.thread_activity_subscription, false);
  assert.equal(f.store.all("command").length, 0);
  assert.equal(f.writes.length, 0);
  f.policy.principals[0].commandHosts = [];
  assert.equal(
    (await f.commands.capabilities("eddie", target)).execution.reason,
    "command_grant_missing",
  );
  f.policy.principals[0].commandHosts = [f.grant];
  f.advance(60001);
  assert.equal(
    (await f.commands.capabilities("eddie", target)).execution.reason,
    "command_grant_expired",
  );
  await assert.rejects(f.commands.capabilities("reader", target), /forbidden/);
});

test("question coverage uses exact response capability and excludes permission approvals", async (t) => {
  const f = fixture(t);
  f.projection.runtimeRequests.push(
    { kind: "user_input", status: "pending", responseCapability: { type: "message" } },
    { kind: "user_input", status: "pending", responseCapability: { type: "future" } },
    { kind: "approval", status: "pending", responseCapability: { type: "live" } },
    { kind: "user_input", status: "responded", responseCapability: { type: "live" } },
  );
  const r = await f.commands.capabilities("eddie", { host: "local", thread_id: "t" });
  assert.deepEqual(r.native_questions, {
    live_pending: 1,
    asynchronous_pending: 1,
    unknown_pending: 1,
    approvals_excluded: true,
  });
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});

test("preflight reflects exact Codex exception limits and rechecks read authorization after source I/O", async (t) => {
  const f = codexFixture(t),
    target = { host: "local", thread_id: "t", source_run_id: "r" };
  assert.equal((await f.commands.capabilities("eddie", target)).execution.allowed, true);
  await f.commands.continue("eddie", f.p);
  const exhausted = await f.commands.capabilities("eddie", target);
  assert.equal(exhausted.execution.reason, "command_budget_exhausted");
  assert.equal(exhausted.capabilities.thread_activity_subscription, true);
  f.grant.maxPerDay = null;
  f.grant.codexExceptions[0].maxPerDay = null;
  const unlimited = await f.commands.capabilities("eddie", target);
  assert.equal(unlimited.execution.allowed, true);
  assert.equal(unlimited.execution.limits.host_max_per_utc_day, null);
  f.projection.thread.projectId = "private";
  await assert.rejects(f.commands.capabilities("eddie", target), /forbidden/);
  assert.equal(f.writes.length, 1);
});

test("unknown and foreign command IDs have identical owner-scoped absence semantics without exposing execution", async (t) => {
  const f = fixture(t),
    request_id = randomUUID();
  const absent = await f.commands.receipt("eddie", { request_id });
  f.store.put("command", request_id, { owner: "someone-else", thread_id: "PRIVATE" });
  const foreign = await f.commands.receipt("eddie", { request_id });
  assert.deepEqual(foreign, absent);
  assert.equal(absent.state, "no_owned_record");
  assert.equal(absent.safe_to_resend, false);
  assert.equal(absent.source_status, "not_checked");
  assert.equal(f.writes.length, 0);
  await assert.rejects(f.commands.receipt("unknown", { request_id }), /forbidden/);
});

test("owned receipts surface observation outages instead of reporting absence or resending", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  f.hook(() => {
    throw Object.assign(new Error("private failure"), { reason: "source_unavailable" });
  });
  const receipt = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.stored, true);
  assert.equal(receipt.source_status, "unavailable");
  assert.equal(receipt.source_error, "source_unavailable");
  assert.equal(receipt.submission, "accepted");
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(f.writes.length, 1);
  assert.equal(f.store.get("command", f.p.request_id).submission, "accepted");
});

test("ordinary Codex host grants support continuations, lanes and live replies without exact-thread exceptions", async (t) => {
  const f = codexFixture(t);
  f.grant.providerInstanceIds.push("codex");
  delete f.grant.codexExceptions;
  f.projection.runs[0].modelSelection.options = {
    reasoningEffort: "medium",
    serviceTier: "default",
  };
  const target = { host: "local", thread_id: "t", source_run_id: "r" };
  const preflight = await f.commands.capabilities("eddie", target);
  assert.equal(preflight.execution.allowed, true);
  assert.equal(preflight.capabilities.thread_activity_subscription, true);
  assert.equal(
    (await f.commands.requests("eddie", { host: "local", thread_id: "t" }, { forLane: true }))
      .requests.length,
    1,
  );
  const r = await f.commands.continue("eddie", f.p);
  assert.equal(r.execution_authorization.scope, "host_provider_grant");
  assert.equal(r.execution_authorization.driver, "codex");
  assert.equal(r.execution_authorization.expiresAt, f.grant.expiresAt);
  assert.deepEqual(f.writes[0].modelSelection, f.projection.runs[0].modelSelection);
  await f.commands.continue("eddie", f.p);
  assert.equal(f.writes.length, 1);
  await f.commands.answer("eddie", {
    host: "local",
    thread_id: "t",
    request_id: randomUUID(),
    native_request_id: "question",
    answers: { q: "Proceed" },
  });
  assert.equal(f.writes.length, 2);
  assert.equal(f.writes[1].type, "runtime-request.respond");
  f.projection.thread.id = "another-thread";
  assert.equal(
    (
      await f.commands.continue("eddie", {
        ...f.p,
        thread_id: "another-thread",
        request_id: randomUUID(),
      })
    ).submission,
    "accepted",
  );
});

test("ordinary Codex grants obey host limits and revocation, without inheriting retired legacy exception limits", async (t) => {
  const f = codexFixture(t);
  f.grant.providerInstanceIds.push("codex");
  f.grant.maxPerDay = 2;
  await f.commands.continue("eddie", f.p);
  assert.equal(
    (await f.commands.capabilities("eddie", { host: "local", thread_id: "t" })).execution.allowed,
    true,
  );
  await f.commands.continue("eddie", { ...f.p, request_id: randomUUID() });
  await assert.rejects(
    f.commands.continue("eddie", { ...f.p, request_id: randomUUID() }),
    /command_budget_exhausted/,
  );
  f.grant.maxPerDay = null;
  const audit = f.store.audit.bind(f.store);
  f.store.audit = (action, ...args) => {
    audit(action, ...args);
    if (action === "command.stored") f.grant.providerInstanceIds = [];
  };
  delete f.grant.codexExceptions;
  assert.equal(
    (await f.commands.continue("eddie", { ...f.p, request_id: randomUUID() })).submission,
    "rejected",
  );
  assert.equal(f.writes.length, 2);
});

test("ordinary Codex host enrollment still refuses expired grants, unknown drivers and missing provider enrollment", async (t) => {
  const f = codexFixture(t);
  f.grant.providerInstanceIds = ["codex"];
  delete f.grant.codexExceptions;
  for (const driver of ["chatgpt", "unknown", undefined]) {
    f.projection.providerThreads[0].driver = driver;
    await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
  }
  f.projection.providerThreads[0].driver = "codex";
  f.grant.providerInstanceIds = [];
  await assert.rejects(f.commands.continue("eddie", f.p), /provider_not_authorized/);
  f.grant.providerInstanceIds = ["codex"];
  f.advance(60001);
  await assert.rejects(f.commands.continue("eddie", f.p), /forbidden/);
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});

test("bound receipt reconciles historical completion after the user-message association disappears", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const stored = f.store.get("command", f.p.request_id);
  stored.runId = "delivered";
  stored.runStatus = "running";
  f.store.put("command", stored.request_id, stored);
  f.projection.runs = [{ id: "delivered", status: "completed" }];
  f.projection.messages = [{ runId: "delivered", role: "assistant", text: "done" }];
  const r = await f.commands.receipt("eddie", { request_id: stored.request_id });
  assert.equal(r.completed, true);
  assert.equal(r.run_status_fresh, true);
  assert.equal(r.run_id, "delivered");
  assert.equal(r.result, "done");
  assert.equal(r.agent_acknowledged, false);
  assert.equal(r.native_message_status, "not_in_projection");
  assert.equal(f.writes.length, 1);
  f.projection.runs = [{ id: "delivered", status: "running" }];
  const stale = await f.commands.receipt("eddie", { request_id: stored.request_id });
  assert.equal(stale.completed, true);
  assert.equal(stale.run_status_fresh, false);
  assert.equal(stale.source_status, "regressive_projection");
});

test("missing historical run reports unknown freshness instead of repeating cached running or selecting latest", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const stored = f.store.get("command", f.p.request_id);
  stored.runId = "old";
  stored.runStatus = "running";
  f.store.put("command", stored.request_id, stored);
  f.projection.runs = [{ id: "unrelated-latest", status: "completed" }];
  let r = await f.commands.receipt("eddie", { request_id: stored.request_id });
  assert.equal(r.run_id, "old");
  assert.equal(r.run_status, null);
  assert.equal(r.last_observed_run_status, "running");
  assert.equal(r.run_status_fresh, false);
  assert.equal(r.completed, false);
  assert.equal(r.safe_to_resend, false);
  assert.equal(r.submission, "accepted");
  let reads = 0;
  f.reader.withHost = async (_o, _h, _p, fn) =>
    fn({
      base: "http://127.0.0.1:3773",
      readThread: async (args) => {
        reads++;
        assert.equal(args.runLimit, 50);
        assert.equal(args.limit, 1);
        return {
          thread: { threadId: "t", projectId: "p" },
          recentRuns: [{ runId: "old", status: "completed" }],
        };
      },
    });
  r = await f.commands.receipt("eddie", { request_id: stored.request_id });
  assert.equal(reads, 1);
  assert.equal(r.source_status, "bounded_run_history");
  assert.equal(r.completed, true);
  assert.equal(r.result, null);
  assert.equal(r.result_status, "not_in_projection");
  assert.equal(f.writes.length, 1);
});

test("receipt rejects conflicting native run bindings without dispatch or acknowledgement", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const stored = f.store.get("command", f.p.request_id);
  stored.runId = "old";
  f.store.put("command", stored.request_id, stored);
  f.projection.runs = [{ id: "wrong", userMessageId: stored.messageId, status: "completed" }];
  await assert.rejects(
    f.commands.receipt("eddie", { request_id: stored.request_id }),
    /identity_mismatch/,
  );
  assert.equal(f.writes.length, 1);
  assert.equal(f.store.get("command", stored.request_id).ackAt, undefined);
});

test("inbox protocol refresh never revives an expired command grant", async (t) => {
  const f = fixture(t);
  f.policy.principals[0].eddieInbox = true;
  f.policy.callbackHosts = ["callbacks.example.com"];
  const b = new Bridge({
    store: f.store,
    policy: () => f.policy,
    backend: {},
    now: () => f.grant.expiresAt + 1,
    post: async (_u, _h, body) => ({
      status: 200,
      body: JSON.stringify({ challenge: JSON.parse(body).challenge }),
    }),
  });
  const expiry = f.grant.expiresAt;
  await b.subscribe("eddie", {
    name: "t3.eddie.requested",
    arguments: { inbox_id: "eddie" },
    delivery: {
      mode: "webhook",
      url: "https://callbacks.example.com/event",
      secret: "whsec_" + randomBytes(32).toString("base64"),
    },
  });
  f.advance(60001);
  assert.throws(() => f.commands.grant("eddie", "local"), /forbidden/);
  assert.equal(f.grant.expiresAt, expiry);
  assert.equal(f.writes.length, 0);
});

test("bounded receipt read cannot erase a concurrent caller acknowledgement", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "running";
  f.store.put("command", r.request_id, r);
  f.projection.runs = [];
  f.reader.withHost = async (_o, _h, _p, fn) =>
    fn({
      base: "http://127.0.0.1:3773",
      readThread: async () => {
        const other = f.store.get("command", r.request_id);
        other.ackAt = Date.now();
        other.ackCaller = "existing-caller";
        f.store.put("command", r.request_id, other);
        return {
          thread: { threadId: "t", projectId: "p" },
          recentRuns: [{ runId: "old", status: "completed" }],
        };
      },
    });
  const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.agent_acknowledged, true);
  assert.equal(receipt.completed, true);
  assert.equal(f.writes.length, 1);
});

test("source outage preserves owned durable acceptance while refusing to call cached running fresh", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "running";
  f.store.put("command", r.request_id, r);
  f.hook(() => {
    throw Object.assign(new Error("PRIVATE credentials"), { reason: "native_auth_unavailable" });
  });
  const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.stored, true);
  assert.equal(receipt.submission, "accepted");
  assert.equal(receipt.run_status, null);
  assert.equal(receipt.source_status, "unavailable");
  assert.equal(receipt.source_error, "native_auth_unavailable");
  assert.equal(receipt.run_status_fresh, false);
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(JSON.stringify(receipt).includes("PRIVATE"), false);
  assert.equal(f.writes.length, 1);
  f.grant.expiresAt = 0;
  await assert.rejects(f.commands.receipt("eddie", { request_id: r.request_id }), /forbidden/);
});

test("bounded receipt read cannot overwrite concurrent terminal evidence with running", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "running";
  f.store.put("command", r.request_id, r);
  f.projection.runs = [];
  f.reader.withHost = async (_o, _h, _p, fn) =>
    fn({
      base: "http://127.0.0.1:3773",
      readThread: async () => {
        const other = f.store.get("command", r.request_id);
        other.runStatus = "completed";
        other.result = "confirmed";
        f.store.put("command", r.request_id, other);
        return {
          thread: { threadId: "t", projectId: "p" },
          recentRuns: [{ runId: "old", status: "running" }],
        };
      },
    });
  const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.completed, true);
  assert.equal(receipt.run_status_fresh, false);
  assert.equal(receipt.result, "confirmed");
  assert.equal(f.store.get("command", r.request_id).runStatus, "completed");
  assert.equal(f.writes.length, 1);
});

test("concurrent contradictory terminal receipt evidence is preserved and not labelled a fresh projection", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "running";
  f.store.put("command", r.request_id, r);
  f.projection.runs = [];
  f.reader.withHost = async (_o, _h, _p, fn) =>
    fn({
      base: "http://127.0.0.1:3773",
      readThread: async () => {
        const other = f.store.get("command", r.request_id);
        other.runStatus = "failed";
        other.result = "newer failure evidence";
        f.store.put("command", r.request_id, other);
        return {
          thread: { threadId: "t", projectId: "p" },
          recentRuns: [{ runId: "old", status: "completed" }],
        };
      },
    });
  const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.run_status, "failed");
  assert.equal(receipt.completed, false);
  assert.equal(receipt.terminal, true);
  assert.equal(receipt.run_status_fresh, false);
  assert.equal(receipt.source_status, "concurrent_terminal_observation");
  assert.equal(receipt.result, "newer failure evidence");
  assert.equal(f.store.get("command", r.request_id).runStatus, "failed");
  assert.equal(f.writes.length, 1);
});

test("a new sequential native terminal correction is observed rather than hidden as a concurrent write", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "completed";
  f.store.put("command", r.request_id, r);
  f.projection.runs = [{ id: "old", status: "rolled_back" }];
  const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.run_status, "rolled_back");
  assert.equal(receipt.run_status_fresh, true);
  assert.equal(receipt.completed, false);
  assert.equal(f.writes.length, 1);
});

test("same-status concurrent observations retain newer evidence across either native await, even with identical content", async (t) => {
  for (const phase of ["projection", "history"])
    for (const changedResult of [true, false]) {
      const f = fixture(t);
      await f.commands.continue("eddie", f.p);
      const r = f.store.get("command", f.p.request_id);
      r.runId = "old";
      r.runStatus = "completed";
      r.result = "original";
      f.store.put("command", r.request_id, r);
      const concurrent = () => {
        const other = f.store.get("command", r.request_id);
        other.runStatus = "completed";
        other.result = changedResult ? "newer result" : "original";
        other.observationRevision = 1;
        f.store.put("command", r.request_id, other);
      };
      if (phase === "projection") {
        f.projection.runs = [{ id: "old", status: "failed" }];
        f.hook(concurrent);
      } else {
        f.projection.runs = [];
        f.reader.withHost = async (_o, _h, _p, fn) =>
          fn({
            base: "http://127.0.0.1:3773",
            readThread: async () => {
              concurrent();
              return {
                thread: { threadId: "t", projectId: "p" },
                recentRuns: [{ runId: "old", status: "failed" }],
              };
            },
          });
      }
      const receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
      assert.equal(receipt.run_status, "completed");
      assert.equal(receipt.result, changedResult ? "newer result" : "original");
      assert.equal(receipt.run_status_fresh, false);
      assert.equal(receipt.result_fresh, false);
      assert.equal(receipt.observation_revision, 1);
      assert.equal(f.store.get("command", r.request_id).runStatus, "completed");
      assert.equal(f.writes.length, 1);
    }
});

test("result availability survives a sequential status correction without claiming fresh assistant output", async (t) => {
  const f = fixture(t);
  await f.commands.continue("eddie", f.p);
  const r = f.store.get("command", f.p.request_id);
  r.runId = "old";
  r.runStatus = "completed";
  r.result = "old assistant output";
  f.store.put("command", r.request_id, r);
  f.projection.runs = [{ id: "old", status: "rolled_back" }];
  let receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.run_status_fresh, true);
  assert.equal(receipt.run_status, "rolled_back");
  assert.equal(receipt.result_status, "available");
  assert.equal(receipt.result_fresh, false);
  assert.equal(receipt.result_observed_at, null);
  assert.equal(receipt.observation_revision, 1);
  f.projection.messages = [{ runId: "old", role: "assistant", text: "observed assistant output" }];
  receipt = await f.commands.receipt("eddie", { request_id: r.request_id });
  assert.equal(receipt.result_fresh, true);
  assert.ok(receipt.result_observed_at);
  assert.equal(receipt.observation_revision, 2);
  assert.equal(f.writes.length, 1);
});

test("receipt observation preserves late durable acceptance and native sequence without redispatch", async (t) => {
  const f = fixture(t);
  f.error("native_outcome_unknown");
  await f.commands.continue("eddie", f.p);
  f.projection.runs = [];
  f.hook(() => {
    const other = f.store.get("command", f.p.request_id);
    other.submission = "accepted";
    other.sequence = 42;
    f.store.put("command", f.p.request_id, other);
  });
  const receipt = await f.commands.receipt("eddie", { request_id: f.p.request_id });
  assert.equal(receipt.submission, "accepted");
  assert.equal(receipt.sequence, 42);
  assert.equal(receipt.run_bound, false);
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(f.store.get("command", f.p.request_id).submission, "accepted");
  assert.equal(f.writes.length, 1);
});
