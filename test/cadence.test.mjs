// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { Cadence, cadenceEventKey } from "../dist/cadence.mjs";
import { cadenceManifest, goalManifestFile } from "../dist/cadence-manifest.mjs";
import { Store } from "../dist/store.mjs";
import { Bridge } from "../dist/bridge.mjs";
import { httpServer } from "../dist/server.mjs";
import { collaborationServer } from "../dist/collaboration-http.mjs";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

const hash = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const stamp = (n) => new Date(n).toISOString();
function fixture(t) {
  let now = Date.parse("2026-10-29T17:00:00Z"),
    allowed = true,
    reads = 0,
    readHook = async () => {};
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  const target = {
    host: "host-a",
    project_id: "project-a",
    thread_id: "thread-a",
    run_id: "goal-run",
  };
  const token = "synthetic-" + randomUUID();
  const policy = {
    sessions: [],
    callbackHosts: [],
    cadence: {
      manifestPath: "unused",
      freshForMs: 120000,
      noProgressMs: 60000,
      repetitionThreshold: 3,
    },
    principals: [
      {
        id: "owner",
        sessions: [],
        tokenSha256: createHash("sha256").update(token).digest("hex"),
        readHosts: [{ host: target.host, projectIds: [target.project_id] }],
        commandHosts: [
          {
            host: target.host,
            projectIds: [target.project_id],
            providerInstanceIds: ["existing"],
            expiresAt: now + 86400000,
          },
        ],
      },
    ],
  };
  const goal = {
    id: "goal-a",
    owner: "owner",
    title: "Deliver the agreed outcome",
    revision: 1,
    created_at: stamp(now - 3600000),
    execution_owner: "agent-a",
    targets: [target],
    artifacts: [
      { id: "artifact", target: 0, uri: "https://example.test/pull/1", revision: "head-a" },
    ],
    finish_criteria: [
      {
        id: "delivered",
        description: "Independent delivery evidence",
        artifact_id: "artifact",
        assertion: "activated",
      },
    ],
    next_action: {
      owner: "agent-a",
      description: "Finish the accepted work",
      waiting_reason: null,
      decision_needed: false,
    },
    handoffs: [],
    verifications: [],
  };
  const manifest = { version: 1, goals: [goal] };
  const snapshot = {
    thread: {
      threadId: target.thread_id,
      projectId: target.project_id,
      updatedAt: stamp(now - 10000),
    },
    runs: [
      {
        runId: target.run_id,
        status: "running",
        requestedAt: goal.created_at,
        startedAt: stamp(now - 3500000),
      },
    ],
    items: [],
  };
  const reader = {
    grant(owner, host, project) {
      if (
        !allowed ||
        owner !== "owner" ||
        host !== target.host ||
        (project && project !== target.project_id)
      )
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
    },
    async read(owner, input) {
      this.grant(owner, input.host);
      reads++;
      await readHook();
      return structuredClone(snapshot);
    },
  };
  const cadence = new Cadence({
    policy: () => policy,
    store,
    reader,
    manifest: () => manifest,
    now: () => now,
  });
  store.put("subscription", "aggregate", {
    id: "aggregate",
    owner: "owner",
    name: "t3.fleet.activity",
    active: true,
    expires: null,
    nonExpiring: true,
  });
  store.put("subscription", "exact", {
    id: "exact",
    owner: "owner",
    name: "t3.thread.activity",
    active: true,
    expires: null,
    nonExpiring: true,
    host: target.host,
    projectId: target.project_id,
    threadId: target.thread_id,
  });
  function scan() {
    store.put("fleet_scan", hash(["aggregate", target.host]), {
      state: "available",
      lastCompleteAt: stamp(now),
      at: stamp(now),
      cursor: null,
    });
  }
  scan();
  const observe = () => cadence.observe("owner", target, structuredClone(snapshot));
  const view = () => cadence.project("owner", cadenceManifest.parse(manifest).goals[0]);
  function event(id, run, at, sub = "aggregate", kind = "task_finished", request) {
    store.put("delivery", id, {
      id,
      subId: sub,
      status: "acknowledged",
      event: {
        name: sub === "aggregate" ? "t3.fleet.activity" : "t3.thread.activity",
        timestamp: stamp(at),
        data: {
          ...target,
          run_id: run,
          kind,
          status: "completed",
          ...(request ? { native_request_id: request } : {}),
        },
      },
    });
  }
  return {
    store,
    target,
    goal,
    manifest,
    policy,
    snapshot,
    reader,
    cadence,
    token,
    observe,
    view,
    event,
    scan,
    now: () => now,
    advance: (n) => {
      now += n;
    },
    deny: () => {
      allowed = false;
    },
    allow: () => {
      allowed = true;
    },
    hook: (fn) => {
      readHook = fn;
    },
    reads: () => reads,
  };
}

test("native reads and unchanged scan/watch restarts do not reset meaningful progress or emit material changes", async (t) => {
  const f = fixture(t);
  f.observe();
  const first = f.view();
  assert.equal(first.phase, "running");
  assert.equal(first.last_meaningful_progress, null);
  const sequence = first.change_sequence;
  f.advance(5000);
  f.scan();
  await f.cadence.detail("owner", f.goal.id);
  const next = f.view();
  assert.equal(next.change_sequence, sequence);
  assert.equal(next.last_activity, first.last_activity);
  assert.equal(next.last_meaningful_progress, null);
  assert.equal(f.cadence.overview("owner", { after_change: sequence }).goals.length, 0);
});

test("aggregate/exact replays deduplicate by host/thread/run/kind/request, irrespective of delivery identity and arrival order", (t) => {
  const f = fixture(t);
  f.observe();
  f.event("later-arrived-first", "watcher-1", f.now() - 1000);
  f.event("earlier-arrived-later", "watcher-1", f.now() - 2000, "exact");
  f.event("question-a", "watcher-1", f.now() - 1000, "exact", "input_requested", "q-a");
  f.event("question-b", "watcher-1", f.now() - 1000, "aggregate", "input_requested", "q-b");
  const first = f.view();
  assert.equal(first.repetitive_activity_count, 3);
  f.event("replay-with-new-arrival", "watcher-1", f.now(), "exact");
  assert.equal(f.view().change_key, first.change_key);
  assert.equal(f.view().last_meaningful_progress, null);
  assert.notEqual(
    cadenceEventKey({ ...f.target, kind: "input_requested", native_request_id: "a" }),
    cadenceEventKey({ ...f.target, kind: "input_requested", native_request_id: "b" }),
  );
});

test("new watcher completions identify a no-progress loop but never nudge, send, or finish the goal", (t) => {
  const f = fixture(t);
  f.observe();
  for (let i = 0; i < 3; i++) f.event("watch-" + i, "watcher-" + i, f.now() - 3000 + i * 1000);
  const view = f.view();
  assert.equal(view.no_progress_loop, true);
  assert.equal(view.bucket, "blocked");
  assert.equal(view.phase, "running");
  assert.equal(view.last_meaningful_progress, null);
  assert.equal(view.automatic_nudges, false);
  assert.equal(view.execution_authority, "none");
  assert.equal(f.reads(), 0);
  assert.equal(f.store.all("command").length, 0);
});

test("concurrent and stale runs cannot complete another pinned goal run or invent progress", (t) => {
  const f = fixture(t);
  f.observe();
  f.snapshot.runs.push({
    runId: "unrelated-run",
    status: "completed",
    completedAt: stamp(f.now() - 500),
  });
  f.snapshot.thread.updatedAt = stamp(f.now());
  f.observe();
  assert.equal(f.view().phase, "running");
  assert.equal(f.view().last_meaningful_progress, null);
  f.snapshot.runs[0] = {
    runId: f.target.run_id,
    status: "completed",
    completedAt: stamp(Date.parse(f.goal.created_at) - 1),
  };
  f.advance(1);
  f.snapshot.thread.updatedAt = stamp(f.now());
  f.observe();
  const stale = f.view();
  assert.equal(stale.stale_completion, true);
  assert.notEqual(stale.phase, "completed");
  assert.notEqual(stale.phase, "independently_verified");
  assert.equal(stale.last_meaningful_progress, null);
});

test("out-of-order native projections cannot regress completion; contradictory same-version responses require reconciliation", (t) => {
  const f = fixture(t);
  f.snapshot.runs[0].status = "completed";
  f.snapshot.runs[0].completedAt = stamp(f.now() - 1000);
  f.observe();
  const first = f.view();
  f.snapshot.thread.updatedAt = stamp(f.now() - 20000);
  f.snapshot.runs[0].status = "running";
  f.observe();
  assert.equal(f.view().phase, "completed");
  f.snapshot.thread.updatedAt = stamp(f.now() - 10000);
  f.observe();
  const conflict = f.view();
  assert.equal(conflict.bucket, "visibility_gap");
  assert.equal(conflict.no_progress_assessable, false);
  f.snapshot.thread.updatedAt = stamp(f.now());
  f.snapshot.runs[0].status = "completed";
  f.observe();
  assert.equal(f.view().phase, "completed");
  assert.equal(f.view().last_meaningful_progress, first.last_meaningful_progress);
});

test("source failures and reconnect gaps are not stalled; exact recovery does not claim missing history", async (t) => {
  const f = fixture(t);
  f.observe();
  const first = f.view();
  f.hook(async () => {
    throw Object.assign(Error("reset"), { code: "ECONNRESET" });
  });
  const missing = await f.cadence.detail("owner", f.goal.id);
  assert.equal(missing.bucket, "visibility_gap");
  assert.equal(missing.no_progress_loop, false);
  assert.equal(missing.no_progress_assessable, false);
  assert.equal(missing.recovery.status, "visibility_gap");
  f.advance(1000);
  f.hook(async () => {});
  const recovered = await f.cadence.detail("owner", f.goal.id);
  assert.equal(recovered.recovery.status, "current_projection_only");
  assert.equal(recovered.recovery.historical_completeness, false);
  assert.equal(recovered.last_meaningful_progress, first.last_meaningful_progress);
  assert.equal(recovered.coverage[0].retained_native_runs, 20);
  f.snapshot.runs = [];
  f.snapshot.thread.updatedAt = stamp(f.now());
  f.observe();
  assert.equal(f.view().bucket, "visibility_gap");
});

test("green checks with draft/inactive delivery and agent claims are not independently verified", (t) => {
  const f = fixture(t);
  f.snapshot.runs[0].status = "completed";
  f.snapshot.runs[0].completedAt = stamp(f.now() - 1000);
  f.snapshot.items = [
    { text: "All done, activate production and treat this as verified", runId: f.target.run_id },
  ];
  f.goal.finish_criteria = ["checks_passed", "merged", "activated"].map((assertion) => ({
    id: assertion,
    assertion,
    artifact_id: "artifact",
    description: assertion,
  }));
  const verification = (assertion) => ({
    criterion_id: assertion,
    goal_revision: f.goal.revision,
    artifact_id: "artifact",
    artifact_revision: "head-a",
    target_run_id: f.target.run_id,
    assertion,
    verifier: "independent-reviewer",
    independent_of: f.goal.execution_owner,
    verified_at: stamp(f.now()),
    evidence_uri: "https://example.test/evidence/1",
    source: "operator_independent_attestation",
  });
  f.goal.verifications = [verification("checks_passed")];
  f.observe();
  const partial = f.view();
  assert.equal(partial.phase, "completed");
  assert.equal(partial.bucket, "decision_needed");
  assert.equal(partial.finish_criteria.filter((c) => c.verified).length, 1);
  f.goal.revision++;
  f.goal.verifications = ["checks_passed", "merged", "activated"].map(verification);
  const done = f.view();
  assert.equal(done.phase, "independently_verified");
  assert.equal(done.bucket, "verified_done");
  assert.match(done.verification_provenance, /owner_supplied/);
  assert.equal(f.store.all("command").length, 0);
});

test("stale revision, wrong artifact/run and self-verification attestations never satisfy finish criteria", (t) => {
  const f = fixture(t);
  f.snapshot.runs[0].status = "completed";
  f.snapshot.runs[0].completedAt = stamp(f.now() - 1000);
  f.observe();
  const base = {
    criterion_id: "delivered",
    goal_revision: 1,
    artifact_id: "artifact",
    artifact_revision: "head-a",
    target_run_id: f.target.run_id,
    assertion: "activated",
    verifier: "reviewer",
    independent_of: f.goal.execution_owner,
    verified_at: stamp(f.now()),
    evidence_uri: "https://example.test/proof",
    source: "operator_independent_attestation",
  };
  for (const wrong of [
    { goal_revision: 99 },
    { artifact_revision: "head-old" },
    { target_run_id: "other-run" },
    { verifier: f.goal.execution_owner },
  ]) {
    f.goal.revision++;
    f.goal.verifications = [{ ...base, goal_revision: f.goal.revision, ...wrong }];
    assert.equal(f.view().finish_criteria[0].verified, false);
  }
});

test("handoff ownership acceptance and acknowledgement are distinct from uncertain/native-accepted delivery", (t) => {
  const f = fixture(t),
    request = randomUUID();
  f.observe();
  f.goal.handoffs = [
    {
      id: "handoff",
      target: 0,
      request_id: request,
      from: "captain",
      to: "agent-b",
      proposed_at: stamp(f.now() - 10000),
    },
  ];
  f.store.put("command", request, {
    owner: "owner",
    host: f.target.host,
    projectId: f.target.project_id,
    thread_id: f.target.thread_id,
    sourceRunId: f.target.run_id,
    runId: "queued-run",
    commandId: "native-command",
    messageId: "native-message",
    submission: "outcome_unknown",
  });
  let handoff = f.view().handoffs[0];
  assert.equal(handoff.delivery, "uncertain");
  assert.equal(handoff.ownership, "proposed");
  assert.equal(handoff.safe_to_resend, false);
  const r = f.store.get("command", request);
  r.submission = "accepted";
  r.ackAt = f.now();
  f.store.put("command", request, r);
  handoff = f.view().handoffs[0];
  assert.equal(handoff.delivery, "native_submitted");
  assert.equal(handoff.ownership, "proposed");
  assert.equal(handoff.native_receipt_id, "native-command");
  f.goal.revision++;
  f.goal.handoffs[0].acceptance = { by: "agent-b", at: stamp(f.now()), source: "owner_record" };
  assert.equal(f.view().handoffs[0].ownership, "accepted");
  f.goal.revision++;
  f.goal.handoffs[0].acknowledgement = {
    by: "agent-b",
    at: stamp(f.now()),
    source: "owner_record",
  };
  assert.equal(f.view().handoffs[0].ownership, "acknowledged");
  assert.equal(f.store.all("command").length, 1);
});

test("expired monitoring grants stay visible without access expansion or false stall conclusions", (t) => {
  const f = fixture(t);
  f.observe();
  f.policy.principals[0].commandHosts[0].expiresAt = f.now() - 1;
  for (let i = 0; i < 3; i++) f.event("w" + i, "watcher" + i, f.now() - 1000);
  const subscriptions = f.store.all("subscription"),
    view = f.view();
  assert.equal(view.coverage[0].command_grant_expired, true);
  assert.equal(view.coverage[0].monitoring_active, false);
  assert.equal(view.no_progress_assessable, false);
  assert.equal(view.no_progress_loop, false);
  assert.deepEqual(f.store.all("subscription"), subscriptions);
  assert.equal(f.policy.principals[0].commandHosts[0].expiresAt, f.now() - 1);
});

test("unowned next actions require a decision and visibility expires without becoming a stalled goal", (t) => {
  const f = fixture(t);
  f.goal.next_action.owner = null;
  f.observe();
  assert.equal(f.view().bucket, "decision_needed");
  assert.equal(f.view().unowned_next_step, true);
  f.advance(121000);
  const invisible = f.view();
  assert.equal(invisible.bucket, "visibility_gap");
  assert.equal(invisible.no_progress_assessable, false);
});

test("read revocation, wrong project and manifest races fail closed", async (t) => {
  const f = fixture(t);
  f.observe();
  f.hook(async () => {
    f.deny();
  });
  await assert.rejects(f.cadence.detail("owner", f.goal.id), /forbidden/);
  assert.equal(f.cadence.overview("owner").goals.length, 0);
  f.allow();
  f.hook(async () => {});
  f.snapshot.thread.projectId = "other-project";
  await assert.rejects(f.cadence.detail("owner", f.goal.id), /identity_mismatch|forbidden/);
  f.snapshot.thread.projectId = f.target.project_id;
  f.hook(async () => {
    f.goal.revision++;
  });
  await assert.rejects(f.cadence.detail("owner", f.goal.id), /cadence_definition_changed/);
  f.policy.principals[0].enabled = false;
  assert.throws(() => f.cadence.overview("owner"), /forbidden/);
});

test("change-only overview pagination binds owner, definition and watermarks without repeated poll changes", (t) => {
  const f = fixture(t);
  f.manifest.goals.push({ ...structuredClone(f.goal), id: "goal-b" });
  f.observe();
  const first = f.cadence.overview("owner", { limit: 1 });
  assert.equal(first.goals.length, 1);
  assert.ok(first.next_cursor);
  const second = f.cadence.overview("owner", { limit: 1, cursor: first.next_cursor });
  assert.equal(second.goals[0].goal_id, "goal-b");
  assert.equal(second.next_cursor, null);
  assert.equal(
    f.cadence.overview("owner", { after_change: first.high_water_change }).goals.length,
    0,
  );
  assert.throws(
    () => f.cadence.overview("owner", { cursor: first.next_cursor + "tamper" }),
    /invalid_cadence_cursor/,
  );
  f.goal.revision++;
  f.goal.title = "Changed by owner";
  assert.throws(
    () => f.cadence.overview("owner", { cursor: first.next_cursor }),
    /invalid_cadence_cursor/,
  );
});

test("bounded manifest loader rejects malformed/oversized files without leaking paths and supports owned updates", (t) => {
  const f = fixture(t),
    directory = mkdtempSync(join(tmpdir(), "kadenco-goals-")),
    path = join(directory, "goals.json");
  try {
    writeFileSync(path, JSON.stringify(f.manifest), { mode: 0o600 });
    const load = goalManifestFile(path);
    assert.equal(load().goals[0].id, f.goal.id);
    writeFileSync(path, "null");
    assert.throws(load, (e) => e.message === "cadence_manifest_unavailable");
    writeFileSync(path, Buffer.alloc(1048577));
    assert.throws(load, /cadence_manifest_unavailable/);
    writeFileSync(path, JSON.stringify({ ...f.manifest, extra: "untrusted" }));
    assert.throws(load, /cadence_manifest_unavailable/);
    assert.equal(
      cadenceManifest.safeParse({
        ...f.manifest,
        goals: [
          {
            ...f.goal,
            artifacts: [{ ...f.goal.artifacts[0], uri: "https://example.test/proof?token=secret" }],
          },
        ],
      }).success,
      false,
    );
  } finally {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});

test("MCP exposes only read-only cadence overview/detail and keeps native commands/subscriptions unchanged", async (t) => {
  const f = fixture(t);
  f.observe();
  const bridge = new Bridge({
    store: f.store,
    backend: {
      supportsFollowup: false,
      read: async () => {
        throw Error("unused");
      },
      followup: async () => {
        throw Error("forbidden");
      },
      close() {},
    },
    policy: () => f.policy,
    post: async () => {
      throw Error("No callback delivery authorized");
    },
    now: f.now,
  });
  bridge.fleetReads = f.reader;
  bridge.cadence = f.cadence;
  const server = httpServer(bridge);
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const client = new Client(
    { name: "cadence-test", version: "1" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  const subscriptions = f.store.all("subscription");
  try {
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${server.address().port}/mcp`), {
        requestInit: { headers: { Authorization: "Bearer " + f.token } },
      }),
    );
    const tools = (await client.listTools()).tools.filter((tool) => tool.name.includes("cadence"));
    assert.equal(tools.length, 2);
    assert.ok(tools.every((tool) => tool.annotations.readOnlyHint));
    const overview = await client.callTool({ name: "get_cadence_overview", arguments: {} });
    assert.equal(overview.isError, undefined);
    assert.equal(overview.structuredContent.goals.length, 1);
    const detail = await client.callTool({
      name: "get_cadence_goal",
      arguments: { goal_id: f.goal.id },
    });
    assert.equal(detail.isError, undefined);
    assert.equal(detail.structuredContent.execution_authority, "none");
    assert.equal(f.store.all("command").length, 0);
    assert.deepEqual(f.store.all("subscription"), subscriptions);
    assert.equal(f.reads(), 1);
  } finally {
    await client.close();
    await new Promise((r) => server.close(r));
  }
});

test("existing UI cadence route is owner-only, and owner revocation during a native read denies the response", async (t) => {
  const f = fixture(t);
  f.policy.collaboration = {
    enabled: true,
    brokerPrincipal: "owner",
    ownerSubjects: ["captain"],
    origin: "https://example.test",
    issuer: "https://test.cloudflareaccess.com",
    audience: "test",
    identityProviderId: "synthetic",
  };
  const bridge = {
    policy: () => f.policy,
    store: f.store,
    fleetReads: f.reader,
    commands: {},
    cadence: f.cadence,
  };
  let subject = "guest";
  const server = collaborationServer(bridge, {
    authenticate: async () => ({
      subject,
      email: "synthetic@example.test",
      expiresAt: Date.now() + 60000,
    }),
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${server.address().port}/collaborate/api/`;
  try {
    assert.equal((await fetch(url + "cadence")).status, 403);
    subject = "captain";
    assert.equal((await fetch(url + "cadence")).status, 200);
    f.hook(async () => {
      f.policy.collaboration.ownerSubjects = [];
    });
    assert.equal((await fetch(url + "cadence-goal?goal_id=" + f.goal.id)).status, 403);
    assert.equal(f.store.all("command").length, 0);
  } finally {
    await new Promise((r) => server.close(r));
  }
});

test("event backlog age is diagnostic, unchanged retry clocks are not progress, and legacy observation lag stays unknown", (t) => {
  const f = fixture(t);
  f.observe();
  f.event("pending", "watcher", f.now() - 130000);
  const event = f.store.get("delivery", "pending");
  event.status = "pending";
  f.store.put("delivery", "pending", event);
  assert.equal(f.view().event_lag.max_recorded_observation_lag_ms, null);
  event.observedAt = f.now() - 60000;
  f.store.put("delivery", "pending", event);
  const first = f.view();
  assert.equal(first.event_lag.max_recorded_observation_lag_ms, 70000);
  assert.equal(first.event_lag.lagging, true);
  assert.equal(first.event_lag.pending_events, 1);
  f.advance(5000);
  f.observe();
  const next = f.view();
  assert.equal(next.change_key, first.change_key);
  assert.equal(next.event_lag.oldest_pending_age_ms, first.event_lag.oldest_pending_age_ms + 5000);
  assert.equal(next.last_meaningful_progress, null);
  event.status = "acknowledged";
  f.store.put("delivery", "pending", event);
  const acknowledged = f.view();
  assert.equal(acknowledged.event_lag.pending_events, 0);
  assert.equal(acknowledged.last_meaningful_progress, null);
  assert.equal(acknowledged.event_lag.delivery_acknowledgement_is_agent_execution, false);
});

test("truncated retained delivery windows disable loop conclusions and never claim historical completeness", (t) => {
  const f = fixture(t);
  f.observe();
  for (let i = 0; i < 2001; i++) f.event("retained-" + i, "watcher-" + i, f.now() - 1000);
  const view = f.view();
  assert.equal(view.event_window_truncated, true);
  assert.equal(view.no_progress_assessable, false);
  assert.equal(view.no_progress_loop, false);
  assert.equal(view.recovery.historical_completeness, false);
});

test("another owner's manifest changes do not alter the visible goal digest or leak goal records", (t) => {
  const f = fixture(t);
  f.observe();
  const first = f.cadence.overview("owner");
  f.manifest.goals.push({
    ...structuredClone(f.goal),
    owner: "other-owner",
    title: "Private other goal",
  });
  const next = f.cadence.overview("owner", { after_change: first.high_water_change });
  assert.equal(next.definition_key, first.definition_key);
  assert.equal(next.goals.length, 0);
  assert.equal(next.total_visible_goals, 1);
});

test("definition regression/conflict fails closed and overview decrypts each retained window only once", (t) => {
  const f = fixture(t);
  f.observe();
  f.view();
  f.goal.title = "Changed without a revision";
  assert.throws(() => f.view(), /cadence_definition_conflict/);
  f.goal.revision++;
  f.view();
  f.goal.revision--;
  assert.throws(() => f.view(), /cadence_definition_regressed/);
  f.goal.revision += 2;
  f.manifest.goals.push({ ...structuredClone(f.goal), id: "goal-b" });
  let windows = 0;
  const recent = f.store.recent.bind(f.store);
  f.store.recent = (...args) => {
    windows++;
    return recent(...args);
  };
  f.cadence.overview("owner");
  assert.equal(windows, 1);
});

test("even an explicitly linked watcher run is activity only and cannot verify or advance its work goal", (t) => {
  const f = fixture(t);
  f.goal.targets.push({ ...f.target, run_id: "bound-watcher", role: "watcher" });
  f.snapshot.runs.push({
    runId: "bound-watcher",
    status: "completed",
    completedAt: stamp(f.now() - 1000),
  });
  f.observe();
  const view = f.view();
  assert.equal(view.phase, "running");
  assert.equal(view.last_meaningful_progress, null);
  const invalid = structuredClone(f.manifest);
  invalid.goals[0].artifacts[0].target = 1;
  assert.equal(cadenceManifest.safeParse(invalid).success, false);
});

test("cancelled queued run with a message observed in another containing run never becomes safe to resend", (t) => {
  const f = fixture(t),
    request = randomUUID();
  f.observe();
  f.goal.handoffs = [
    {
      id: "queued",
      target: 0,
      request_id: request,
      from: "captain",
      to: "agent-b",
      proposed_at: stamp(f.now() - 10000),
    },
  ];
  f.store.put("command", request, {
    owner: "owner",
    host: f.target.host,
    projectId: f.target.project_id,
    thread_id: f.target.thread_id,
    sourceRunId: f.target.run_id,
    runId: "queued-run",
    runStatus: "cancelled",
    messageId: "exact-message",
    commandId: "exact-command",
    submission: "accepted",
    messageObservation: {
      message_id: "exact-message",
      run_id: f.target.run_id,
      run_status: "running",
      input_intent: "promoted_queued_to_steer",
      observed_at: stamp(f.now()),
    },
  });
  const h = f.view().handoffs[0];
  assert.equal(h.native_run_status, "cancelled");
  assert.equal(h.native_message_observation.run_id, f.target.run_id);
  assert.equal(h.ownership, "proposed");
  assert.equal(h.safe_to_resend, false);
  assert.equal(f.store.all("command").length, 1);
});

test("native record reordering is not a contradiction, long exact IDs are supported, and unknown status is not stalled", (t) => {
  const f = fixture(t);
  f.snapshot.runs.push({ runId: "other", status: "running", startedAt: f.goal.created_at });
  f.observe();
  const first = f.view();
  f.snapshot.runs.reverse();
  f.observe();
  assert.equal(f.view().change_key, first.change_key);
  const manifest = structuredClone(f.manifest);
  manifest.goals[0].targets[0].thread_id = "node:" + "x".repeat(400);
  assert.equal(cadenceManifest.safeParse(manifest).success, true);
  f.snapshot.runs.find((r) => r.runId === f.target.run_id).status = "unsupported-provider-status";
  f.snapshot.thread.updatedAt = stamp(f.now());
  f.observe();
  assert.equal(f.view().phase, "unknown");
  assert.equal(f.view().no_progress_assessable, false);
});
