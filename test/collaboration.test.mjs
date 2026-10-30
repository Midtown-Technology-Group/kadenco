// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { Store } from "../dist/store.mjs";
import { Collaboration, grantArgs } from "../dist/collaboration.mjs";
import { accessIdentity, collaborationServer } from "../dist/collaboration-http.mjs";
import { generateKeyPair, SignJWT } from "jose";

function fixture(t) {
  let now = Date.now(),
    hook = async () => {},
    writeHook = async () => {},
    readScope = true;
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  const target = { host: "local", thread_id: "t" },
    writes = [],
    receipts = new Map();
  const policy = {
    collaboration: { enabled: true, brokerPrincipal: "eddie", ownerSubjects: ["owner"] },
    principals: [{ id: "eddie" }],
  };
  const reader = {
    grant(owner, host, project) {
      if (!readScope || owner !== "eddie" || host !== "local" || (project && project !== "p"))
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
    },
    async read(owner, p) {
      this.grant(owner, p.host);
      await hook();
      return {
        thread: {
          threadId: p.thread_id,
          projectId: "p",
          title: "Test",
          model: "unchanged",
          latestRunId: "exact-run",
          status: "completed",
        },
        items: [
          {
            type: "assistant_message",
            itemId: "a",
            text: "<script>never execute</script>",
            status: "completed",
          },
          { type: "command_execution", text: "SECRET COMMAND" },
          { type: "reasoning", text: "SECRET REASONING" },
        ],
      };
    },
  };
  const commands = {
    async continue(owner, p, { authorize }) {
      await writeHook();
      authorize();
      writes.push(p);
      const r = {
        stored: true,
        submission: "accepted",
        completed: false,
        agent_acknowledged: false,
        run_id: null,
      };
      receipts.set(p.request_id, r);
      return r;
    },
    async receipt(owner, p) {
      return receipts.get(p.request_id) ?? { stored: false, safe_to_resend: false };
    },
  };
  const service = new Collaboration({
    store,
    policy: () => policy,
    reader,
    commands,
    now: () => now,
  });
  const users = Object.fromEntries(
    ["owner", "viewer", "proposer", "sender", "reviewer", "outsider"].map((subject) => [
      subject,
      { subject, email: subject + "@example.test" },
    ]),
  );
  for (const u of Object.values(users)) service.identity(u);
  const grant = async (subject, capabilities) =>
    service.setGrant(users.owner, {
      ...target,
      subject,
      capabilities,
      expires_at: now + 60000,
      expected_revision:
        store.all("collaboration.grant").find((g) => g.subject === subject)?.revision ?? 0,
    });
  const message = (extra = {}) => ({
    ...target,
    request_id: randomUUID(),
    text: "Harmless nonce",
    intent: "propose",
    ...extra,
  });
  return {
    service,
    store,
    reader,
    commands,
    policy,
    users,
    target,
    writes,
    receipts,
    grant,
    message,
    advance: (ms) => (now += ms),
    hook: (f) => (hook = f),
    writeHook: (f) => (writeHook = f),
    revokeRead: () => (readScope = false),
  };
}

test("signed-in users get no thread rights by default; each capability is enforced independently", async (t) => {
  const f = fixture(t);
  await assert.rejects(f.service.view(f.users.outsider, f.target), /forbidden/);
  await f.grant("viewer", ["view"]);
  assert.equal((await f.service.view(f.users.viewer, f.target)).items.length, 1);
  await assert.rejects(f.service.propose(f.users.viewer, f.message()), /forbidden/);
  await f.grant("proposer", ["view", "propose"]);
  const p = await f.service.propose(f.users.proposer, f.message());
  assert.equal(p.state, "pending");
  assert.equal(f.writes.length, 0);
  await assert.rejects(
    f.service.propose(f.users.proposer, f.message({ intent: "send", source_run_id: "exact-run" })),
    /forbidden/,
  );
  await assert.rejects(
    f.service.decide(f.users.proposer, {
      ...f.target,
      message_id: p.message_id,
      action: "send",
      source_run_id: "exact-run",
    }),
    /forbidden/,
  );
  await assert.rejects(
    f.service.setGrant(f.users.proposer, {
      ...f.target,
      subject: "proposer",
      capabilities: ["view", "send", "propose"],
      expires_at: Date.now() + 10000,
      expected_revision: 1,
    }),
    /forbidden/,
  );
  await f.grant("reviewer", ["view", "review"]);
  await f.service.decide(f.users.reviewer, {
    ...f.target,
    message_id: p.message_id,
    action: "send",
    source_run_id: "exact-run",
  });
  assert.equal(f.writes.length, 1);
  assert.equal(f.writes[0].source_run_id, "exact-run");
  assert.match(f.writes[0].message, /approved by reviewer/);
  await assert.rejects(
    f.service.propose(f.users.reviewer, f.message({ intent: "send", source_run_id: "exact-run" })),
    /forbidden/,
  );
});

test("direct send has no owner approval, preserves source and one stable native command across concurrency/restart/replay", async (t) => {
  const f = fixture(t);
  await f.grant("sender", ["view", "propose", "send"]);
  const p = f.message({ intent: "send", source_run_id: "exact-run" });
  const results = await Promise.all([
    f.service.propose(f.users.sender, p),
    f.service.propose(f.users.sender, p),
  ]);
  assert.equal(f.writes.length, 1);
  assert.equal(results[0].message_id, results[1].message_id);
  assert.equal(f.writes[0].execution, "allow_new_turn");
  const resumed = new Collaboration({ ...f.service });
  await resumed.propose(f.users.sender, p);
  assert.equal(f.writes.length, 1);
  await assert.rejects(
    resumed.propose(f.users.sender, { ...p, text: "changed" }),
    /idempotency_conflict/,
  );
  f.receipts.set(f.writes[0].request_id, {
    stored: true,
    submission: "accepted",
    run_id: "bound-exact-run",
    run_status: "completed",
    completed: true,
    terminal: true,
    result: "NONCE_OK",
    agent_acknowledged: false,
  });
  const receipt = await resumed.receipt(f.users.sender, {
    ...f.target,
    message_id: results[0].message_id,
  });
  assert.equal(receipt.receipt.result, "NONCE_OK");
  assert.equal(receipt.receipt.agent_acknowledged, false);
  assert.equal(f.writes.length, 1);
});

test("concurrent approval and replay produce one command; dismissal never sends", async (t) => {
  const f = fixture(t);
  await f.grant("proposer", ["view", "propose"]);
  const p = await f.service.propose(f.users.proposer, f.message());
  const decision = {
    ...f.target,
    message_id: p.message_id,
    action: "send",
    source_run_id: "question-run",
  };
  await Promise.all([
    f.service.decide(f.users.owner, decision),
    f.service.decide(f.users.owner, decision),
  ]);
  assert.equal(f.writes.length, 1);
  const second = await f.service.propose(f.users.proposer, f.message());
  await f.grant("proposer", []);
  await f.service.decide(f.users.owner, {
    ...decision,
    message_id: second.message_id,
    action: "dismiss",
  });
  assert.equal(f.writes.length, 1);
});

test("review permission cannot self-approve a proposal without explicit send permission", async (t) => {
  const f = fixture(t);
  await f.grant("proposer", ["view", "propose", "review"]);
  const p = await f.service.propose(f.users.proposer, f.message());
  await assert.rejects(
    f.service.decide(f.users.proposer, {
      ...f.target,
      message_id: p.message_id,
      action: "send",
      source_run_id: "r",
    }),
    /forbidden/,
  );
  assert.equal(f.writes.length, 0);
  assert.equal(f.store.all("command").length, 0);
});

test("self-approval loses dispatch authority when send is revoked during native preflight", async (t) => {
  const f = fixture(t);
  await f.grant("proposer", ["view", "propose", "review", "send"]);
  const p = await f.service.propose(f.users.proposer, f.message());
  f.writeHook(async () => {
    await f.grant("proposer", ["view", "propose", "review"]);
  });
  const result = await f.service.decide(f.users.proposer, {
    ...f.target,
    message_id: p.message_id,
    action: "send",
    source_run_id: "r",
  });
  assert.equal(result.state, "not_submitted");
  assert.equal(f.writes.length, 0);
});

test("project movement refuses both new proposals and approval of an existing proposal", async (t) => {
  const f = fixture(t);
  await f.grant("proposer", ["view", "propose"]);
  await f.grant("sender", ["view", "propose", "send"]);
  const proposed = await f.service.propose(f.users.proposer, f.message()),
    read = f.reader.read.bind(f.reader);
  f.reader.read = async (...args) => {
    const result = await read(...args);
    result.thread.projectId = "moved-project";
    return result;
  };
  await assert.rejects(
    f.service.propose(f.users.sender, f.message({ intent: "send", source_run_id: "r" })),
    /identity_mismatch/,
  );
  assert.equal(f.writes.length, 0);
  f.commands.continue = async (owner, p, options) => {
    options.authorize({ projectId: "moved-project" });
    f.writes.push(p);
    return { submission: "accepted" };
  };
  const result = await f.service.decide(f.users.owner, {
    ...f.target,
    message_id: proposed.message_id,
    action: "send",
    source_run_id: "r",
  });
  assert.equal(result.state, "not_submitted");
  assert.equal(f.writes.length, 0);
});

test("revocation/expiry/off switch/read-scope removal deny reads and delivery; downgrade during native preflight prevents execution", async (t) => {
  const f = fixture(t);
  await f.grant("sender", ["view", "propose", "send"]);
  f.writeHook(async () => {
    await f.grant("sender", ["view", "propose"]);
  });
  const p = await f.service.propose(
    f.users.sender,
    f.message({ intent: "send", source_run_id: "r" }),
  );
  assert.equal(p.state, "not_submitted");
  assert.equal(f.writes.length, 0);
  await f.grant("viewer", ["view"]);
  f.advance(61000);
  await assert.rejects(f.service.view(f.users.viewer, f.target), /forbidden/);
  f.policy.collaboration.enabled = false;
  await assert.rejects(f.service.view(f.users.owner, f.target), /sharing_disabled/);
  f.policy.collaboration.enabled = true;
  f.revokeRead();
  await assert.rejects(f.service.view(f.users.owner, f.target), /forbidden/);
});

test("uncertain outcomes and crash-reserved messages are reconciled, never automatically dispatched again", async (t) => {
  const f = fixture(t);
  await f.grant("sender", ["view", "propose", "send"]);
  let attempts = 0;
  f.commands.continue = async () => {
    attempts++;
    throw Error("lost response");
  };
  const p = f.message({ intent: "send", source_run_id: "r" });
  await f.service.propose(f.users.sender, p);
  await f.service.propose(f.users.sender, p);
  assert.equal(attempts, 1);
  const row = f.store.all("collaboration.message")[0];
  row.state = "reserved";
  f.store.put("collaboration.message", row.id, row);
  const resumed = new Collaboration({ ...f.service });
  const result = await resumed.propose(f.users.sender, p);
  assert.equal(result.state, "reserved");
  assert.equal(attempts, 1);
  const receipt = await resumed.receipt(f.users.sender, { ...f.target, message_id: row.id });
  assert.equal(receipt.receipt.stored, false);
  assert.equal(receipt.safe_to_resend, false);
  assert.equal(attempts, 1);
});

test("grant updates require seen identities and expected revision; invalid/inherited grants and pending floods are denied", async (t) => {
  const f = fixture(t);
  await assert.rejects(f.grant("invented", ["view"]), /identity_not_seen/);
  const grant = await f.grant("viewer", ["view"]);
  await assert.rejects(
    f.service.setGrant(f.users.owner, {
      ...grant,
      project_id: undefined,
      changed_by: undefined,
      revision: undefined,
      expected_revision: 0,
    }),
    /Unrecognized|unrecognized/,
  );
  await assert.rejects(
    f.service.setGrant(f.users.owner, {
      ...f.target,
      subject: "viewer",
      capabilities: ["view"],
      expires_at: Date.now() + 10000,
      expected_revision: 0,
    }),
    /revision_conflict/,
  );
  assert.equal(
    grantArgs.safeParse({
      ...f.target,
      subject: "viewer",
      capabilities: ["send"],
      expected_revision: 1,
      expires_at: Date.now() + 10000,
    }).success,
    false,
  );
  await f.grant("proposer", ["view", "propose"]);
  for (let i = 0; i < 3; i++) await f.service.propose(f.users.proposer, f.message());
  await assert.rejects(f.service.propose(f.users.proposer, f.message()), /pending_limit/);
  await assert.rejects(
    f.service.view(f.users.viewer, { host: "remote", thread_id: "t" }),
    /forbidden/,
  );
  await assert.rejects(
    f.service.view(f.users.viewer, { host: "local", thread_id: "other" }),
    /forbidden/,
  );
});

test("MTG authentication validates issuer/audience/signature/expiry and exact Entra identity, rejecting service tokens and other IdPs", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256"),
    c = {
      issuer: "https://example.cloudflareaccess.com",
      audience: "app",
      identityProviderId: randomUUID(),
    };
  let identity = {
    user_uuid: "human",
    email: "human@example.test",
    idp: { id: c.identityProviderId, type: "azureAD" },
  };
  const authenticate = accessIdentity({
    keySet: async () => publicKey,
    fetchImpl: async () => new Response(JSON.stringify(identity)),
  });
  const sign = (payload = {}, aud = "app", exp = "5m") =>
    new SignJWT({ type: "app", email: "human@example.test", ...payload })
      .setProtectedHeader({ alg: "RS256" })
      .setIssuer(c.issuer)
      .setAudience(aud)
      .setSubject("human")
      .setExpirationTime(exp)
      .sign(privateKey);
  assert.equal((await authenticate(await sign(), c)).subject, "human");
  for (const token of [
    "forged",
    await sign({}, "other"),
    await sign({}, "app", 1),
    await sign({ common_name: "service" }),
    await sign({ type: "org" }),
  ])
    await assert.rejects(authenticate(token, c), /authentication_required/);
  for (const patch of [
    { user_uuid: "other" },
    { email: "spoofed@example.test" },
    { idp: { id: randomUUID(), type: "azureAD" } },
    { idp: { id: c.identityProviderId, type: "onetimepin" } },
    { service_token_status: true },
  ]) {
    const old = identity;
    identity = { ...identity, ...patch };
    await assert.rejects(authenticate(await sign(), c), /authentication_required/);
    identity = old;
  }
});

test("a late submit response cannot overwrite concurrent exact-run completion evidence", async (t) => {
  const f = fixture(t);
  await f.grant("sender", ["view", "propose", "send"]);
  let release, entered;
  const waiting = new Promise((resolve) => (entered = resolve)),
    gate = new Promise((resolve) => (release = resolve));
  f.commands.continue = async () => {
    entered();
    await gate;
    return { stored: true, submission: "accepted", run_id: null };
  };
  f.commands.receipt = async () => ({
    stored: true,
    submission: "accepted",
    run_id: "exact-run",
    run_status: "completed",
    completed: true,
    result: "DONE",
    result_fresh: true,
  });
  const sending = f.service.propose(
    f.users.sender,
    f.message({ intent: "send", source_run_id: "r" }),
  );
  await waiting;
  const record = f.store.all("collaboration.message")[0];
  await f.service.receipt(f.users.sender, { ...f.target, message_id: record.id });
  release();
  const response = await sending;
  assert.equal(response.receipt.run_id, "exact-run");
  assert.equal(response.receipt.result, "DONE");
  assert.equal(response.receipt.completed, true);
});

test("changing issuer/audience/IdP invalidates grants and receipts even for a matching subject/email", async (t) => {
  const f = fixture(t);
  await f.grant("proposer", ["view", "propose"]);
  const input = f.message(),
    old = await f.service.propose(f.users.proposer, input);
  const priorOwner = { ...f.users.owner, identity_scope: f.service.identityScope() };
  f.policy.collaboration.issuer = "https://other.cloudflareaccess.com";
  await assert.rejects(f.service.view(f.users.proposer, f.target), /forbidden/);
  assert.deepEqual(f.service.list(f.users.proposer), []);
  assert.equal(f.service.admin(priorOwner), false);
  await assert.rejects(
    f.service.setGrant(priorOwner, {
      ...f.target,
      subject: "proposer",
      capabilities: ["view"],
      expires_at: Date.now() + 10000,
      expected_revision: 0,
    }),
    /forbidden/,
  );
  await assert.rejects(
    f.service.setGrant(f.users.owner, {
      ...f.target,
      subject: "proposer",
      capabilities: ["view", "propose"],
      expires_at: Date.now() + 10000,
      expected_revision: 0,
    }),
    /identity_not_seen/,
  );
  f.service.identity(f.users.proposer);
  await f.service.setGrant(f.users.owner, {
    ...f.target,
    subject: "proposer",
    capabilities: ["view", "propose"],
    expires_at: Date.now() + 10000,
    expected_revision: 0,
  });
  await assert.rejects(
    f.service.receipt(f.users.proposer, { ...f.target, message_id: old.message_id }),
    /not_found/,
  );
  const next = await f.service.propose(f.users.proposer, input);
  assert.notEqual(next.message_id, old.message_id);
  assert.equal(f.service.messages(f.users.owner, f.target).length, 1);
});

test("HTTP rejects CSRF, oversized input and native endpoints; streams recheck grants without transmitting private source fields", async (t) => {
  const f = fixture(t);
  await f.grant("viewer", ["view"]);
  f.policy.collaboration.origin = "https://main.example.test";
  const server = collaborationServer(
    { policy: () => f.policy, store: f.store, fleetReads: f.reader, commands: f.commands },
    {
      authenticate: async () => ({ ...f.users.viewer, expiresAt: Date.now() + 60000 }),
      intervalMs: 10,
    },
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    server.stopStreams();
    server.closeAllConnections();
    server.close();
  });
  const base = "http://127.0.0.1:" + server.address().port;
  const csrf = await fetch(base + "/collaborate/api/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
  assert.equal(csrf.status, 403);
  assert.equal(f.writes.length, 0);
  const oversized = await fetch(base + "/collaborate/api/messages", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: f.policy.collaboration.origin,
      "x-t3-collaboration": "1",
    },
    body: JSON.stringify({ text: "x".repeat(17000) }),
  });
  assert.equal(oversized.status, 413);
  assert.equal(f.writes.length, 0);
  const native = await fetch(base + "/mcp");
  assert.equal(native.status, 404);
  const view = await (await fetch(base + "/collaborate/api/view?host=local&thread_id=t")).json();
  assert.equal(view.items.length, 1);
  assert.doesNotMatch(JSON.stringify(view), /SECRET/);
  const controller = new AbortController(),
    response = await fetch(base + "/collaborate/api/stream?host=local&thread_id=t", {
      signal: controller.signal,
    }),
    reader = response.body.getReader();
  assert.equal(response.headers.get("content-type"), "text/event-stream");
  const first = new TextDecoder().decode((await reader.read()).value);
  assert.match(first, /snapshot/);
  await f.grant("viewer", []);
  let ended = false,
    output = "";
  for (let i = 0; i < 5; i++) {
    const chunk = await reader.read();
    if (chunk.done) {
      ended = true;
      break;
    }
    output += new TextDecoder().decode(chunk.value);
  }
  assert.equal(ended, true);
  assert.match(output, /access_revoked/);
  controller.abort();
});

test("stream authentication resuming after stop cannot enroll a new stream or delay server close", async (t) => {
  const f = fixture(t);
  await f.grant("viewer", ["view"]);
  let entered, release;
  const authenticated = new Promise((resolve) => {
    entered = resolve;
  });
  const barrier = new Promise((resolve) => {
    release = resolve;
  });
  const server = collaborationServer(
    { policy: () => f.policy, store: f.store, fleetReads: f.reader, commands: f.commands },
    {
      authenticate: async () => {
        entered();
        await barrier;
        return { ...f.users.viewer, expiresAt: Date.now() + 60000 };
      },
      intervalMs: 10,
    },
  );
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    release();
    server.stopStreams();
    server.closeAllConnections();
    server.close();
  });
  const request = fetch(
    `http://127.0.0.1:${server.address().port}/collaborate/api/stream?host=local&thread_id=t`,
    { signal: AbortSignal.timeout(5000) },
  ).catch((error) => error);
  await authenticated;
  server.stopStreams();
  const closed = new Promise((resolve) => server.close(resolve));
  release();
  const result = await request;
  assert.ok(
    result instanceof TypeError,
    "shutdown must destroy the resumed response, not open SSE until the client deadline",
  );
  await closed;
  assert.equal(f.writes.length, 0);
});

test("owner creates an email-bound invite before sign-in; one claim grants only view/propose and dispatches nothing", async (t) => {
  const f = fixture(t),
    guest = { subject: "new-guest", email: "Doug@midtowntg.com" };
  const invite = {
    ...f.target,
    request_id: randomUUID(),
    email: "doug@midtowntg.com",
    expires_at: Date.now() + 600000,
  };
  const r = await f.service.invite(f.users.owner, invite);
  assert.equal(r.state, "pending");
  assert.deepEqual(await f.service.invite(f.users.owner, invite), r);
  await assert.rejects(
    f.service.claim(f.users.outsider, { ...f.target, invitation_id: r.id }),
    /invitation_unavailable/,
  );
  const claim = await f.service.claim(guest, { ...f.target, invitation_id: r.id });
  assert.deepEqual(claim.capabilities, ["view", "propose"]);
  assert.deepEqual(await f.service.claim(guest, { ...f.target, invitation_id: r.id }), claim);
  assert.equal(f.service.permissions(guest, f.target).capabilities.includes("send"), false);
  await f.service.propose(guest, f.message());
  assert.equal(f.writes.length, 0);
  assert.equal(f.service.messages(f.users.owner, f.target)[0].sender_email, guest.email);
  f.service.revokeInvitation(f.users.owner, { ...f.target, invitation_id: r.id });
  await assert.rejects(
    f.service.claim(guest, { ...f.target, invitation_id: r.id }),
    /invitation_unavailable/,
  );
  await assert.rejects(f.service.view(guest, f.target), /forbidden/);
});

test("invites reject nonowners, excess expiry, reused identity, foreign target, existing grant and expiry", async (t) => {
  const f = fixture(t),
    invite = {
      ...f.target,
      request_id: randomUUID(),
      email: f.users.outsider.email,
      expires_at: Date.now() + 600000,
    };
  await assert.rejects(f.service.invite(f.users.proposer, invite), /forbidden/);
  await assert.rejects(
    f.service.invite(f.users.owner, { ...invite, expires_at: Date.now() + 86400001 }),
    /invalid_expiry/,
  );
  const r = await f.service.invite(f.users.owner, invite),
    p = { ...f.target, invitation_id: r.id };
  await assert.rejects(
    f.service.claim(f.users.outsider, { ...p, thread_id: "foreign" }),
    /invitation_unavailable/,
  );
  await assert.rejects(
    f.service.invite(f.users.owner, { ...invite, email: "other@example.test" }),
    /idempotency_conflict/,
  );
  await f.grant("outsider", ["view"]);
  await assert.rejects(f.service.claim(f.users.outsider, p), /grant_already_exists/);
  f.advance(700000);
  await assert.rejects(f.service.claim(f.users.outsider, p), /invitation_unavailable/);
});

test("claim fences revocation during native read, duplicate subjects and later owner grant changes", async (t) => {
  const f = fixture(t),
    guest = { subject: "new", email: "guest@example.test" };
  const r = await f.service.invite(f.users.owner, {
    ...f.target,
    request_id: randomUUID(),
    email: guest.email,
    expires_at: Date.now() + 600000,
  });
  const p = { ...f.target, invitation_id: r.id };
  f.hook(async () => f.service.revokeInvitation(f.users.owner, p));
  await assert.rejects(f.service.claim(guest, p), /invitation_unavailable/);
  assert.equal(f.store.all("collaboration.grant").length, 0);
  f.hook(async () => {});
  const next = await f.service.invite(f.users.owner, {
    ...f.target,
    request_id: randomUUID(),
    email: guest.email,
    expires_at: Date.now() + 600000,
  });
  const q = { ...f.target, invitation_id: next.id };
  await Promise.all([f.service.claim(guest, q), f.service.claim(guest, q)]);
  await assert.rejects(
    f.service.claim({ ...guest, subject: "other" }, q),
    /invitation_unavailable/,
  );
  f.service.identity(guest);
  await f.service.setGrant(f.users.owner, {
    ...f.target,
    subject: guest.subject,
    capabilities: [],
    expected_revision: 1,
    expires_at: Date.now() + 600000,
  });
  await assert.rejects(f.service.claim(guest, q), /invitation_unavailable/);
  assert.equal(f.writes.length, 0);
});
