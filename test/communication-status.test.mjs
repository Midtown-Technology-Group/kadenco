// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { communicationStatus } from "../src/communication-status.mjs";
function fixture() {
  const now = 100000,
    events = [],
    subscriptions = [
      {
        id: "lane",
        owner: "eddie",
        name: "t3.thread.activity",
        host: "local",
        threadId: "t",
        projectId: "p",
        active: true,
        expires: now - 1,
        url: "SECRET_URL",
        secret: "SECRET_KEY",
      },
      {
        id: "inbox",
        owner: "eddie",
        name: "t3.eddie.requested",
        inboxId: "eddie",
        active: true,
        expires: now + 1000,
      },
      {
        id: "other",
        owner: "other",
        name: "t3.thread.activity",
        host: "local",
        threadId: "t",
        projectId: "p",
        active: true,
        expires: now + 1000,
      },
    ];
  const policy = {
      principals: [
        {
          id: "eddie",
          commandHosts: [{ host: "local", providerInstanceIds: ["codex"], expiresAt: now + 1000 }],
        },
        {
          id: "caller",
          eddieHostCaller: { host: "local", reviewer: "eddie", expiresAt: now + 1000 },
        },
      ],
    },
    page = {
      host: "local",
      threads: [{ threadId: "t", projectId: "p", providerInstanceId: "codex" }],
      projects: [],
      next_cursor: "next",
      complete: false,
    };
  const b = {
    now: () => now,
    policy: () => policy,
    store: {
      all: (k) => {
        assert.equal(k, "subscription");
        return subscriptions;
      },
      audit: (...a) => events.push(a),
    },
    fleetReads: {
      inventory: async (owner, input) => {
        assert.equal(owner, "eddie");
        assert.equal(input.host, "local");
        return page;
      },
      grant: (owner, host, project) => {
        if (owner !== "eddie" || host !== "local" || (project && project !== "p"))
          throw Error("forbidden");
      },
    },
  };
  return { b, policy, page, subscriptions, events };
}
test("communication inventory preserves pagination and distinguishes expired lanes from passive availability and unverified proof", async () => {
  const f = fixture(),
    r = await communicationStatus(f.b, "eddie", { host: "local" }),
    c = r.threads[0].communication;
  assert.equal(r.next_cursor, "next");
  assert.equal(r.complete, false);
  assert.equal(c.event_lane, "expired");
  assert.equal(c.passive_host_binding, true);
  assert.equal(c.passive_inbox_active, true);
  assert.equal(c.command_scope_reason, null);
  assert.equal(c.native_preflight_required, true);
  assert.equal(c.round_trip, "not_verified");
  assert.equal(c.agent_tool_installation, "not_verified");
  assert.equal(c.subscriptions.length, 1);
  assert.doesNotMatch(JSON.stringify(r), /SECRET_|other/);
  assert.equal(r.communication.passive_replies_start_runs, false);
});

test("nonexpiring standing status is active with a null expiration rather than the Unix epoch", async () => {
  const f = fixture();
  f.subscriptions[0].expires = null;
  f.subscriptions[0].nonExpiring = true;
  f.subscriptions[1].expires = null;
  f.subscriptions[1].nonExpiring = true;
  const r = await communicationStatus(f.b, "eddie", { host: "local" });
  assert.equal(r.threads[0].communication.event_lane, "active");
  assert.equal(r.threads[0].communication.subscriptions[0].expires_at, null);
  assert.equal(r.threads[0].communication.passive_inbox_active, true);
  assert.equal(r.communication.active_subscriptions, 2);
});
test("scope restrictions and empty intermediate pages remain explicit without native commands or subscriptions", async () => {
  const f = fixture();
  f.page.threads[0].providerInstanceId = "codex-imported";
  let r = await communicationStatus(f.b, "eddie", { host: "local" });
  assert.equal(r.threads[0].communication.command_scope_reason, "provider_not_authorized");
  f.policy.principals[0].commandHosts[0].expiresAt = 1;
  r = await communicationStatus(f.b, "eddie", { host: "local" });
  assert.equal(r.threads[0].communication.command_scope_reason, "command_grant_expired");
  f.page.threads = [];
  r = await communicationStatus(f.b, "eddie", { host: "local", cursor: "next" });
  assert.equal(r.next_cursor, "next");
  assert.deepEqual(r.threads, []);
  assert.equal(f.subscriptions.length, 3);
  assert.equal(
    f.events.every((e) => e[0] === "communication.inventory"),
    true,
  );
});
test("post-inventory revocation and foreign-project pages fail closed", async () => {
  const f = fixture();
  f.b.fleetReads.inventory = async () => {
    f.policy.principals[0].enabled = false;
    return f.page;
  };
  await assert.rejects(communicationStatus(f.b, "eddie", { host: "local" }), /forbidden/);
  const g = fixture();
  g.page.threads[0].projectId = "private";
  await assert.rejects(communicationStatus(g.b, "eddie", { host: "local" }), /forbidden/);
});
