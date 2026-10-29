// SPDX-License-Identifier: AGPL-3.0-or-later
// Browser acceptance against the real HTTP/UI surface with synthetic identities
// and a recording native boundary. This is not production SSO/execution proof.
import { chromium } from "playwright-core";
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { resolve } from "node:path";
import assert from "node:assert/strict";
import { Store } from "../dist/store.mjs";
import { Collaboration } from "../dist/collaboration.mjs";
import { collaborationServer } from "../dist/collaboration-http.mjs";

if (!process.env.T3_TEST_BROWSER_PATH)
  throw Error("Set T3_TEST_BROWSER_PATH to an installed Chromium executable");
const output = resolve(process.env.T3_TEST_OUTPUT ?? "ui-proof");
mkdirSync(output, { recursive: true });
const store = new Store(":memory:", randomBytes(32)),
  writes = [],
  target = { host: "local", thread_id: "test-thread" };
const policy = {
  collaboration: {
    enabled: true,
    brokerPrincipal: "eddie",
    ownerSubjects: ["owner"],
    origin: "https://unset.test",
  },
  principals: [{ id: "eddie" }],
};
let releaseSlow,
  enterSlow,
  delaySlow = false;
const slowStarted = new Promise((resolve) => (enterSlow = resolve)),
  slowGate = new Promise((resolve) => (releaseSlow = resolve));
const reader = {
  grant(owner, host) {
    assert.equal(owner, "eddie");
    assert.equal(host, "local");
  },
  async read(owner, p) {
    this.grant(owner, p.host);
    if (delaySlow && p.thread_id === "slow-thread") {
      enterSlow();
      await slowGate;
    }
    return {
      thread: {
        threadId: p.thread_id,
        projectId: "p",
        title:
          p.thread_id === "test-thread"
            ? "Shared thread canary"
            : p.thread_id === "slow-thread"
              ? "Slow thread"
              : "Fast thread",
        model: "preserved-model",
        latestRunId: p.thread_id === "test-thread" ? "source-run" : "source-" + p.thread_id,
        status: writes.length ? "completed" : "idle",
      },
      items: [
        {
          itemId: "a",
          type: "assistant_message",
          text: writes.length
            ? "BROWSER_NONCE_OK"
            : "Ready for a harmless message. <img src=x onerror=alert(1)>",
          status: "completed",
        },
      ],
    };
  },
};
let submission = "accepted";
const commands = {
  async continue(owner, p, options) {
    options.authorize();
    writes.push(p);
    return { stored: true, submission, completed: false, agent_acknowledged: false };
  },
  async receipt() {
    return {
      stored: true,
      submission: "accepted",
      run_id: "exact-canary-run",
      run_status: "completed",
      terminal: true,
      completed: true,
      agent_acknowledged: false,
      result: "BROWSER_NONCE_OK",
      result_fresh: true,
      safe_to_resend: false,
    };
  },
};
const bridge = { policy: () => policy, store, fleetReads: reader, commands };
const service = new Collaboration({ policy: bridge.policy, store, reader, commands });
for (const subject of ["owner", "proposer", "sender", "viewer"])
  service.identity({ subject, email: subject + "@example.test" });
for (const [subject, capabilities] of [
  ["proposer", ["view", "propose", "review"]],
  ["sender", ["view", "propose", "send"]],
  ["viewer", ["view"]],
])
  await service.setGrant(
    { subject: "owner" },
    { ...target, subject, capabilities, expected_revision: 0, expires_at: Date.now() + 3600000 },
  );
for (const thread_id of ["slow-thread", "fast-thread"])
  await service.setGrant(
    { subject: "owner" },
    {
      host: "local",
      thread_id,
      subject: "owner",
      capabilities: ["view"],
      expected_revision: 0,
      expires_at: Date.now() + 3600000,
    },
  );
const server = collaborationServer(bridge, {
  authenticate: async (token) => ({
    subject: token,
    email: token + "@example.test",
    expiresAt: Date.now() + 60000,
  }),
  intervalMs: 100,
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = "http://127.0.0.1:" + server.address().port;
policy.collaboration.origin = base;
let browser;
const contexts = [];
const errors = [];
try {
  browser = await chromium.launch({
    executablePath: process.env.T3_TEST_BROWSER_PATH,
    headless: true,
  });
  const pageFor = async (subject, mobile = false) => {
    const context = await browser.newContext({
      extraHTTPHeaders: { "cf-access-jwt-assertion": subject },
      viewport: mobile ? { width: 390, height: 844 } : { width: 1280, height: 900 },
    });
    contexts.push(context);
    const page = await context.newPage();
    page.on("pageerror", (error) => errors.push(error.message));
    await page.goto(base + "/collaborate/#" + new URLSearchParams(target));
    await page.getByRole("heading", { name: "Shared thread canary", exact: true }).waitFor();
    return page;
  };
  const guestContext = await browser.newContext({
    extraHTTPHeaders: { "cf-access-jwt-assertion": "guest" },
  });
  contexts.push(guestContext);
  const guest = await guestContext.newPage();
  await guest.goto(base + "/collaborate/#" + new URLSearchParams(target));
  await guest.locator("#guest-access").waitFor();
  assert.equal(await guest.locator("#timeline").textContent(), "");
  assert.equal(await guest.locator("#compose").isVisible(), false);
  assert.match(await guest.locator("#guest-identity").textContent(), /guest@example.test/);
  assert.equal(service.list({ subject: "guest" }).length, 0);
  assert.equal(writes.length, 0);
  await service.setGrant(
    { subject: "owner" },
    {
      ...target,
      subject: "guest",
      capabilities: ["view"],
      expected_revision: 0,
      expires_at: Date.now() + 60000,
    },
  );
  await guest.getByRole("button", { name: "Check access again", exact: true }).click();
  await guest.getByRole("heading", { name: "Shared thread canary", exact: true }).waitFor();
  assert.equal(await guest.locator("#guest-access").isVisible(), false);
  assert.equal(await guest.locator("#compose").isVisible(), false);
  assert.equal(writes.length, 0);
  await service.setGrant(
    { subject: "owner" },
    {
      ...target,
      subject: "guest",
      capabilities: [],
      expected_revision: 1,
      expires_at: Date.now() + 60000,
    },
  );
  await guest.locator("#guest-access").waitFor();
  assert.equal(await guest.locator("#timeline").textContent(), "");
  assert.equal(await guest.locator("#title").textContent(), "Shared thread unavailable");
  assert.equal(await guest.locator("#disclosure").textContent(), "");
  const viewer = await pageFor("viewer", true);
  assert.equal(await viewer.locator("#compose").isVisible(), false);
  assert.equal(await viewer.locator("#access").isVisible(), false);
  assert.equal(await viewer.locator("#timeline img").count(), 0);
  await viewer.screenshot({ path: output + "/viewer-mobile.png", fullPage: true });
  const proposer = await pageFor("proposer");
  await proposer.getByLabel("Message", { exact: true }).fill("Reply BROWSER_NONCE_OK. No tools.");
  await proposer.getByRole("button", { name: "Propose message", exact: true }).click();
  await proposer.locator("#requests article").first().waitFor();
  assert.equal(writes.length, 0);
  assert.equal(
    await proposer.getByRole("button", { name: "Approve and send", exact: true }).count(),
    0,
  );
  const owner = await pageFor("owner");
  await owner.getByRole("button", { name: "Approve and send", exact: true }).click();
  await owner.getByRole("button", { name: "Check exact delivery receipt", exact: true }).waitFor();
  assert.equal(writes.length, 1);
  await owner.getByRole("button", { name: "Check exact delivery receipt", exact: true }).click();
  await owner.getByText("Execution: completed", { exact: true }).waitFor();
  await owner.screenshot({ path: output + "/owner-approved-completed.png", fullPage: true });
  const sender = await pageFor("sender");
  await sender.getByLabel("Message", { exact: true }).fill("Direct canary. No tools.");
  await sender.getByRole("button", { name: "Send to T3", exact: true }).click();
  await sender.getByRole("button", { name: "Check exact delivery receipt", exact: true }).waitFor();
  assert.equal(writes.length, 2);
  await sender.reload();
  await sender.getByRole("heading", { name: "Shared thread canary", exact: true }).waitFor();
  assert.equal(writes.length, 2);
  submission = "outcome_unknown";
  await sender.getByLabel("Message", { exact: true }).fill("Uncertain delivery probe");
  await sender.getByRole("button", { name: "Send to T3", exact: true }).click();
  await sender.locator("#requests").getByText("Unresolved delivery.", { exact: false }).waitFor();
  assert.equal(writes.length, 3);
  await sender.reload();
  await sender.getByRole("heading", { name: "Shared thread canary", exact: true }).waitFor();
  await sender.getByRole("button", { name: "Send to T3", exact: true }).click();
  await sender.locator("#requests").getByText("Unresolved delivery.", { exact: false }).waitFor();
  assert.equal(writes.length, 3);
  await owner.locator("#access summary").click();
  await owner.getByLabel("MTG user", { exact: true }).selectOption("sender");
  await owner.getByRole("button", { name: "Revoke access", exact: true }).click();
  await sender.getByText("access_revoked", { exact: true }).waitFor();
  assert.equal(await sender.locator("#compose").isVisible(), false);
  assert.equal(writes.length, 3);
  delaySlow = true;
  await owner.getByRole("link", { name: "local / slow-thread", exact: true }).click();
  await slowStarted;
  await owner.getByRole("link", { name: "local / fast-thread", exact: true }).click();
  await owner.getByRole("heading", { name: "Fast thread", exact: true }).waitFor({ timeout: 5000 });
  const oldResponse = owner.waitForResponse(
    (response) =>
      response.url().includes("/api/view?") && response.url().includes("thread_id=slow-thread"),
  );
  releaseSlow();
  await (await oldResponse).finished();
  await owner.getByRole("heading", { name: "Fast thread", exact: true }).waitFor({ timeout: 5000 });
  await owner.getByLabel("Message", { exact: true }).fill("Bound fast-thread message");
  await owner.getByRole("button", { name: "Send to T3", exact: true }).click();
  await owner.getByRole("button", { name: "Check exact delivery receipt", exact: true }).waitFor();
  assert.equal(writes.at(-1).thread_id, "fast-thread");
  assert.equal(writes.at(-1).source_run_id, "source-fast-thread");
  assert.equal(writes.length, 4);
  assert.deepEqual(errors, []);
  console.log(
    JSON.stringify({
      passed: true,
      source: "synthetic identities/native recording boundary",
      nativeWrites: writes.length,
      proposalBeforeApproval: 0,
      reloadReplay: 0,
      revocation: true,
      safeTextRendering: true,
      screenshots: output,
    }),
  );
} finally {
  releaseSlow();
  server.stopStreams();
  server.closeAllConnections();
  for (const context of contexts) await context.close();
  await browser?.close();
  await new Promise((resolve) => server.close(resolve));
  store.close();
}
