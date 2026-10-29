// SPDX-License-Identifier: AGPL-3.0-or-later
// Synthetic owner/guest identities, native read recording boundary, zero writes.
import { chromium } from "playwright-core";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdirSync } from "node:fs";
import { resolve, join } from "node:path";
import { Store } from "../dist/store.mjs";
import { Cadence } from "../dist/cadence.mjs";
import { collaborationServer } from "../dist/collaboration-http.mjs";

if (!process.env.T3_TEST_BROWSER_PATH)
  throw Error("Set T3_TEST_BROWSER_PATH to installed Chromium");
const store = new Store(":memory:", randomBytes(32)),
  now = Date.now();
let subject = "captain",
  nativeReads = 0,
  nativeWrites = 0;
const target = {
  host: "synthetic-host",
  project_id: "synthetic-project",
  thread_id: "synthetic-thread",
  run_id: "synthetic-run",
};
const policy = {
  sessions: [],
  principals: [{ id: "owner", readHosts: [{ host: target.host }] }],
  cadence: { freshForMs: 120000, noProgressMs: 900000, repetitionThreshold: 3 },
  collaboration: {
    enabled: true,
    brokerPrincipal: "owner",
    ownerSubjects: ["captain"],
    origin: "https://example.test",
    issuer: "https://synthetic.cloudflareaccess.com",
    audience: "synthetic",
    identityProviderId: "synthetic",
  },
};
const goal = {
  id: "goal",
  owner: "owner",
  title: "<img src=x onerror=window.CADENCE_XSS=true>",
  revision: 1,
  created_at: new Date(now - 60000).toISOString(),
  execution_owner: "agent",
  targets: [target],
  artifacts: [
    { id: "artifact", target: 0, uri: "https://example.test/artifact", revision: "candidate-head" },
  ],
  finish_criteria: [
    {
      id: "delivered",
      description: "Independent delivery proof",
      assertion: "activated",
      artifact_id: "artifact",
    },
  ],
  next_action: {
    owner: null,
    description: "Assign the next action owner",
    waiting_reason: null,
    decision_needed: true,
  },
  handoffs: [],
  verifications: [],
};
const snapshot = {
  thread: {
    threadId: target.thread_id,
    projectId: target.project_id,
    updatedAt: new Date(now).toISOString(),
  },
  runs: [{ runId: target.run_id, status: "running", startedAt: goal.created_at }],
  items: [],
};
const reader = {
  grant(owner, host, project) {
    if (owner !== "owner" || host !== target.host || (project && project !== target.project_id))
      throw Object.assign(Error("forbidden"), { reason: "forbidden" });
  },
  async read(owner, input) {
    this.grant(owner, input.host, target.project_id);
    assert.equal(input.thread_id, target.thread_id);
    nativeReads++;
    return structuredClone(snapshot);
  },
};
const cadence = new Cadence({
  policy: () => policy,
  store,
  reader,
  manifest: () => ({ version: 1, goals: [goal] }),
});
cadence.observe("owner", target, snapshot);
const forbidden = () => {
  nativeWrites++;
  throw Error("No native write authorized");
};
const server = collaborationServer(
  {
    policy: () => policy,
    store,
    fleetReads: reader,
    cadence,
    commands: { continue: forbidden, answer: forbidden, receipt: forbidden },
  },
  {
    authenticate: async () => ({
      subject,
      email: "synthetic@example.test",
      expiresAt: Date.now() + 60000,
    }),
  },
);
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const output = resolve(process.env.T3_TEST_OUTPUT ?? "ui-proof", "cadence");
mkdirSync(output, { recursive: true });
let browser;
try {
  browser = await chromium.launch({
    executablePath: process.env.T3_TEST_BROWSER_PATH,
    headless: true,
  });
  const context = await browser.newContext(),
    page = await context.newPage(),
    errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  const url = `http://127.0.0.1:${server.address().port}/collaborate/`;
  await page.goto(url);
  await page.getByRole("button", { name: "Read goal overview" }).click();
  await page.getByRole("heading", { name: goal.title + " · decision_needed" }).waitFor();
  assert.equal(await page.locator("#cadence-goals img").count(), 0);
  await page.getByRole("button", { name: "Read exact goal evidence" }).click();
  await page.locator("#cadence-goals pre").waitFor();
  const evidence = JSON.parse(await page.locator("#cadence-goals pre").textContent());
  assert.equal(evidence.unowned_next_step, true);
  assert.equal(evidence.last_meaningful_progress, null);
  assert.equal(evidence.targets[0].run_id, target.run_id);
  assert.equal(evidence.execution_authority, "none");
  assert.equal(await page.evaluate(() => window.CADENCE_XSS), undefined);
  await page.screenshot({ path: join(output, "owner-overview.png"), fullPage: true });
  await context.close();
  subject = "guest";
  const guest = await browser.newContext(),
    guestPage = await guest.newPage();
  await guestPage.goto(url);
  await guestPage.getByText("Signed in as synthetic@example.test").waitFor();
  assert.equal(await guestPage.locator("#cadence").isVisible(), false);
  assert.equal((await guest.request.get(url + "api/cadence")).status(), 403);
  await guest.close();
  assert.equal(nativeReads, 1);
  assert.equal(nativeWrites, 0);
  assert.deepEqual(errors, []);
  console.log(
    JSON.stringify({
      passed: true,
      source: "synthetic owner/guest and native read boundary",
      nativeReads,
      nativeWrites,
      ownerOnly: true,
      safeTextRendering: true,
      exactGoalBinding: true,
      screenshots: output,
    }),
  );
} finally {
  await browser?.close();
  server.stopStreams();
  server.closeAllConnections();
  await new Promise((r) => server.close(r));
  store.close();
}
