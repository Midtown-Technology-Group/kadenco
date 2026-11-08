// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { nativeFixture } from "./native-fixture.mts";
import { prepareOwnerEnrollment } from "../src/prepare-owner-enrollment.ts";
import { projectControlPolicy } from "../src/production-bootstrap.ts";
import type { ControlPolicy } from "../src/owner-enrollment.ts";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
test("offline preparation refuses grant and principal capacity overflow before returning a staged policy", async () => {
  const f = nativeFixture();
  try {
    const sponsor = f.policy.principals[0]!;
    sponsor.readHosts = Array.from({ length: 6 }, (_, i) => ({ host: i ? `host-${i}` : "host" }));
    sponsor.commandHosts = sponsor.readHosts.map(({ host }) => ({
      ...sponsor.commandHosts![0]!,
      host,
    }));
    f.policy.fleetRead!.hosts = sponsor.readHosts.map(({ host }) => ({ name: host }));
    f.policy.nativeDelivery!.hosts = sponsor.readHosts.map(({ host }) => ({
      name: host,
      command: "never-executed-fixture",
    }));
    const central: ControlPolicy = projectControlPolicy(f.policy, {
      fleet: "fixture",
      executor: "edge",
      executorToken: "synthetic-executor-credential-at-least-32",
      ownerTokens: new Map([["owner", "fixture-owner"]]),
      observationOwner: "owner",
      serviceExpiresAt: f.now + 300000,
      key: f.key,
      journalPath: "unused",
      origin: "https://fixture.invalid",
      epoch: 7,
    });
    const prepare = (policy = central, local = f.policy, id = "new-owner") =>
      prepareOwnerEnrollment({
        local,
        central: policy,
        sponsor: "owner",
        principal: id,
        tokenSha256: sha("synthetic-" + id),
        executor: "edge",
        expiresAt: f.now + 300000,
        requestId: randomUUID(),
      });
    const first = prepare(),
      second = prepare(first.central, first.local, "second");
    assert.equal(second.central.principals.find((p) => p.id === "edge")!.nativeGrants!.length, 36);
    const before = JSON.stringify(second);
    assert.throws(
      () => prepare(second.central, second.local, "third"),
      /owner_enrollment_capacity_exceeded/,
    );
    assert.equal(JSON.stringify(second), before);
    const filled = (count: number) => {
      const p = structuredClone(central),
        worker = p.principals.find((v) => v.id === "edge")!;
      while (worker.nativeGrants!.length < count)
        worker.nativeGrants!.push({
          ...worker.nativeGrants![0]!,
          grant: sha("extra-grant-" + worker.nativeGrants!.length),
        });
      return p;
    };
    assert.equal(
      prepare(filled(28)).central.principals.find((p) => p.id === "edge")!.nativeGrants!.length,
      40,
    );
    assert.throws(() => prepare(filled(29)), /owner_enrollment_capacity_exceeded/);
    const nearlyFull = structuredClone(central);
    while (nearlyFull.principals.length < 99)
      nearlyFull.principals.push({
        id: "extra-" + nearlyFull.principals.length,
        role: "owner",
        hosts: ["host"],
        expiresAt: f.now + 300000,
        tokenSha256: sha("extra-owner-" + nearlyFull.principals.length),
      });
    assert.equal(prepare(nearlyFull).central.principals.length, 100);
    nearlyFull.principals.push({
      id: "last",
      role: "owner",
      hosts: ["host"],
      expiresAt: f.now + 300000,
      tokenSha256: sha("last-owner"),
    });
    const fullBefore = JSON.stringify(nearlyFull);
    assert.throws(() => prepare(nearlyFull), /owner_enrollment_capacity_exceeded/);
    assert.equal(JSON.stringify(nearlyFull), fullBefore);
    assert.equal(f.effects(), 0);
  } finally {
    await f.close();
  }
});
test("offline parity preparation preserves six-host/all-project authority and never mutates its inputs", async () => {
  const f = nativeFixture();
  try {
    const source = f.policy.principals[0]!;
    source.readHosts = Array.from({ length: 6 }, (_, i) => ({ host: i ? `host-${i}` : "host" }));
    source.commandHosts = source.readHosts.map(({ host }) => ({
      ...source.commandHosts![0]!,
      host,
      projectIds: undefined,
    }));
    f.policy.fleetRead!.hosts = source.readHosts.map(({ host }) => ({ name: host }));
    f.policy.nativeDelivery!.hosts = source.readHosts.map(({ host }) => ({
      name: host,
      command: "never-executed-fixture",
    }));
    const central = projectControlPolicy(f.policy, {
      fleet: "fixture",
      executor: "edge",
      executorToken: "synthetic-executor-credential-at-least-32",
      ownerTokens: new Map([["owner", "fixture-owner"]]),
      observationOwner: "owner",
      serviceExpiresAt: f.now + 300000,
      key: f.key,
      journalPath: "unused",
      origin: "https://fixture.invalid",
      epoch: 7,
    });
    const before = JSON.stringify({ local: f.policy, central });
    const prepared = prepareOwnerEnrollment({
      local: f.policy,
      central,
      sponsor: "owner",
      principal: "grok",
      tokenSha256: sha("synthetic-grok"),
      executor: "edge",
      expiresAt: f.now + 300000,
      requestId: randomUUID(),
    });
    const grok = prepared.local.principals.find((p) => p.id === "grok")!;
    assert.deepEqual(grok.commandHosts, source.commandHosts);
    assert.deepEqual(grok.readHosts, source.readHosts);
    assert.equal(grok.eddieInbox, true);
    assert.equal(grok.readHosts!.length, 6);
    assert.equal(
      grok.commandHosts!.some((g) => g.projectIds !== undefined),
      false,
    );
    const target = prepared.central.principals.find((p) => p.id === "grok")!;
    assert.equal(target.nativeGrants!.length, 12);
    assert.equal(
      target.nativeGrants!.some(
        (g, i) => g.grant === central.principals[0]!.nativeGrants![i]!.grant,
      ),
      false,
    );
    assert.equal(JSON.stringify({ local: f.policy, central }), before);
    assert.equal(prepared.activation_permitted, false);
    assert.equal(f.effects(), 0);
    for (const change of [
      { principal: "owner" },
      { tokenSha256: source.tokenSha256 },
      { expiresAt: f.now + 400000 },
      { sponsor: "missing" },
    ])
      assert.throws(
        () =>
          prepareOwnerEnrollment({
            local: f.policy,
            central,
            sponsor: "owner",
            principal: "grok",
            tokenSha256: sha("synthetic-grok"),
            executor: "edge",
            expiresAt: f.now + 300000,
            requestId: randomUUID(),
            ...change,
          }),
        /preparation_forbidden/,
      );
  } finally {
    await f.close();
  }
});

test("Grok MCP uses the existing single central executor with independent receipts, uncertainty and revocation", async () => {
  const runtimeModule = (await import(
    new URL("../dist/edge-runtime.mjs", import.meta.url).href
  )) as typeof import("../src/edge-entry.ts");
  const f = nativeFixture(),
    dir = mkdtempSync(join(tmpdir(), "kadenco-parity-"));
  const config = {
    fleet: "fixture",
    origin: "https://fixture.invalid",
    epoch: 7,
    executor: "edge",
    executorToken: "synthetic-executor-credential-at-least-32",
    ownerTokens: new Map([["owner", "fixture-owner"]]),
    observationOwner: "owner",
    serviceExpiresAt: f.now + 300000,
    key: f.key,
    journalPath: join(dir, "attempts.db"),
  };
  const current = projectControlPolicy(f.policy, config),
    request = randomUUID();
  const prepared = runtimeModule.prepareOwnerEnrollment({
    local: f.policy,
    central: current,
    sponsor: "owner",
    principal: "grok",
    tokenSha256: sha("synthetic-grok"),
    executor: "edge",
    expiresAt: config.serviceExpiresAt,
    requestId: request,
  });
  f.policy.principals.push(prepared.local.principals.find((p) => p.id === "grok")!);
  config.ownerTokens.set("grok", "synthetic-grok");
  const inert = "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)";
  const worker = readFileSync(fileURLToPath(new URL("../dist/worker.js", import.meta.url)), "utf8");
  assert.equal(worker.split(inert).length, 2);
  // Seed existing policy in the fixture, while environment stages the approved
  // successor. This is not production activation or a live native provider.
  // Use supported Miniflare deployment updates to stage environment policy;
  // no source SQL substitution is needed for auth_policy.
  const options = (p: ControlPolicy) =>
    convertV4MiniflareOptions({
      modules: true,
      script: worker.replace(inert, "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)"),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: { AUTH_POLICY: JSON.stringify(p) },
    });
  const mf = new Miniflare(options(current));
  let runtime: Awaited<ReturnType<typeof runtimeModule.createProductionRuntime>> | undefined;
  const clients: Client[] = [];
  const fetchImpl: typeof fetch = async (url, init) =>
    (await mf.dispatchFetch(
      String(url),
      init as Parameters<typeof mf.dispatchFetch>[1],
    )) as unknown as Response;
  const call = async (op: string, body: object, token = "fixture-owner") => {
    const r = await fetchImpl("https://fixture.invalid/" + op, {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    return { status: r.status, body: (await r.json()) as any };
  };
  try {
    assert.equal((await call("status", {})).status, 200);
    await mf.setOptions(options(prepared.central));
    assert.equal((await call("status", {}, "synthetic-grok")).status, 403);
    const admitted = await call("enroll_configured_owner", prepared.admission);
    assert.equal(admitted.status, 200, JSON.stringify(admitted.body));
    assert.equal(admitted.body.committed, true);
    assert.deepEqual(
      (await call("owner_enrollment_receipt", { request_id: request })).body,
      admitted.body,
    );
    runtime = await runtimeModule.createProductionRuntime(f.bridge, {
      ...config,
      fetch: fetchImpl,
    });
    await new Promise<void>((resolve) => runtime!.mcp.listen(0, "127.0.0.1", resolve));
    const port = (runtime.mcp.address() as { port: number }).port;
    async function connect(token: string) {
      const c = new Client(
        { name: "synthetic-parity", version: "1" },
        { versionNegotiation: { mode: { pin: "2026-07-28" } } },
      );
      clients.push(c);
      await c.connect(
        new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
          requestInit: { headers: { authorization: "Bearer " + token } },
        }),
      );
      return c;
    }
    const grok = await connect("synthetic-grok"),
      eddie = await connect("fixture-owner");
    assert.ok((await grok.listTools()).tools.some((t) => t.name === "continue_thread"));
    assert.equal(
      (await grok.listTools()).tools.some((t) => /enrollment|enroll_configured/.test(t.name)),
      false,
    );
    assert.deepEqual(
      (await grok.listTools()).tools.map((t) => t.name).sort(),
      (await eddie.listTools()).tools.map((t) => t.name).sort(),
    );
    const value = (r: Awaited<ReturnType<Client["callTool"]>>) =>
      JSON.parse((r.content as { text: string }[])[0]!.text);
    const p = {
      host: "host",
      thread_id: "thread",
      source_run_id: "run",
      request_id: randomUUID(),
      message: "synthetic authorized work",
      execution: "allow_new_turn",
    };
    f.dispatch("accept");
    assert.equal(
      value(await grok.callTool({ name: "continue_thread", arguments: p })).native_submitted,
      true,
    );
    assert.equal(f.effects(), 1);
    await grok.callTool({ name: "continue_thread", arguments: p });
    assert.equal(f.effects(), 1);
    assert.equal(
      (await eddie.callTool({ name: "continue_thread", arguments: p })).isError,
      true,
      "different owner cannot adopt Grok's UUID",
    );
    f.dispatch("unknown");
    const uncertain = { ...p, request_id: randomUUID() };
    assert.equal(
      value(await grok.callTool({ name: "continue_thread", arguments: uncertain })).safe_to_resend,
      false,
    );
    await grok.callTool({ name: "continue_thread", arguments: uncertain });
    assert.equal(f.effects(), 2);
    const diagnostics = value(
      await grok.callTool({ name: "get_relay_request_diagnostics", arguments: { limit: 100 } }),
    );
    assert.ok(
      diagnostics.items.some((r: any) => r.principal_id === "grok" && r.operation === "reserve"),
    );
    assert.ok(
      diagnostics.items.some((r: any) => r.principal_id === "edge" && r.initiator_id === "grok"),
    );
    assert.equal(JSON.stringify(diagnostics).includes("synthetic-grok"), false);
    assert.equal((await call("revoke", { principal_id: "grok" })).status, 200);
    assert.equal(
      (
        await grok.callTool({
          name: "continue_thread",
          arguments: { ...p, request_id: randomUUID() },
        })
      ).isError,
      true,
    );
    assert.equal(f.effects(), 2);
    assert.equal(
      (await eddie.callTool({ name: "get_relay_request_diagnostics", arguments: {} })).isError,
      undefined,
    );
  } finally {
    for (const c of clients) await c.close();
    if (runtime?.mcp.listening)
      await new Promise<void>((resolve) => runtime!.mcp.close(() => resolve()));
    await runtime?.close();
    await mf.dispose();
    await f.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
