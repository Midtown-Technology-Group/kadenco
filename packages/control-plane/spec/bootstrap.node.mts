// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { nativeFixture } from "./native-fixture.mts";
import { existingBindings } from "../src/existing-bindings.ts";
import { eventTarget } from "../src/event-target.ts";
import { existingCallback } from "../src/edge-services.ts";
import { projectControlPolicy, projectVerificationPolicy } from "../src/production-bootstrap.ts";
import { cachePolicyGuard, startProductionSidecar } from "../src/production-startup.ts";
const hash = (x: unknown) => createHash("sha256").update(JSON.stringify(x)).digest("hex");

test("supported startup refuses historical cache aliases, key mismatch and inactive central service", async () => {
  const {
    mkdtempSync,
    mkdirSync,
    writeFileSync,
    readFileSync,
    rmSync,
    symlinkSync,
    linkSync,
    unlinkSync,
  } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const { randomBytes } = await import("node:crypto");
  const dir = mkdtempSync(join(tmpdir(), "kadenco-startup-"));
  const archive = join(dir, "archive"),
    cache = join(dir, "cache"),
    alias = join(dir, "alias");
  mkdirSync(archive, { mode: 0o700 });
  mkdirSync(cache, { mode: 0o700 });
  writeFileSync(join(archive, "historical.db"), "historical bytes untouched");
  const configPath = join(dir, "config.json"),
    key = randomBytes(32);
  const policy = {
    stateDirectory: cache,
    source: { type: "local-projection" as const, databasePath: "unused" },
    callbackHosts: [],
    sessions: [],
    principals: [
      {
        id: "owner",
        tokenSha256: createHash("sha256").update("fixture-owner").digest("hex"),
        sessions: [],
      },
    ],
  };
  writeFileSync(configPath, JSON.stringify(policy));
  let backends = 0,
    closed = 0,
    requests = 0;
  const input = {
    configPath,
    historicalStateDirectory: archive,
    cacheStateDirectory: cache,
    stateKey: key,
    bootstrap: {
      fleet: "fixture",
      origin: "https://fixture.invalid",
      epoch: 1,
      executor: "fixture-executor",
      executorToken: "test-only-executor-at-least-32-characters",
      ownerTokens: new Map([["owner", "fixture-owner"]]),
      observationOwner: "owner",
      serviceExpiresAt: Date.now() + 600000,
      key,
      journalPath: join(cache, "central-attempts.db"),
      fetch: async () => {
        requests++;
        return Response.json({ mode: "staging", epoch: 0 });
      },
    },
    backendFactory: () => {
      backends++;
      return {
        supportsFollowup: false,
        read: async () => {
          throw Error("unexpected_read");
        },
        followup: async () => {
          throw Error("unexpected_effect");
        },
        close: async () => {
          closed++;
        },
      };
    },
  };
  try {
    assert.throws(() => cachePolicyGuard(archive, archive), /historical_state_overlap/);
    symlinkSync(archive, alias, process.platform === "win32" ? "junction" : "dir");
    assert.throws(() => cachePolicyGuard(archive, alias), /historical_state_overlap/);
    const guard = cachePolicyGuard(archive, cache);
    guard(policy as any);
    assert.throws(
      () => guard({ ...policy, stateDirectory: archive } as any),
      /production_state_directory_changed/,
    );
    await assert.rejects(
      startProductionSidecar({ ...input, stateKey: randomBytes(32) }),
      /production_startup_configuration_required/,
    );
    await assert.rejects(
      startProductionSidecar({
        ...input,
        bootstrap: { ...input.bootstrap, journalPath: join(archive, "central-attempts.db") },
      }),
      /production_journal_directory_mismatch/,
    );
    writeFileSync(configPath, JSON.stringify({ ...policy, stateDirectory: archive }));
    await assert.rejects(startProductionSidecar(input), /production_state_directory_changed/);
    assert.equal(backends, 0, "validation precedes backend and writable Store construction");
    writeFileSync(configPath, JSON.stringify(policy));
    linkSync(join(archive, "historical.db"), join(cache, "bridge.db"));
    await assert.rejects(startProductionSidecar(input), /production_cache_file_alias/);
    assert.equal(backends, 0);
    unlinkSync(join(cache, "bridge.db"));
    await assert.rejects(startProductionSidecar(input), /central_activation_required/);
    assert.equal(backends, 1);
    assert.equal(closed, 1);
    assert.equal(requests, 1, "inactive startup is not retried or replaced with local delivery");
    assert.equal(
      readFileSync(join(archive, "historical.db"), "utf8"),
      "historical bytes untouched",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("original service bindings resolve exact context for all supported operations without a native effect", async () => {
  const f = nativeFixture(),
    b = existingBindings(f.bridge, {
      fleet: "fixture",
      observationOwner: "owner",
      serviceExpiresAt: f.now + 300000,
      now: () => f.now,
    });
  try {
    const continuation = {
      host: "host",
      thread_id: "thread",
      source_run_id: "run",
      request_id: randomUUID(),
      message: "fixture-only",
      execution: "allow_new_turn",
    };
    const c = await b.bind("continue", "owner", continuation);
    assert.equal(c.envelope.provider, "codex");
    assert.equal(c.envelope.project, "project");
    assert.equal(c.envelope.run, "run");
    const answer = await b.bind("answer", "owner", {
      host: "host",
      thread_id: "thread",
      request_id: randomUUID(),
      native_request_id: "question",
      answers: { q: "fixture" },
    });
    assert.equal(answer.envelope.run, "run");
    const creation = await b.bind("create", "owner", {
      host: "host",
      project_id: "project",
      provider_instance_id: "codex",
      request_id: randomUUID(),
      title: "fixture",
      message: "fixture",
      model: "model",
      options: [{ id: "serviceTier", value: "default" }],
      runtime_mode: "approval-required",
      execution: "allow_new_thread",
    });
    assert.match(creation.envelope.thread_id, /^[a-f0-9-]{36}$/);
    assert.equal(creation.envelope.run, null);
    const before = await f.commands.settings.read("owner", { host: "host", thread_id: "thread" });
    const settings = await b.bind("settings_standard", "owner", {
      host: "host",
      thread_id: "thread",
      request_id: randomUUID(),
      speed: "standard",
      expected_fingerprint: before.fingerprint,
    });
    assert.equal(settings.envelope.run, "run");
    const verification = await b.bind("verify_result", "owner", {
      session_id: "verification",
      run_id: "verification-run",
      request_id: randomUUID(),
      action: "verify_result",
    });
    assert.equal(verification.envelope.thread_id, "verification-thread");
    assert.equal(verification.envelope.provider, "opencode");
    assert.equal(f.effects(), 0);
    f.policy.principals[0].commandHosts![0].providerInstanceIds = ["opencode"];
    await assert.rejects(b.currentGrant(c.envelope), /forbidden/);
  } finally {
    await f.close();
  }
});

test("binding rejects live-question changes, cross-targets and revocation during native read", async () => {
  const f = nativeFixture(),
    b = existingBindings(f.bridge, {
      fleet: "fixture",
      observationOwner: "owner",
      serviceExpiresAt: f.now + 300000,
      now: () => f.now,
    });
  try {
    f.projection.runtimeRequests[0].responseCapability.type = "message";
    await assert.rejects(
      b.bind("answer", "owner", {
        host: "host",
        thread_id: "thread",
        request_id: randomUUID(),
        native_request_id: "question",
        answers: { q: "fixture" },
      }),
      /live_request_required/,
    );
    const p = {
      host: "host",
      thread_id: "thread",
      source_run_id: "run",
      request_id: randomUUID(),
      message: "fixture",
      execution: "allow_new_turn",
    };
    await assert.rejects(
      b.bind("continue", "owner", { ...p, thread_id: "another-thread" }),
      /identity_mismatch/,
    );
    f.onRead(async () => {
      f.policy.principals[0].enabled = false;
    });
    await assert.rejects(b.bind("continue", "owner", p), /forbidden/);
    assert.equal(f.effects(), 0);
  } finally {
    await f.close();
  }
});

test("duplicate owned reservations bind offline and preserve uncertain receipt without reexecution", async () => {
  const f = nativeFixture(),
    b = existingBindings(f.bridge, {
      fleet: "fixture",
      observationOwner: "owner",
      serviceExpiresAt: f.now + 300000,
      now: () => f.now,
    });
  try {
    const p = {
      host: "host",
      thread_id: "thread",
      source_run_id: "run",
      request_id: randomUUID(),
      message: "fixture",
      execution: "allow_new_turn",
    };
    f.store.put("command", p.request_id, {
      ...p,
      owner: "owner",
      kind: "continue",
      projectId: "project",
      sourceRunId: "run",
      digest: hash({ kind: "continue", ...p }),
      submission: "outcome_unknown",
      executionAuthorization: { providerInstanceId: "codex" },
    });
    f.offline(true);
    const bound = await b.bind("continue", "owner", p);
    assert.equal(bound.envelope.run, "run");
    await assert.rejects(
      b.bind("continue", "owner", { ...p, message: "changed" }),
      /idempotency_conflict/,
    );
    assert.equal(f.reads(), 0);
    assert.equal(f.effects(), 0);
  } finally {
    await f.close();
  }
});

test("task completion derives the original authorized session target and refuses cross-session data", async () => {
  const f = nativeFixture();
  try {
    const s = {
      id: "subscription",
      owner: "owner",
      sessionId: "verification",
      name: "t3.task.finished",
      active: true,
      expires: null,
      nonExpiring: true,
    };
    const event = {
      eventId: "event",
      name: s.name,
      data: { session_id: "verification", run_id: "verification-run" },
    };
    assert.deepEqual(eventTarget(f.bridge, s, event), {
      host: "host",
      thread: "verification-thread",
    });
    assert.throws(
      () => eventTarget(f.bridge, s, { ...event, data: { ...event.data, host: "another-host" } }),
      /identity_mismatch/,
    );
    f.store.put("subscription", s.id, s);
    const callback = existingCallback(f.bridge, async () => {
      f.store.put("subscription", s.id, { ...s, active: false });
    });
    await assert.rejects(
      callback(s.id, {
        data: event,
        scope: { owner: "owner", host: "host", thread: "verification-thread", name: s.name },
      }),
      /forbidden/,
    );
    f.store.put("subscription", s.id, s);
    let checkpointed = false;
    const rebound = existingCallback(
      f.bridge,
      async () => {
        checkpointed = true;
      },
      (_subscription, received, binding) => {
        assert.equal(checkpointed, true);
        assert.deepEqual(received, event);
        assert.deepEqual(binding, { grant: "stale" });
        throw Error("forbidden");
      },
    );
    await assert.rejects(
      rebound(s.id, {
        data: event,
        scope: {
          owner: "owner",
          host: "host",
          thread: "verification-thread",
          name: s.name,
          binding: { grant: "stale" },
        },
      }),
      /forbidden/,
    );
    assert.equal(checkpointed, true);
    assert.equal(f.effects(), 0);
  } finally {
    await f.close();
  }
});

test("control policy projection binds original credentials, separates executor and verifies dedicated scopes", async () => {
  const f = nativeFixture();
  const config = {
    fleet: "fixture",
    origin: "https://fixture.invalid",
    epoch: 7,
    executor: "fixture-edge",
    executorToken: "test-only-executor-credential-at-least-32-bytes",
    ownerTokens: new Map([["owner", "fixture-owner"]]),
    observationOwner: "owner",
    serviceExpiresAt: f.now + 300000,
    key: f.key,
    journalPath: "/fixture-attempts.db",
  };
  try {
    const projected = projectControlPolicy(f.policy, config);
    assert.equal(JSON.stringify(projected).includes("fixture-owner"), false);
    assert.equal(
      projected.principals.filter((p) => p.role === "owner").find((p) => p.id === "owner")
        ?.maxPerDay,
      3,
    );
    assert.equal(projected.principals.find((p) => p.id === "fixture-edge")?.role, "executor");
    assert.throws(
      () =>
        projectControlPolicy(f.policy, {
          ...config,
          ownerTokens: new Map([["owner", "another-caller"]]),
        }),
      /identity_mismatch/,
    );
    assert.throws(
      () => projectControlPolicy(f.policy, { ...config, executor: "owner" }),
      /identity_mismatch/,
    );
    const verified = await projectVerificationPolicy(f.bridge, config, [
      {
        owner: "owner",
        session_id: "verification",
        run_id: "verification-run",
        request_id: randomUUID(),
      },
    ]);
    assert.equal(
      verified.principals.find((p) => p.id === "owner")?.scopes[0].run,
      "verification-run",
    );
    await assert.rejects(
      projectVerificationPolicy(f.bridge, config, [
        {
          owner: "owner",
          session_id: "verification",
          run_id: "invented-run",
          request_id: randomUUID(),
        },
      ]),
      /followup_boundary_denied/,
    );
    assert.equal(f.effects(), 0);
  } finally {
    await f.close();
  }
});

test("compiled production composition routes official MCP through central reservation and exact original native service", async () => {
  const { Miniflare, convertV4MiniflareOptions } = await import("miniflare");
  const { readFileSync, mkdtempSync, rmSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { fileURLToPath } = await import("node:url");
  const { Client, StreamableHTTPClientTransport } = await import("@modelcontextprotocol/client");
  const runtimeModule = (await import(
    new URL("../dist/edge-runtime.mjs", import.meta.url).href
  )) as typeof import("../src/edge-entry.ts");
  const f = nativeFixture(),
    dir = mkdtempSync(join(tmpdir(), "kadenco-bootstrap-"));
  const config = {
    fleet: "fixture",
    origin: "https://fixture.invalid",
    epoch: 7,
    executor: "fixture-edge",
    executorToken: "test-only-executor-credential-at-least-32-bytes",
    ownerTokens: new Map([["owner", "fixture-owner"]]),
    observationOwner: "owner",
    serviceExpiresAt: f.now + 300000,
    key: f.key,
    journalPath: join(dir, "attempts.db"),
  };
  const policy = runtimeModule.projectControlPolicy(f.policy, config);
  const inert = "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)";
  const worker = readFileSync(fileURLToPath(new URL("../dist/worker.js", import.meta.url)), "utf8");
  assert.equal(worker.split(inert).length, 2);
  // Explicit test-only initial SQL; production activate remains independently gated.
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: worker.replace(inert, "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)"),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: { AUTH_POLICY: JSON.stringify(policy) },
    }),
  );
  let runtime: Awaited<ReturnType<typeof runtimeModule.createProductionRuntime>> | undefined;
  let client: InstanceType<typeof Client> | undefined;
  try {
    const fetchImpl: typeof fetch = async (url, init) =>
      (await mf.dispatchFetch(
        String(url),
        init as Parameters<typeof mf.dispatchFetch>[1],
      )) as unknown as Response;
    runtime = await runtimeModule.createProductionRuntime(f.bridge, {
      ...config,
      fetch: fetchImpl,
    });
    await new Promise<void>((resolve) => runtime!.mcp.listen(0, "127.0.0.1", resolve));
    const port = (runtime.mcp.address() as { port: number }).port;
    client = new Client(
      { name: "fixture-only", version: "1" },
      { versionNegotiation: { mode: { pin: "2026-07-28" } } },
    );
    await client.connect(
      new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${port}/mcp`), {
        requestInit: { headers: { authorization: "Bearer fixture-owner" } },
      }),
    );
    const p = {
      host: "host",
      thread_id: "thread",
      source_run_id: "run",
      request_id: randomUUID(),
      message: "synthetic boundary only",
      execution: "allow_new_turn",
    };
    const value = (r: Awaited<ReturnType<InstanceType<typeof Client>["callTool"]>>) =>
      JSON.parse((r.content as { text: string }[])[0].text);
    f.dispatch("accept");
    const accepted = value(await client.callTool({ name: "continue_thread", arguments: p }));
    assert.equal(accepted.native_submitted, true);
    assert.equal(accepted.completed, false);
    assert.equal(f.effects(), 1);
    assert.equal(
      value(await client.callTool({ name: "continue_thread", arguments: p })).native_submitted,
      true,
    );
    assert.equal(f.effects(), 1);
    f.dispatch("unknown");
    const uncertain = { ...p, request_id: randomUUID() };
    assert.equal(
      value(await client.callTool({ name: "continue_thread", arguments: uncertain }))
        .safe_to_resend,
      false,
    );
    await client.callTool({ name: "continue_thread", arguments: uncertain });
    assert.equal(f.effects(), 2, "uncertain retry only reconciles, never dispatches again");
    f.policy.principals[0].enabled = false;
    await assert.rejects(
      client.callTool({ name: "continue_thread", arguments: { ...p, request_id: randomUUID() } }),
      (error: unknown) => (error as { data?: { status?: number } }).data?.status === 401,
    );
    assert.equal(f.effects(), 2);
  } finally {
    await client?.close().catch(() => {});
    if (runtime?.mcp.listening)
      await new Promise<void>((resolve) => runtime!.mcp.close(() => resolve()));
    await runtime?.close();
    await f.close();
    await mf.dispose();
    rmSync(dir, { recursive: true, force: true });
  }
});
