// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomBytes, createHash } from "node:crypto";
import { Bridge } from "../../../dist/bridge.mjs";
import { Store } from "../../../dist/store.mjs";
import { Commands } from "../../../dist/commands.mjs";
import { FleetReader } from "../../../dist/fleet-read.mjs";
import { configSchema } from "../../../dist/config.mjs";
import type { NativeRecord } from "../../../dist/contracts.mjs";
export function nativeFixture() {
  const now = Date.now(),
    key = randomBytes(32),
    store = new Store(":memory:", key);
  const policy = configSchema.parse({
    stateDirectory: "/fixture-unused",
    fleetHelperPath: "fixture-unused",
    callbackHosts: [],
    principals: [
      {
        id: "owner",
        tokenSha256: createHash("sha256").update("fixture-owner").digest("hex"),
        eddieInbox: true,
        sessions: ["verification"],
        readHosts: [{ host: "host", projectIds: ["project"] }],
        commandHosts: [
          {
            host: "host",
            projectIds: ["project"],
            providerInstanceIds: ["codex"],
            expiresAt: now + 600000,
            maxPerDay: 3,
            creationRuntime: {
              allowedModes: ["approval-required"],
              defaultMode: "approval-required",
              authorization: "synthetic-only",
            },
          },
        ],
      },
    ],
    sessions: [
      {
        id: "verification",
        host: "host",
        threadId: "verification-thread",
        observeAfter: new Date(now).toISOString(),
        followup: {
          action: "verify_result",
          dedicated: true,
          maxPerDay: 1,
          expiresAt: now + 600000,
          providerInstanceId: "opencode",
          model: "verification-model",
        },
      },
    ],
    fleetRead: { hosts: [{ name: "host" }] },
    nativeDelivery: { hosts: [{ name: "host", command: "never-executed-fixture" }] },
  });
  const selection = {
    instanceId: "codex",
    model: "model",
    options: [{ id: "serviceTier", value: "priority" }],
  };
  const projection: NativeRecord = {
    thread: { id: "thread", projectId: "project", modelSelection: selection },
    runs: [
      {
        id: "run",
        ordinal: 1,
        status: "completed",
        providerThreadId: "provider-thread",
        modelSelection: selection,
      },
    ],
    providerThreads: [{ id: "provider-thread", driver: "codex" }],
    nodes: [{ id: "node", runId: "run" }],
    runtimeRequests: [
      {
        id: "question",
        nodeId: "node",
        kind: "user_input",
        status: "pending",
        responseCapability: { type: "live" },
      },
    ],
    messages: [],
  };
  const config = {
    providers: [
      {
        instanceId: "codex",
        driver: "codex",
        enabled: true,
        installed: true,
        supportedRuntimeModes: ["approval-required"],
        models: [
          {
            slug: "model",
            capabilities: {
              optionDescriptors: [
                {
                  id: "serviceTier",
                  type: "select",
                  options: [{ id: "priority" }, { id: "default" }],
                },
              ],
            },
          },
        ],
      },
    ],
  };
  let effects = 0,
    reads = 0,
    offline = false;
  let dispatch: "forbid" | "accept" | "unknown" = "forbid";
  let afterRead = async () => {};
  const nativeClient = {
    base: "http://127.0.0.1:1",
    async listProjects() {
      reads++;
      return { projects: [{ id: "project", title: "Fixture" }], nextCursor: null };
    },
    async readThread() {
      reads++;
      return {
        thread: {
          threadId: "thread",
          projectId: "project",
          providerInstanceId: "codex",
          model: "model",
          activeRunId: "run",
        },
        items: [],
        recentRuns: [{ runId: "run", status: "completed" }],
        hasMore: false,
        nextPosition: null,
      };
    },
    async currentOptions() {
      reads++;
      return {
        threadId: "thread",
        modelSelection: selection,
        runtimeMode: "approval-required",
        interactionMode: "default",
      };
    },
    async providerOptions() {
      reads++;
      return {
        providers: [
          {
            providerInstanceId: "codex",
            driverKind: "codex",
            models: [
              {
                id: "model",
                options: [
                  { id: "serviceTier", values: ["default", "priority"], default: "default" },
                ],
              },
            ],
          },
        ],
      };
    },
    async configure() {
      effects++;
      throw Error("unexpected_native_write");
    },
  };
  const reader = new FleetReader({
    policy: () => policy,
    audit: (...args: Parameters<Store["audit"]>) => store.audit(...args),
    transport: () => ({
      async connect() {
        if (offline) throw Error("source_unavailable");
        return nativeClient;
      },
      async connectSettings() {
        if (offline) throw Error("source_unavailable");
        return nativeClient;
      },
      async close() {},
    }),
  });
  const commands = new Commands({
    policy: () => policy,
    store,
    reader,
    now: () => now,
    session: async (
      route: NativeRecord,
      fn: (
        call: (base: string, tag: string, input: object) => Promise<NativeRecord>,
      ) => Promise<unknown>,
    ) =>
      fn(async (_base, tag) => {
        if (offline) throw Error("source_unavailable");
        if (tag === "orchestration.dispatchCommand") {
          route.authorizeDispatch?.();
          effects++;
          if (dispatch === "accept") return { sequence: effects };
          throw Object.assign(
            Error(dispatch === "unknown" ? "native_outcome_unknown" : "unexpected_native_write"),
            { reason: "native_outcome_unknown" },
          );
        }
        if (route.readOnly !== true && dispatch === "forbid")
          throw Error("read_only_fixture_required");
        reads++;
        await afterRead();
        if (tag === "orchestration.getThreadProjection") return projection;
        if (tag === "server.getConfig") return config;
        throw Error("unsupported_native_read");
      }),
  });
  const backend = {
    supportsFollowup: true,
    async read() {
      return {
        thread: {
          threadId: "verification-thread",
          projectId: "project",
          latestRunId: "verification-run",
          activeRunId: null,
          providerInstanceId: "opencode",
          model: "verification-model",
          runtimeMode: "approval-required",
        },
        recentRuns: [{ runId: "verification-run", status: "completed" }],
        items: [],
      };
    },
    async followup() {
      effects++;
      throw Error("unexpected_native_write");
    },
    async close() {},
  };
  const bridge = new Bridge({
    policy: () => policy,
    store,
    backend,
    post: async () => {
      effects++;
      throw Error("unexpected_callback");
    },
    now: () => now,
  });
  bridge.commands = commands;
  bridge.fleetReads = reader;
  return {
    bridge,
    policy,
    store,
    commands,
    projection,
    now,
    key,
    effects: () => effects,
    reads: () => reads,
    offline(value: boolean) {
      offline = value;
    },
    onRead(fn: () => Promise<void>) {
      afterRead = fn;
    },
    dispatch(value: "forbid" | "accept" | "unknown") {
      dispatch = value;
    },
    async close() {
      await reader.close();
      store.close();
    },
  };
}
