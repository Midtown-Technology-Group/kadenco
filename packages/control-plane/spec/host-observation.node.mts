// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID, createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { randomBytes } from "node:crypto";
import { Store } from "../../../dist/store.mjs";
import { createHostLocalRuntime } from "../src/host-observation.ts";
import { hostLocalPolicyGuard, startHostLocalSidecar } from "../src/host-startup.ts";

test("actual Worker fences observation and callbacks by original host/process, including legacy bypass", async () => {
  const binding = {
    project: "project",
    provider: "codex",
    run: "source",
    grant: "grant",
    revision: 1,
    expires: 4102444700000,
  };
  const principals = [
    { id: "owner", role: "owner", hosts: ["a", "b", "c", "d", "e"] },
    ...["a", "b", "c", "d", "e"].map((host) => ({ id: host, role: "executor", hosts: [host] })),
  ].map((p) => ({
    ...p,
    scopes: [binding],
    expiresAt: 4102444800000,
    tokenSha256: createHash("sha256")
      .update("fixture-" + p.id)
      .digest("hex"),
  }));
  const source = readFileSync(new URL("../dist/worker.js", import.meta.url), "utf8");
  const inert = "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)";
  assert.equal(source.split(inert).length, 2);
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: source.replace(inert, "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)"),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: {
        AUTH_POLICY: JSON.stringify({ revision: 1, fleet: "fixture", principals }),
        HOST_CONNECTORS: "enabled",
      },
    }),
  );
  const call = async (actor: string, op: string, p: object) => {
    const response = await mf.dispatchFetch("https://fixture/" + op, {
      method: "POST",
      headers: { authorization: "Bearer fixture-" + actor, "content-type": "application/json" },
      body: JSON.stringify({ epoch: 7, ...p }),
    });
    return (await response.json()) as any;
  };
  try {
    const sessions = new Map<string, any>();
    for (const host of ["a", "b"]) {
      assert.equal(
        (
          await call("owner", "subscribe_central", {
            id: host,
            external_id: host,
            host,
            thread_id: "thread-" + host,
            binding,
            expires: null,
            name: "t3.thread.activity",
            callback_reference: host,
          })
        ).stored,
        true,
      );
      const connection = randomUUID();
      const opened = await call(host, "link_open", { host, connection });
      assert.equal(opened.host, host);
      sessions.set(host, { host, connection, generation: opened.generation });
    }
    const service = (
      host: string,
      operation: string,
      payload: object,
      session = sessions.get(host),
    ) => call(host, "link_service", { ...session, operation, payload });
    for (const host of ["a", "b"]) {
      assert.equal(
        (await call(host, "observation_cursor", { subscription_id: host })).reason,
        "fenced",
      );
      assert.equal(
        (await service(host, "observation_cursor", { subscription_id: host })).cursor,
        0,
      );
      assert.equal(
        (await service(host, "observation_cursor", { subscription_id: host === "a" ? "b" : "a" }))
          .reason,
        "fenced",
      );
      const event = {
        eventId: "event-" + host,
        name: "t3.thread.activity",
        data: { host, thread_id: "thread-" + host, run_id: "source", kind: "completed" },
      };
      const observation = {
        subscription_id: host,
        expected_cursor: 0,
        cursor: 1,
        run: "source",
        kind: "completed",
        native_request_id: "native-" + host,
        event,
      };
      const stored = await service(host, "observe_central", observation);
      assert.equal(stored.stored, true);
      const replay = await service(host, "observe_central", observation);
      assert.equal(replay.id, stored.id);
      assert.equal((await call(host, "outbox_claim", { id: stored.id })).reason, "fenced");
      const claim = await service(host, "outbox_claim", { id: stored.id });
      assert.equal(claim.claimed, true);
      assert.equal(
        (await service(host, "outbox_begin", { id: stored.id, generation: claim.generation }))
          .may_attempt,
        true,
      );
      assert.equal(
        (
          await service(host, "outbox_result", {
            id: stored.id,
            generation: claim.generation,
            http_status: 200,
          })
        ).state,
        "acknowledged",
      );
      assert.equal(
        (await service(host, "outbox_receipt", { id: stored.id })).state,
        "acknowledged",
      );
    }
    assert.equal((await service("a", "reserve", {})).reason, "forbidden");
    assert.equal(
      (await service("a", "observation_cursor", { subscription_id: "a", epoch: 7 })).reason,
      "invalid_request",
    );
    assert.equal(
      (
        await service(
          "a",
          "observation_cursor",
          { subscription_id: "a" },
          { ...sessions.get("a"), generation: 99 },
        )
      ).reason,
      "fenced",
    );
    assert.equal((await service("b", "observation_cursor", { subscription_id: "b" })).cursor, 1);
    assert.equal(
      (
        await call("owner", "link_service", {
          ...sessions.get("a"),
          operation: "observation_cursor",
          payload: { subscription_id: "a" },
        })
      ).reason,
      "forbidden",
    );
    // Real runtime composition, existing signer and actual Worker storage. No
    // native commands are published in this fixture; command IO must stay zero.
    const resources: Store[] = [];
    try {
      const runtimes = ["c", "d"].map((host) => {
        const store = new Store(":memory:", randomBytes(32));
        resources.push(store);
        const sub = {
          id: "standing-" + host,
          owner: "owner",
          host,
          threadId: "thread-" + host,
          active: true,
          expires: null,
          nonExpiring: true,
          name: "t3.eddie.requested",
          url: "https://callback.example.test/events",
          secret: "whsec_" + randomBytes(32).toString("base64"),
        };
        const event = {
          eventId: "runtime-event-" + host,
          name: sub.name,
          data: { host, thread_id: sub.threadId, run_id: "source", request_id: "request-" + host },
        };
        store.put("subscription", sub.id, sub);
        store.put("delivery", host, { id: host, subId: sub.id, status: "pending", event });
        let posts = 0,
          checkpoints = 0,
          loseResult = host === "c";
        const bridge = {
          store,
          now: Date.now,
          async observe(target: string) {
            assert.equal(target, host);
          },
          fleetEvents: {
            async observeHost(target: string) {
              assert.equal(target, host);
            },
          },
          exchanges: {
            async deliverable() {
              if (host === "d")
                throw Object.assign(Error("closed"), { reason: "input_request_not_pending" });
            },
          },
          async post(_url: string, headers: Record<string, string>, body: string) {
            assert.ok(checkpoints > 0);
            assert.equal(headers["webhook-id"], event.eventId);
            assert.ok(headers["webhook-signature"]);
            assert.equal(JSON.parse(body).eventId, event.eventId);
            posts++;
            return { status: 204 };
          },
        } as any;
        const input = {
          enabled: true,
          host,
          epoch: 7,
          store,
          key: randomBytes(32),
          payloadKey: randomBytes(32),
          now: Date.now,
          journal: {} as any,
          services: {} as any,
          async grant() {
            throw Error("unexpected native command");
          },
          async checkpoint() {
            checkpoints++;
          },
          binding: () => binding,
          ownerCall: async (owner: string, op: string, p: object) => {
            assert.equal(owner, "owner");
            return call(owner, op, p);
          },
          async call(op: string, p: any) {
            const result = await call(host, op, p);
            if (op === "link_service" && p.operation === "outbox_result" && loseResult) {
              loseResult = false;
              throw Error("fixture lost result response");
            }
            return result;
          },
        };
        assert.throws(
          () => createHostLocalRuntime(bridge, { ...input, enabled: false }),
          /host_runtime_disabled/,
        );
        return { runtime: createHostLocalRuntime(bridge, input), store, posts: () => posts };
      });
      await assert.rejects(runtimes[0].runtime.cycle(), /fixture lost result response/);
      assert.equal(runtimes[0].posts(), 1);
      assert.equal((await runtimes[1].runtime.cycle()).state, "cycle_complete");
      assert.equal(runtimes[1].posts(), 0);
      assert.equal(runtimes[1].store.get("delivery", "d")?.status, "revoked");
      await runtimes[0].runtime.cycle();
      assert.equal(runtimes[0].posts(), 1); // Receipt recovery, never resend an acknowledged callback.
      assert.equal(runtimes[0].store.get("delivery", "c")?.status, "acknowledged");
      for (const r of runtimes) {
        r.runtime.close();
        assert.equal((await r.runtime.cycle()).state, "closed");
      }
    } finally {
      for (const store of resources) store.close();
    }
    const directory = mkdtempSync(join(tmpdir(), "host-startup-"));
    const historical = join(directory, "historical"),
      cache = join(directory, "cache"),
      config = join(directory, "policy.json");
    mkdirSync(historical, { mode: 0o700 });
    mkdirSync(cache, { mode: 0o700 });
    writeFileSync(
      config,
      JSON.stringify({
        stateDirectory: cache,
        source: { type: "local-projection", databasePath: "unused" },
        sessions: [],
        principals: [],
        callbackHosts: [],
      }),
    );
    let sidecar: Awaited<ReturnType<typeof startHostLocalSidecar>> | undefined;
    let checkpoints = 0,
      closed = 0;
    try {
      const input = {
        enabled: true,
        host: "e",
        configPath: config,
        historicalStateDirectory: historical,
        cacheStateDirectory: cache,
        stateKey: randomBytes(32),
        backendFactory: () =>
          ({
            read: async () => {
              throw Error("unexpected native read");
            },
            close: async () => {
              closed++;
            },
          }) as any,
        async ports(bridge: any) {
          return {
            enabled: true,
            host: "e",
            store: bridge.store,
            epoch: 7,
            key: randomBytes(32),
            payloadKey: randomBytes(32),
            now: Date.now,
            journal: {} as any,
            services: {} as any,
            grant: async () => {
              throw Error("unexpected command");
            },
            checkpoint: async () => {
              checkpoints++;
            },
            binding: () => binding,
            ownerCall: async () => {
              throw Error("unexpected owner write");
            },
            call: (op: string, p: object) => call("e", op, p),
          };
        },
      };
      await assert.rejects(
        startHostLocalSidecar({ ...input, enabled: false }),
        /host_runtime_disabled/,
      );
      sidecar = await startHostLocalSidecar(input);
      assert.equal(sidecar.address(), null);
      await sidecar.shutdown();
      assert.equal(closed, 1);
      assert.ok(checkpoints >= 2);
    } finally {
      await sidecar?.shutdown();
      rmSync(directory, { recursive: true, force: true });
    }
  } finally {
    await mf.dispose();
  }
});

test("host-local policy refuses remote native routes and foreign observation/command scope", () => {
  const guard = hostLocalPolicyGuard("a");
  const policy = {
    sessions: [],
    principals: [],
    fleetRead: { hosts: [{ name: "a" }] },
    nativeDelivery: { hosts: [{ name: "a", command: "fixture" }] },
  } as any;
  guard(policy);
  for (const patch of [
    { sessions: [{ host: "b" }] },
    { fleetRead: { hosts: [{ name: "b" }] } },
    { nativeDelivery: { hosts: [{ name: "a", ssh: "b" }] } },
    { principals: [{ commandHosts: [{ host: "b" }] }] },
    { collaboration: { enabled: true } },
    { fleetHelperPath: "global-helper" },
  ])
    assert.throws(() => guard({ ...policy, ...patch }), /host_local_policy_required/);
});
