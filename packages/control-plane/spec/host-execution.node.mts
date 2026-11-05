// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { seal, validateOperation, type Envelope, type Grant } from "../src/authorization.ts";
import { encryptHostPayload, hostPayloadIdentity } from "../src/host-payload.ts";
import { consumeHostReference } from "../src/host-execution.ts";
import { ConnectorInbox } from "../src/host-connector.ts";
import { createHostLocalConnector } from "../src/host-local.ts";
import { Store } from "../../../dist/store.mjs";
import { SqliteJournal } from "../src/journal.ts";
import type { SidecarServices } from "../src/native-adapter.ts";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
test("Worker host connector routes are disabled without explicit source configuration", async () => {
  const source = readFileSync(new URL("../dist/worker.js", import.meta.url), "utf8").replace(
    "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)",
    "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)",
  );
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: source,
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: {
        AUTH_POLICY: JSON.stringify({
          revision: 1,
          fleet: "fixture",
          principals: [
            {
              id: "a",
              role: "executor",
              hosts: ["a"],
              tokenSha256: sha("fixture-a"),
              expiresAt: 4102444800000,
            },
          ],
        }),
      },
    }),
  );
  try {
    const response = await mf.dispatchFetch("https://fixture/link_open", {
      method: "POST",
      headers: { authorization: "Bearer fixture-a", "content-type": "application/json" },
      body: JSON.stringify({ epoch: 7, host: "a", connection: randomUUID() }),
    });
    assert.deepEqual(await response.json(), { reason: "forbidden" });
  } finally {
    await mf.dispose();
  }
});
test("two real Worker host links deliver exact mock native operations, restart and reconcile lost responses without redispatch", async () => {
  const scope = {
    project: "project",
    provider: "codex",
    run: "source",
    grant: "grant",
    revision: 1,
    expires: 4102444700000,
  };
  const principals = [
    { id: "owner", role: "owner", hosts: ["a", "b"], maxPerDay: null },
    ...["a", "b"].map((host) => ({ id: host, role: "executor", hosts: [host] })),
  ].map((p) => ({
    ...p,
    scopes: [scope],
    expiresAt: 4102444800000,
    tokenSha256: sha("fixture-" + p.id),
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
  const call = (actor: string) => async (op: string, p: object) => {
    const r = await mf.dispatchFetch("https://fixture/" + op, {
      method: "POST",
      headers: { authorization: "Bearer fixture-" + actor, "content-type": "application/json" },
      body: JSON.stringify(op === "receipt" ? p : { epoch: 7, ...p }),
    });
    return (await r.json()) as Record<string, unknown>;
  };
  const key = randomBytes(32),
    payloadKey = randomBytes(32),
    dir = mkdtempSync(join(tmpdir(), "host-execution-"));
  const resources: { close(): void }[] = [];
  try {
    const results = await Promise.allSettled(
      ["a", "b"].map(async (host) => {
        const request_id = randomUUID(),
          thread_id = "exact-" + host;
        const e: Envelope = {
          request_id,
          fleet: "fixture",
          principal: "owner",
          ...scope,
          host,
          thread_id,
          kind: "continue",
          payload: { text: "Continue only approved fixture work" },
        };
        const grant: Grant = { ...e, revoked: false, kinds: ["continue"] };
        const digest = validateOperation(e, grant, Date.now());
        const packet = seal(e, key),
          ciphertext = encryptHostPayload(
            packet,
            payloadKey,
            hostPayloadIdentity(host, thread_id, request_id, digest),
          );
        assert.equal(
          (
            await call("owner")("reserve", {
              request_id,
              host,
              thread_id,
              kind: e.kind,
              payload_sha256: digest,
              binding: scope,
            })
          ).state,
          "pending",
        );
        assert.equal(
          (await call("owner")("link_publish", { request_id, ciphertext })).existing,
          false,
        );
        const store = new Store(join(dir, host + ".db"), key);
        resources.push(store);
        const inbox = new ConnectorInbox(store, host);
        let executions = 0,
          reads = 0;
        const receipt = {
          request_id,
          host,
          thread_id,
          native_submitted: true,
          run_status: "completed",
          message_id: "message-" + host,
          run_id: "run-" + host,
          safe_to_resend: false,
          terminal: true,
          completed: true,
          run_status_fresh: true,
          message_observation_fresh: true,
          native_message_observation: {
            message_id: "message-" + host,
            run_id: "run-" + host,
            run_status: "completed",
          },
        };
        const services = {
          continue: async (owner: string, args: any) => {
            executions++;
            assert.equal(owner, "owner");
            assert.equal(args.host, host);
            assert.equal(args.thread_id, thread_id);
            assert.equal(args.request_id, request_id);
            assert.equal(args.message, e.payload.text);
            throw Error("lost native response after effect");
          },
          receipt: async (_owner: string, args: any) => {
            reads++;
            assert.equal(args.request_id, request_id);
            return receipt;
          },
          creation: {
            create: async () => {
              throw Error("unexpected");
            },
          },
          settings: {
            standard: async () => {
              throw Error("unexpected");
            },
          },
        } as SidecarServices;
        const path = join(dir, host + "-journal.db");
        let journal = new SqliteJournal(path, key);
        let loseReceipt = true;
        const local = createHostLocalConnector({
          host,
          store,
          epoch: 7,
          key,
          payloadKey,
          grant: async () => grant,
          now: Date.now,
          journal: {
            reserve: (id) => journal.reserve(id),
            finish: (id, outcome) => journal.finish(id, outcome),
          },
          call: async (op: string, body: object) => {
            const result = await call(host)(op, body);
            if (op === "link_record_receipt" && loseReceipt) {
              loseReceipt = false;
              throw Error("receipt committed but response lost");
            }
            return result;
          },
          services,
        });
        assert.deepEqual(await local.cycle(), { state: "cycle_complete", examined: 1, settled: 0 });
        const frame = inbox.read(request_id)!;
        assert.equal(frame.request_id, request_id);
        assert.equal(executions, 1);
        journal.close();
        journal = new SqliteJournal(path, key);
        assert.deepEqual(await local.cycle(), { state: "cycle_complete", examined: 1, settled: 0 });
        assert.equal(executions, 1);
        assert.equal(reads, 1);
        assert.deepEqual(await local.cycle(), { state: "cycle_complete", examined: 1, settled: 1 });
        assert.deepEqual(await local.cycle(), { state: "cycle_complete", examined: 0, settled: 0 });
        assert.equal(executions, 1);
        await assert.rejects(
          consumeHostReference({ host: host === "a" ? "b" : "a", frame } as Parameters<
            typeof consumeHostReference
          >[0]),
          /host_identity_mismatch/,
        );
        local.close();
        assert.equal((await local.cycle()).state, "closed");
        journal.close();
      }),
    );
    for (const result of results) if (result.status === "rejected") throw result.reason;
  } finally {
    for (const r of resources) r.close();
    await mf.dispose();
  }
});
