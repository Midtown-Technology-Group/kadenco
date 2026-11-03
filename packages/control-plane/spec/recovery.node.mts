// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { centralTransport } from "../src/transport.ts";
import { captureRecovery, verifyRecovery, packRecovery } from "../src/recovery-archive.ts";
import { uploadRecovery } from "../src/recovery-upload.ts";
import { Store } from "../../../dist/store.mjs";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const scope = {
  project: "fixture",
  provider: "codex",
  run: "source",
  grant: "fixture-grant",
  revision: 1,
  expires: 4102444700000,
};
const policy = {
  revision: 1,
  fleet: "fixture",
  principals: [
    {
      id: "owner",
      role: "owner",
      migrationAuthority: true,
      maxPerDay: null,
      tokenSha256: sha("fixture-owner"),
      hosts: ["fixture"],
      scopes: [scope],
      expiresAt: 4102444800000,
    },
    {
      id: "owner2",
      role: "owner",
      migrationAuthority: true,
      maxPerDay: null,
      tokenSha256: sha("fixture-owner2"),
      hosts: ["fixture"],
      scopes: [scope],
      expiresAt: 4102444800000,
    },
    {
      id: "edge",
      role: "executor",
      stateCustodian: true,
      tokenSha256: sha("fixture-edge"),
      hosts: ["fixture"],
      scopes: [scope],
      expiresAt: 4102444800000,
    },
  ],
};
const worker = readFileSync(new URL("../dist/worker.js", import.meta.url), "utf8");
async function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-recovery-api-"));
  const inert = "INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL)";
  assert.equal(worker.split(inert).length, 2);
  const build = (active: boolean, path: string) =>
    new Miniflare({
      ...convertV4MiniflareOptions({
        name: "kadenco-recovery-fixture",
        modules: true,
        script: active
          ? worker.replace(inert, "INSERT OR IGNORE INTO control VALUES(1,7,'active',NULL)")
          : worker,
        compatibilityDate: "2026-10-30",
        compatibilityFlags: ["nodejs_compat"],
        durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
        bindings: { AUTH_POLICY: JSON.stringify(policy) },
      }),
      resourcePersistencePath: path,
    });
  const source = build(true, join(dir, "source"));
  let destination = build(false, join(dir, "destination"));
  let dropCommit = false,
    commits = 0;
  const transport = (get: () => Miniflare, token: string, dest = false) =>
    centralTransport({
      origin: "https://fixture.invalid",
      token: () => token,
      fetch: async (url, init) => {
        const r = await get().dispatchFetch(
          String(url),
          init as Parameters<Miniflare["dispatchFetch"]>[1],
        );
        if (dest && String(url).endsWith("/commit_recovery")) {
          commits++;
          if (dropCommit && r.ok) {
            dropCommit = false;
            await r.body?.cancel();
            throw Error("fixture_lost_commit_response");
          }
        }
        return r as unknown as Response;
      },
    });
  const owner = transport(() => source, "fixture-owner"),
    edge = transport(() => source, "fixture-edge");
  const key = randomBytes(32),
    store = new Store(":memory:", key);
  const uncertain = "00000000-0000-4000-8000-000000000081",
    completed = "00000000-0000-4000-8000-000000000082";
  try {
    for (const id of [uncertain, completed]) {
      assert.equal(
        (
          await owner("reserve", {
            epoch: 7,
            request_id: id,
            host: "fixture",
            thread_id: "thread",
            kind: "continue",
            payload_sha256: sha(id),
            binding: scope,
          })
        ).id,
        id,
      );
      const claim = await edge("claim", { epoch: 7, request_id: id, lease_ms: 10000 });
      assert.equal(
        (await edge("begin", { epoch: 7, request_id: id, generation: claim.generation }))
          .may_attempt,
        true,
      );
      if (id === completed)
        await edge("record_receipt", {
          epoch: 7,
          request_id: id,
          generation: claim.generation,
          receipt: { state: "observed", evidence: "fixture-only native receipt" },
        });
    }
    const lease = await edge("edge_lease", { epoch: 7 });
    store.put("command", uncertain, { request_id: uncertain, safe_to_resend: false });
    const ciphertext = String(
      store.db.prepare("SELECT value FROM records WHERE id=?").get(uncertain)!.value,
    );
    assert.equal(
      (
        await edge("replica_apply", {
          epoch: 7,
          generation: lease.generation,
          request_id: "00000000-0000-4000-8000-000000000083",
          expected_revision: 0,
          records: [{ kind: "command", id: uncertain, ciphertext }],
        })
      ).committed,
      true,
    );
    const archive = await captureRecovery(owner, 7, key);
    const verified = verifyRecovery(archive, key, {
      epoch: 8,
      watermark: JSON.parse(archive.header.body).header.watermark,
    });
    const expected = { epoch: verified.header.epoch, watermark: verified.header.watermark };
    return {
      archive,
      key,
      expected,
      verified,
      uncertain,
      completed,
      ciphertext,
      target: transport(() => destination, "fixture-owner", true),
      other: transport(() => destination, "fixture-owner2", true),
      executor: transport(() => destination, "fixture-edge", true),
      owner,
      loseCommit() {
        dropCommit = true;
      },
      commits: () => commits,
      async restart() {
        await destination.dispose();
        destination = build(false, join(dir, "destination"));
      },
      async close() {
        store.close();
        await Promise.all([source.dispose(), destination.dispose()]);
        rmSync(dir, { recursive: true, force: true });
      },
    };
  } catch (e) {
    store.close();
    await Promise.all([source.dispose(), destination.dispose()]);
    rmSync(dir, { recursive: true, force: true });
    throw e;
  }
}
test("authenticated recovery survives destination restart and lost commit response without losing uncertain IDs or current receipts", async () => {
  const f = await fixture();
  try {
    f.loseCommit();
    const target = { importId: "fixture-import", expectedEpoch: 0, call: f.target };
    await assert.rejects(
      uploadRecovery(f.archive, f.key, f.expected, target),
      /central_transport_uncertain/,
    );
    await f.restart();
    const result = await uploadRecovery(f.archive, f.key, f.expected, target);
    assert.equal(result.committed, true, JSON.stringify({ result, commits: f.commits() }));
    assert.equal(result.epoch, 9);
    assert.equal(f.commits(), 1, "receipt recovery does not submit the commit again");
    assert.equal((await f.target("status", {})).mode, "quiesced");
    assert.equal((await f.target("reserve", { epoch: 9 })).reason, "not_active");
    assert.equal(
      (await f.owner("begin", { epoch: 7, request_id: f.uncertain, generation: 1 })).reason,
      "not_active",
      "frozen source cannot issue another permit",
    );
    const current = await captureRecovery(f.target, 9, f.key);
    const h = JSON.parse(current.header.body).header;
    const recovered = verifyRecovery(current, f.key, h);
    const commands = recovered.rows.filter((r) => r.table === "commands");
    assert.equal(commands.length, 2);
    assert.equal(commands.find((r) => r.values.id === f.uncertain)!.values.state, "uncertain");
    assert.equal(
      commands.find((r) => r.values.id === f.completed)!.values.receipt,
      JSON.stringify({ state: "observed", evidence: "fixture-only native receipt" }),
    );
    assert.equal(recovered.rows.filter((r) => r.table === "budget_reservations").length, 2);
    assert.equal(recovered.rows.filter((r) => r.table === "recovery_import_receipts").length, 1);
    assert.equal(
      recovered.rows.find((r) => r.table === "replica_records")!.values.ciphertext,
      f.ciphertext,
    );
  } finally {
    await f.close();
  }
});
test("partial uploads, changed duplicates and foreign actors cannot commit or activate", async () => {
  const f = await fixture();
  try {
    const { header, rows } = f.verified,
      digest = sha(JSON.stringify({ header, rows }));
    const stage = { import_id: "partial", expected_epoch: 0, header, digest, chunks: 2 };
    assert.equal((await f.executor("stage_recovery", stage)).reason, "forbidden");
    assert.equal(
      (await f.target("stage_recovery", { ...stage, expected_epoch: 1 })).reason,
      "fenced",
    );
    assert.equal((await f.target("stage_recovery", stage)).staged, true);
    assert.equal(
      (
        await f.other("recovery_chunk", {
          import_id: "partial",
          sequence: 0,
          rows: rows.slice(0, 1),
        })
      ).reason,
      "forbidden",
    );
    assert.equal(
      (await f.target("recovery_chunk", { import_id: "partial", sequence: 1, rows: rows.slice(1) }))
        .stored,
      true,
    );
    assert.equal(
      (await f.target("commit_recovery", { import_id: "partial", digest })).reason,
      "incomplete_recovery",
    );
    assert.equal(
      (
        await f.target("recovery_chunk", {
          import_id: "partial",
          sequence: 1,
          rows: rows.slice(0, 1),
        })
      ).reason,
      "idempotency_conflict",
    );
    await f.restart();
    assert.equal(
      (
        await f.target("recovery_chunk", {
          import_id: "partial",
          sequence: 0,
          rows: rows.slice(0, 1),
        })
      ).stored,
      true,
    );
    assert.equal(
      (await f.target("commit_recovery", { import_id: "partial", digest })).activation_permitted,
      false,
    );
    assert.equal(
      (await f.other("recovery_import_receipt", { import_id: "partial" })).reason,
      "forbidden",
    );
    assert.equal(
      (await f.target("commit_recovery", { import_id: "partial", digest: "0".repeat(64) })).reason,
      "idempotency_conflict",
    );
  } finally {
    await f.close();
  }
});
test("an authenticated archive cannot replace policy and a failed restore retains the exact staged input", async () => {
  const f = await fixture();
  try {
    const rows = structuredClone(f.verified.rows);
    const auth = rows.find((r) => r.table === "auth_policy")!;
    const changed = JSON.parse(String(auth.values.value));
    changed.principals[0].hosts.push("ungranted");
    auth.values.value = JSON.stringify(changed);
    const archive = packRecovery(f.verified.header, rows, f.key);
    await assert.rejects(
      uploadRecovery(archive, f.key, f.expected, {
        importId: "wrong-policy",
        expectedEpoch: 0,
        call: f.target,
      }),
      /recovery_commit_unverified/,
    );
    assert.equal((await f.target("status", {})).commands, 0);
    assert.equal((await f.target("status", {})).mode, "staging");
    assert.equal(
      (await f.target("recovery_import_receipt", { import_id: "wrong-policy" })).committed,
      false,
    );
    const digest = sha(JSON.stringify({ header: f.verified.header, rows }));
    assert.equal(
      (await f.target("commit_recovery", { import_id: "wrong-policy", digest })).reason,
      "recovery_policy_mismatch",
    );
  } finally {
    await f.close();
  }
});
test("revocation during upload and invalid archive authentication stop before further writes", async () => {
  const f = await fixture();
  try {
    let calls = 0;
    const damaged = structuredClone(f.archive);
    damaged.pages[0].mac = "0".repeat(64);
    await assert.rejects(
      uploadRecovery(damaged, f.key, f.expected, {
        importId: "damaged",
        expectedEpoch: 0,
        call: async () => {
          calls++;
          return {};
        },
      }),
      /invalid_signature/,
    );
    assert.equal(calls, 0);
    const { header, rows } = f.verified,
      digest = sha(JSON.stringify({ header, rows }));
    assert.equal(
      (
        await f.target("stage_recovery", {
          import_id: "revoked",
          expected_epoch: 0,
          header,
          digest,
          chunks: 1,
        })
      ).staged,
      true,
    );
    assert.equal((await f.other("revoke", { principal_id: "owner" })).revoked, true);
    assert.equal(
      (await f.target("recovery_chunk", { import_id: "revoked", sequence: 0, rows })).reason,
      "forbidden",
    );
    assert.equal(
      (await f.target("commit_recovery", { import_id: "revoked", digest })).reason,
      "forbidden",
    );
    assert.equal((await f.other("status", {})).commands, 0);
  } finally {
    await f.close();
  }
});

test("a restore constraint failure rolls back partial destination writes and preserves staged chunks", async () => {
  const f = await fixture();
  try {
    const rows = structuredClone(f.verified.rows);
    const commands = rows.filter((r) => r.table === "commands");
    commands[1].values.id = commands[0].values.id; // Distinct recovery rowids, conflicting actual primary key.
    const archive = packRecovery(f.verified.header, rows, f.key);
    await assert.rejects(
      uploadRecovery(archive, f.key, f.expected, {
        importId: "constraint",
        expectedEpoch: 0,
        call: f.target,
      }),
      /recovery_commit_unverified:invalid_recovery/,
    );
    const state = await f.target("status", {});
    assert.equal(state.mode, "staging");
    assert.equal(state.commands, 0);
    const digest = sha(JSON.stringify({ header: f.verified.header, rows }));
    assert.equal(
      (await f.target("commit_recovery", { import_id: "constraint", digest })).reason,
      "invalid_recovery",
    );
    assert.equal(
      (await f.target("recovery_import_receipt", { import_id: "constraint" })).committed,
      false,
    );
    assert.equal((await f.other("status", {})).commands, 0);
  } finally {
    await f.close();
  }
});

test("current principal expiry during upload cannot be bypassed by the retained archive or another owner", async () => {
  const f = await fixture();
  try {
    const { header, rows } = f.verified,
      digest = sha(JSON.stringify({ header, rows }));
    assert.equal(
      (
        await f.target("stage_recovery", {
          import_id: "expired",
          expected_epoch: 0,
          header,
          digest,
          chunks: 1,
        })
      ).staged,
      true,
    );
    const next = structuredClone(policy);
    next.revision = 2;
    next.principals[0].expiresAt = Date.now() - 1;
    assert.equal(
      (await f.other("tighten_policy", { expected_revision: 1, policy: next })).revision,
      2,
    );
    assert.equal(
      (await f.target("recovery_chunk", { import_id: "expired", sequence: 0, rows })).reason,
      "forbidden",
    );
    assert.equal(
      (await f.target("commit_recovery", { import_id: "expired", digest })).reason,
      "forbidden",
    );
    assert.equal(
      (await f.other("commit_recovery", { import_id: "expired", digest })).reason,
      "forbidden",
    );
    assert.equal((await f.other("status", {})).mode, "staging");
  } finally {
    await f.close();
  }
});
