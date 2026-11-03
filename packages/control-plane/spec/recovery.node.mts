// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { createServer } from "node:net";
import { verifyManagedRetirement, retirementTombstone } from "../src/managed-retirement.ts";
import { localArchiveReference } from "../src/local-archive.ts";
import { signRetirement, type RetirementEvidence } from "../src/activation.ts";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { centralTransport } from "../src/transport.ts";
import { captureRecovery, verifyRecovery, packRecovery } from "../src/recovery-archive.ts";
import { uploadRecovery } from "../src/recovery-upload.ts";
import { Store } from "../../../dist/store.mjs";
import { nativeFixture } from "./native-fixture.mts";
import { prepareLegacyRecovery } from "../src/legacy-recovery.ts";
import { segmentSnapshot } from "../src/import-service.ts";
import { manifestOf } from "../src/snapshot.ts";
import { projectControlPolicy } from "../src/production-bootstrap.ts";
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
test(
  "managed Windows retirement probes actual closed ingress and refuses surviving credentials or changed bootstrap",
  { skip: process.platform !== "win32" },
  async () => {
    const dir = mkdtempSync(join(tmpdir(), "kadenco-retirement-fixture-"));
    const archivePath = join(dir, "history.db"),
      entry = join(dir, "retired.ps1"),
      credentials = join(dir, "old-credentials.clixml"),
      releaseEntry = join(dir, "old-main.mjs");
    const store = new Store(archivePath, randomBytes(32));
    store.close();
    writeFileSync(entry, retirementTombstone("fixture"));
    writeFileSync(releaseEntry, "// inert fixture only\n");
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as { port: number }).port;
    const input = {
      root: dir,
      entry,
      credentials,
      releaseEntry,
      archivePath,
      archiveSha256: localArchiveReference(archivePath).archive_sha256,
      fenceId: "fixture",
      ports: [port],
    };
    try {
      await assert.rejects(verifyManagedRetirement(input), /legacy_ingress_still_open/);
      await new Promise<void>((resolve, reject) =>
        server.close((e) => (e ? reject(e) : resolve())),
      );
      writeFileSync(credentials, "fixture, not a credential");
      await assert.rejects(verifyManagedRetirement(input), /legacy_credentials_still_present/);
      unlinkSync(credentials);
      writeFileSync(entry, "throw 'different'\r\n");
      await assert.rejects(verifyManagedRetirement(input), /legacy_bootstrap_not_retired/);
      writeFileSync(entry, retirementTombstone("fixture"));
      const result = await verifyManagedRetirement(input);
      assert.equal(result.processes, 0);
      assert.equal(result.ingress_closed, true);
      assert.equal(result.revival_denied, true);
      assert.equal(localArchiveReference(archivePath).archive_sha256, input.archiveSha256);
    } finally {
      if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
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
test("activation binds imported state, current authority and retirement challenge; receipt survives restart", async () => {
  const f = await fixture();
  try {
    const rows = structuredClone(f.verified.rows),
      header = structuredClone(f.verified.header),
      archiveHash = sha("fixture historical database");
    rows.find((r) => r.table === "control")!.values.migration = "fixture-retirement";
    rows.push({
      table: "imported",
      key: Math.max(0, ...rows.filter((r) => r.table === "imported").map((r) => r.key)) + 1,
      values: {
        kind: "$history_archive",
        id: archiveHash,
        ciphertext: JSON.stringify({ archive_sha256: archiveHash }),
      },
    });
    header.counts.imported++;
    const archive = packRecovery(header, rows, f.key),
      digest = JSON.parse(archive.header.body).digest;
    await uploadRecovery(archive, f.key, f.expected, {
      importId: "activation-import",
      expectedEpoch: 0,
      call: f.target,
    });
    const args = {
      activation_id: "fixture-activation",
      expected_epoch: 9,
      import_id: "activation-import",
      digest,
    };
    assert.equal((await f.executor("activation_challenge", args)).reason, "forbidden");
    const challenge = await f.target("activation_challenge", args);
    assert.equal(typeof challenge.nonce, "string");
    const now = Date.now(),
      proof: RetirementEvidence = {
        kind: "managed_bootstrap_retirement",
        migration_id: "fixture-retirement",
        snapshot: digest,
        issued: now,
        expires: now + 30000,
        routes: ["native:fixture", "callback", "restart"],
        denied: ["native:fixture", "callback", "restart"],
        revival_denied: true,
        issuer: "owner",
        challenge: String(challenge.nonce),
        epoch: 9,
        import_id: "activation-import",
        archive_sha256: archiveHash,
        source_release_sha256: sha("release"),
        bootstrap_sha256: sha("bootstrap"),
        credential_path_sha256: sha("path"),
        processes: 0,
        ingress_closed: true,
      };
    const attempt = (p: RetirementEvidence, token = "fixture-owner") =>
      f.target("activate", { ...args, retirement: signRetirement(p, token) });
    assert.equal((await attempt(proof, "wrong-fixture-token")).reason, "invalid_signature");
    assert.equal((await attempt({ ...proof, challenge: "wrong" })).reason, "retirement_not_proven");
    assert.equal(
      (await attempt({ ...proof, denied: ["callback", "restart"] })).reason,
      "retirement_not_proven",
    );
    assert.equal(
      (await attempt({ ...proof, archive_sha256: sha("wrong archive") })).reason,
      "retirement_not_proven",
    );
    assert.equal(
      (await attempt({ ...proof, issued: now - 120000, expires: now - 1000 })).reason,
      "activation_expired",
    );
    const activated = await attempt(proof);
    assert.equal(activated.activated, true, JSON.stringify(activated));
    assert.equal(activated.epoch, 10);
    await f.restart();
    const receipt = await f.target("activation_receipt", { activation_id: args.activation_id });
    assert.equal(receipt.committed, true);
    assert.equal(receipt.epoch, 10);
    assert.deepEqual(await attempt(proof), activated);
    assert.equal(
      (await f.target("activation_challenge", { ...args, digest: sha("changed") })).reason,
      "idempotency_conflict",
    );
    assert.equal((await f.target("status", {})).epoch, 10);
  } finally {
    await f.close();
  }
});

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

test("legacy operational state reaches the authenticated destination without plaintext prompts or reviving expired subscriptions", async () => {
  const f = nativeFixture();
  f.policy.principals[0].readHosts![0].projectIds = undefined;
  const now = f.now,
    identity = sha(JSON.stringify(["owner", "host", "thread"]));
  const standing = {
    id: "standing",
    owner: "owner",
    name: "t3.thread.activity",
    host: "host",
    threadId: "thread",
    projectId: "project",
    laneId: "lane_" + identity,
    sessionId: "thread_" + identity.slice(0, 32),
    active: true,
    expires: null,
    nonExpiring: true,
    url: "https://fixture.invalid/callback",
    secret: "fixture-preserved-callback-secret",
  };
  const old = {
    owner: "owner",
    host: "host",
    thread_id: "thread",
    projectId: "project",
    sourceRunId: "historical-run",
    request_id: "00000000-0000-4000-8000-000000000091",
    kind: "continue",
    message: "FIXTURE_PROMPT_MUST_STAY_ENCRYPTED",
    at: now - 1000,
    submission: "outcome_unknown",
  };
  const entries = [
    { kind: "command", id: old.request_id, value: old },
    { kind: "subscription", id: standing.id, value: standing },
    {
      kind: "subscription",
      id: "retired-v1",
      value: {
        owner: "owner",
        id: "retired-v1",
        sessionId: "unconfigured-old-session",
        active: false,
        expires: now - 100,
        url: standing.url,
        secret: standing.secret,
      },
    },
    {
      kind: "delivery",
      id: "acknowledged",
      value: {
        subId: standing.id,
        status: "acknowledged",
        attempts: 1,
        nextAt: now,
        event: {
          eventId: "old-ack",
          name: standing.name,
          data: { host: "host", thread_id: "thread", run_id: "historical-run" },
        },
      },
    },
    {
      kind: "delivery",
      id: "pending",
      value: {
        subId: standing.id,
        status: "pending",
        attempts: 2,
        nextAt: now,
        event: {
          eventId: "retained-pending",
          name: standing.name,
          data: { host: "host", thread_id: "thread", run_id: "historical-run" },
        },
      },
    },
    {
      kind: "followup",
      id: "old-fixed",
      value: {
        owner: "owner",
        requestId: "00000000-0000-4000-8000-000000000092",
        sessionId: "verification",
        runId: "verification-run",
        createdAt: now - 86400000,
        status: "completed",
      },
    },
  ];
  const snapshot = {
    migration_id: "legacy-live-shaped-fixture",
    source_snapshot: "fixture-quiesced",
    encryption_provenance: "fixture-original-key",
    records: entries.map((r) => ({ kind: r.kind, id: r.id, ciphertext: f.store.encode(r.value) })),
  };
  const config = {
    fleet: "legacy-fixture",
    origin: "https://fixture.invalid",
    epoch: 1,
    executor: "fixture-edge",
    executorToken: "fixture-executor-token-at-least-32-characters",
    ownerTokens: new Map([["owner", "fixture-owner"]]),
    observationOwner: "owner",
    serviceExpiresAt: now + 300000,
    key: f.key,
    journalPath: join(tmpdir(), "unused-fixture-journal"),
  };
  const mapping = projectControlPolicy(f.policy, config);
  const central = {
    ...mapping,
    principals: mapping.principals.map((p) => ({
      ...p,
      ...(p.role === "owner" ? { migrationAuthority: true } : {}),
    })),
  };
  const packets = segmentSnapshot(snapshot, f.key),
    expected = manifestOf(snapshot);
  let mf: Miniflare | undefined;
  try {
    const prepared = prepareLegacyRecovery(
      packets,
      f.key,
      expected,
      f.policy,
      central,
      config.serviceExpiresAt,
      now,
    );
    assert.equal(prepared.ledger.encrypted_records, entries.length);
    assert.equal(prepared.ledger.retained_inert_subscriptions, 1);
    assert.equal(prepared.ledger.commands, 2);
    assert.equal(prepared.ledger.subscriptions, 1);
    assert.equal(prepared.ledger.deliveries, 1);
    assert.equal(f.effects(), 0);
    mf = new Miniflare(
      convertV4MiniflareOptions({
        modules: true,
        script: worker,
        compatibilityDate: "2026-10-30",
        compatibilityFlags: ["nodejs_compat"],
        durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
        bindings: { AUTH_POLICY: JSON.stringify(central) },
      }),
    );
    const call = centralTransport({
      origin: config.origin,
      token: () => "fixture-owner",
      fetch: async (url, init) =>
        (await mf!.dispatchFetch(
          String(url),
          init as Parameters<Miniflare["dispatchFetch"]>[1],
        )) as unknown as Response,
    });
    assert.equal(
      (
        await uploadRecovery(prepared.archive, f.key, prepared.expected, {
          importId: "legacy-fixture",
          expectedEpoch: 0,
          call,
        })
      ).epoch,
      1,
    );
    const capture = await captureRecovery(call, 1, f.key),
      header = JSON.parse(capture.header.body).header;
    const rows = verifyRecovery(capture, f.key, header).rows;
    const command = rows.find((r) => r.table === "commands" && r.values.id === old.request_id)!;
    assert.equal(command.values.state, "uncertain");
    assert.equal(String(command.values.receipt).includes(old.message), false);
    assert.equal(JSON.parse(String(command.values.binding)).expires, 0);
    const encrypted = rows.find(
      (r) =>
        r.table === "imported" && r.values.kind === "command" && r.values.id === old.request_id,
    )!;
    assert.equal(encrypted.values.ciphertext, snapshot.records[0].ciphertext);
    assert.deepEqual(f.store.decode(encrypted.values.ciphertext), old);
    assert.equal(
      rows.filter((r) => r.table === "imported" && r.values.kind === "subscription").length,
      2,
    );
    assert.equal(rows.filter((r) => r.table === "outbox").length, 1);
    assert.equal(rows.find((r) => r.table === "outbox")!.values.attempts, 2);
    assert.equal(
      rows.some(
        (r) => r.table === "subscriptions" && String(r.values.value).includes(standing.secret),
      ),
      false,
    );
    const damaged = structuredClone(packets);
    damaged[0].mac = "0".repeat(64);
    assert.throws(
      () =>
        prepareLegacyRecovery(
          damaged,
          f.key,
          expected,
          f.policy,
          central,
          config.serviceExpiresAt,
          now,
        ),
      /invalid_signature/,
    );
    const revoked = structuredClone(f.policy);
    revoked.principals[0].enabled = false;
    assert.throws(
      () =>
        prepareLegacyRecovery(
          packets,
          f.key,
          expected,
          revoked,
          central,
          config.serviceExpiresAt,
          now,
        ),
      /legacy_owner_unmapped/,
    );
  } finally {
    await mf?.dispose();
    await f.close();
  }
});
