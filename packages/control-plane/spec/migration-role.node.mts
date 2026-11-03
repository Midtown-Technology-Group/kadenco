// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { encodePolicy, decodePolicy } from "../src/policy-transport.ts";
import { gzipSync } from "node:zlib";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
const migration = {
  id: "migration",
  role: "migration",
  migrationAuthority: true,
  maxPerDay: 0,
  scopes: [],
  nativeGrants: [],
  hosts: ["fixture"],
  expiresAt: Date.now() + 3600000,
  tokenSha256: hash("fixture-migration"),
};
async function fixture(principals: unknown[], binding?: string, persistence?: string) {
  const mf = new Miniflare({
    ...convertV4MiniflareOptions({
      name: "kadenco-migration-role-fixture",
      modules: true,
      script: readFileSync(new URL("../dist/worker.js", import.meta.url), "utf8"),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: {
        AUTH_POLICY: binding ?? JSON.stringify({ revision: 1, fleet: "fixture", principals }),
      },
    }),
    ...(persistence ? { resourcePersistencePath: persistence } : {}),
  });
  return {
    close: () => mf.dispose(),
    call: async (op: string, p: object = {}, token = "fixture-migration") => {
      const r = await mf.dispatchFetch("https://fixture.invalid/" + op, {
        method: "POST",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        body: JSON.stringify(p),
      });
      return (await r.json()) as Record<string, unknown>;
    },
  };
}

test("encoded policy exceeds the text-binding size before compression without losing any principal or authorization rule", async () => {
  const principals = [
    migration,
    ...Array.from({ length: 40 }, (_, i) => ({
      id: "owner-" + i,
      role: "owner",
      hosts: ["fixture"],
      scopes: [],
      nativeGrants: [],
      expiresAt: Date.now() + 3600000,
      tokenSha256: hash("fixture-owner-" + i),
    })),
  ];
  const raw = JSON.stringify({ revision: 1, fleet: "fixture", principals }),
    encoded = encodePolicy(raw);
  assert.ok(Buffer.byteLength(raw) > 5120);
  assert.ok(Buffer.byteLength(encoded) < 5000);
  assert.equal(decodePolicy(encoded), raw);
  assert.equal(decodePolicy(raw), raw);
  const f = await fixture(principals, encoded);
  try {
    assert.equal((await f.call("status")).mode, "staging");
    assert.equal((await f.call("revoke", { principal_id: "owner-0" })).reason, "forbidden");
    const frozen = await f.call("freeze_recovery", { expected_epoch: 0 });
    const page = await f.call("export_recovery", {
      epoch: frozen.epoch,
      watermark: frozen.watermark,
      table: 1,
      after: 0,
    });
    const rows = page.rows as { values: { value: string } }[];
    assert.deepEqual(JSON.parse(rows[0].values.value).principals, principals);
  } finally {
    await f.close();
  }
});

test("reauthorization receipt and single-use fence survive process reconstruction and current-state export", async () => {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-reauthorization-"));
  const principals = [
    { ...migration, expiresAt: Date.now() - 1000 },
    {
      id: "owner",
      role: "owner",
      hosts: ["fixture"],
      tokenSha256: hash("fixture-owner"),
      expiresAt: Date.now() + 7200000,
    },
  ];
  let f = await fixture(principals, undefined, dir);
  try {
    const c = await f.call(
      "migration_reauthorization_challenge",
      { principal_id: "migration" },
      "fixture-owner",
    );
    const input = {
      principal_id: "migration",
      request_id: "restart-stable",
      expected_revision: c.revision,
      expected_principal_sha256: c.principal_sha256,
      previous_expires_at: c.previous_expires_at,
      expires_at: Date.now() + 3500000,
      approval_reference: "approved-once",
    };
    const receipt = await f.call("reauthorize_migration", input, "fixture-owner");
    assert.equal(receipt.kind, "migration_reauthorization");
    await f.close();
    f = await fixture(principals, undefined, dir);
    assert.deepEqual(
      await f.call(
        "migration_reauthorization_receipt",
        { principal_id: "migration", request_id: input.request_id },
        "fixture-owner",
      ),
      { committed: true, ...receipt },
    );
    assert.deepEqual(await f.call("reauthorize_migration", input, "fixture-owner"), receipt);
    assert.equal(
      (
        await f.call(
          "reauthorize_migration",
          { ...input, request_id: "different" },
          "fixture-owner",
        )
      ).reason,
      "idempotency_conflict",
    );
    const freeze = await f.call("freeze_recovery", { expected_epoch: 0 });
    assert.equal((freeze.counts as Record<string, number>).migration_reauthorizations, 1);
    const page = await f.call("export_recovery", {
      epoch: freeze.epoch,
      watermark: freeze.watermark,
      table: 20,
      after: 0,
    });
    const rows = page.rows as { table: string; values: { value: string } }[];
    assert.equal(rows[0].table, "migration_reauthorizations");
    assert.deepEqual(JSON.parse(rows[0].values.value), receipt);
  } finally {
    await f.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("one-time migration reauthorization changes only expiry, survives replay, and retains recovery-only permissions", async () => {
  const expired = { ...migration, expiresAt: Date.now() - 1000 };
  const owner = {
    id: "owner",
    role: "owner",
    hosts: ["fixture"],
    tokenSha256: hash("fixture-owner"),
    expiresAt: Date.now() + 7200000,
  };
  const f = await fixture([expired, owner]);
  try {
    const body = { principal_id: "migration", request_id: "stable-approval" };
    assert.equal((await f.call("status")).reason, "forbidden");
    const c = await f.call(
      "migration_reauthorization_challenge",
      { principal_id: "migration" },
      "fixture-owner",
    );
    const input = {
      ...body,
      expected_revision: c.revision,
      expected_principal_sha256: c.principal_sha256,
      previous_expires_at: c.previous_expires_at,
      expires_at: Date.now() + 3500000,
      approval_reference: "owner-explicit-approval",
    };
    assert.equal((await f.call("reauthorize_migration", input)).reason, "forbidden");
    assert.equal(
      (await f.call("reauthorize_migration", { ...input, expected_revision: 99 }, "fixture-owner"))
        .reason,
      "fenced",
    );
    assert.equal(
      (
        await f.call(
          "reauthorize_migration",
          { ...input, expected_principal_sha256: "f".repeat(64) },
          "fixture-owner",
        )
      ).reason,
      "fenced",
    );
    assert.equal(
      (
        await f.call(
          "reauthorize_migration",
          { ...input, expires_at: Date.now() + 3601000 },
          "fixture-owner",
        )
      ).reason,
      "invalid_request",
    );
    assert.equal(
      (await f.call("reauthorize_migration", { ...input, hosts: ["other"] }, "fixture-owner"))
        .reason,
      "invalid_request",
    );
    const r = await f.call("reauthorize_migration", input, "fixture-owner");
    assert.equal(r.revision, 2);
    assert.equal(r.expires_at, input.expires_at);
    assert.deepEqual(await f.call("reauthorize_migration", input, "fixture-owner"), r);
    assert.deepEqual(await f.call("migration_reauthorization_receipt", body, "fixture-owner"), {
      committed: true,
      ...r,
    });
    assert.equal(
      (
        await f.call(
          "reauthorize_migration",
          { ...input, request_id: "second-approval" },
          "fixture-owner",
        )
      ).reason,
      "idempotency_conflict",
    );
    assert.equal(
      (
        await f.call(
          "reauthorize_migration",
          { ...input, expires_at: input.expires_at + 1 },
          "fixture-owner",
        )
      ).reason,
      "idempotency_conflict",
    );
    assert.equal((await f.call("status")).mode, "staging");
    for (const op of [
      "reserve",
      "claim",
      "revoke",
      "reauthorize_migration",
      "future_admin_operation",
    ])
      assert.equal((await f.call(op, input)).reason, "forbidden");
    const frozen = await f.call("freeze_recovery", { expected_epoch: 0 });
    const page = await f.call("export_recovery", {
      epoch: frozen.epoch,
      watermark: frozen.watermark,
      table: 1,
      after: 0,
    });
    const rows = page.rows as { values: { value: string } }[];
    const persisted = JSON.parse(rows[0].values.value);
    assert.deepEqual(persisted, {
      revision: 2,
      fleet: "fixture",
      principals: [{ ...expired, expiresAt: input.expires_at }, owner],
    });
    assert.equal(
      (await f.call("revoke", { principal_id: "migration" }, "fixture-owner")).revoked,
      true,
    );
    assert.equal((await f.call("status")).reason, "forbidden");
    // Receipt read/replay cannot undo revocation or extend the immutable expiry.
    assert.deepEqual(await f.call("reauthorize_migration", input, "fixture-owner"), r);
    assert.equal((await f.call("status")).reason, "forbidden");
  } finally {
    await f.close();
  }
});

test("reauthorization refuses revoked target, wrong role, foreign hosts, expired owner and owner ceiling", async () => {
  for (const variant of ["revoked", "role", "hosts", "expired-owner", "ceiling"]) {
    const expired = {
      ...migration,
      expiresAt: Date.now() - 1000,
      ...(variant === "role" ? { role: "executor" } : {}),
      ...(variant === "hosts" ? { hosts: ["other"] } : {}),
    };
    const owner = {
      id: "owner",
      role: "owner",
      hosts: ["fixture"],
      tokenSha256: hash("fixture-owner"),
      expiresAt: Date.now() + (variant === "expired-owner" ? -1000 : 600000),
    };
    const f = await fixture([expired, owner]);
    try {
      if (variant === "revoked")
        await f.call("revoke", { principal_id: "migration" }, "fixture-owner");
      const c = await f.call(
        "migration_reauthorization_challenge",
        { principal_id: "migration" },
        "fixture-owner",
      );
      if (variant !== "ceiling") {
        assert.equal(c.reason, "forbidden", variant);
        continue;
      }
      assert.equal(c.maximum_expires_at, owner.expiresAt);
      assert.equal(
        (
          await f.call(
            "reauthorize_migration",
            {
              principal_id: "migration",
              request_id: "bounded",
              approval_reference: "owner-approved",
              expected_revision: c.revision,
              expected_principal_sha256: c.principal_sha256,
              previous_expires_at: c.previous_expires_at,
              expires_at: owner.expiresAt + 1,
            },
            "fixture-owner",
          )
        ).reason,
        "invalid_request",
      );
    } finally {
      await f.close();
    }
  }
});

test("competing approvals commit once; owner revocation and policy drift stop a prepared update", async () => {
  const expired = { ...migration, expiresAt: Date.now() - 1000 };
  const owner = {
    id: "owner",
    role: "owner",
    hosts: ["fixture"],
    tokenSha256: hash("fixture-owner"),
    expiresAt: Date.now() + 7200000,
  };
  const f = await fixture([expired, owner]);
  try {
    const c = await f.call(
      "migration_reauthorization_challenge",
      { principal_id: "migration" },
      "fixture-owner",
    );
    const input = {
      principal_id: "migration",
      request_id: "competing-a",
      expected_revision: c.revision,
      expected_principal_sha256: c.principal_sha256,
      previous_expires_at: c.previous_expires_at,
      expires_at: Date.now() + 3500000,
      approval_reference: "explicit-owner-approval",
    };
    const results = await Promise.all(
      [input, { ...input, request_id: "competing-b" }].map((p) =>
        f.call("reauthorize_migration", p, "fixture-owner"),
      ),
    );
    assert.equal(results.filter((r) => r.kind === "migration_reauthorization").length, 1);
    assert.equal(results.filter((r) => r.reason === "idempotency_conflict").length, 1);
    assert.equal(
      (await f.call("revoke", { principal_id: "owner" }, "fixture-owner")).revoked,
      true,
    );
    assert.equal(
      (
        await f.call(
          "migration_reauthorization_receipt",
          { principal_id: "migration", request_id: results.find((r) => r.kind)?.request_id },
          "fixture-owner",
        )
      ).reason,
      "forbidden",
    );
  } finally {
    await f.close();
  }
  const drift = await fixture([expired, owner]);
  try {
    const c = await drift.call(
      "migration_reauthorization_challenge",
      { principal_id: "migration" },
      "fixture-owner",
    );
    await drift.call(
      "tighten_policy",
      {
        expected_revision: 1,
        policy: { revision: 2, fleet: "fixture", principals: [{ ...expired, hosts: [] }, owner] },
      },
      "fixture-owner",
    );
    assert.equal(
      (
        await drift.call(
          "reauthorize_migration",
          {
            principal_id: "migration",
            request_id: "stale-policy",
            expected_revision: c.revision,
            expected_principal_sha256: c.principal_sha256,
            previous_expires_at: c.previous_expires_at,
            expires_at: Date.now() + 3500000,
            approval_reference: "explicit-owner-approval",
          },
          "fixture-owner",
        )
      ).reason,
      "fenced",
    );
  } finally {
    await drift.close();
  }
});
test("policy transport rejects malformed/truncated data and bounded decompression overflow in real workerd", async () => {
  const bad = [
    "gzip-base64-v1:not_base64",
    "gzip-base64-v1:" + Buffer.from("not gzip").toString("base64"),
    "gzip-base64-v1:" + gzipSync(Buffer.alloc(65537, 32)).toString("base64"),
  ];
  for (const value of bad) {
    assert.throws(() => decodePolicy(value));
    const f = await fixture([], value);
    try {
      assert.equal((await f.call("status")).reason, "configuration_required");
    } finally {
      await f.close();
    }
  }
  assert.throws(() => encodePolicy("x".repeat(65537)), /policy_transport_too_large/);
});
test("migration role permits recovery receipts/freeze/export but denies administration, native effects and future operations", async () => {
  const f = await fixture([
    migration,
    {
      ...migration,
      id: "expired",
      tokenSha256: hash("fixture-expired"),
      expiresAt: Date.now() - 1000,
    },
    {
      id: "owner",
      role: "owner",
      hosts: ["fixture"],
      tokenSha256: hash("fixture-owner"),
      expiresAt: Date.now() + 3600000,
    },
  ]);
  try {
    assert.equal((await f.call("status")).mode, "staging");
    for (const op of [
      "revoke",
      "tighten_policy",
      "reserve",
      "claim",
      "begin",
      "record_receipt",
      "edge_lease",
      "replica_apply",
      "observe",
      "outbox_claim",
      "import",
      "inventory",
      "future_admin_operation",
    ])
      assert.equal((await f.call(op, { principal_id: "owner" })).reason, "forbidden", op);
    assert.deepEqual(await f.call("activation_receipt", { activation_id: "fixture" }), {
      committed: false,
    });
    assert.deepEqual(await f.call("recovery_import_receipt", { import_id: "fixture" }), {
      committed: false,
    });
    assert.equal((await f.call("status", {}, "fixture-expired")).reason, "forbidden");
    const frozen = await f.call("freeze_recovery", { expected_epoch: 0 });
    assert.equal(frozen.epoch, 1);
    assert.deepEqual(await f.call("freeze_recovery", { expected_epoch: 0 }), frozen);
    const page = await f.call("export_recovery", {
      epoch: 1,
      watermark: frozen.watermark,
      table: 0,
      after: 0,
    });
    assert.equal(page.epoch, 1);
    assert.ok(Array.isArray(page.rows));
    assert.equal(
      (await f.call("revoke", { principal_id: "migration" }, "fixture-owner")).revoked,
      true,
    );
    assert.equal((await f.call("status")).reason, "forbidden");
    assert.equal((await f.call("status", {}, "fixture-owner")).commands, 0);
  } finally {
    await f.close();
  }
});
test("migration policy cannot carry native scopes, execution custody or a nonzero budget", async () => {
  const variants = [
    { maxPerDay: 1 },
    { stateCustodian: true },
    { migrationAuthority: false },
    {
      scopes: [
        {
          project: "p",
          provider: "codex",
          run: null,
          grant: "g",
          revision: 1,
          expires: Date.now() + 300000,
        },
      ],
    },
    {
      nativeGrants: [
        {
          host: "fixture",
          purpose: "command",
          grant: "a".repeat(64),
          revision: 1,
          expires: Date.now() + 300000,
          projects: null,
          providers: ["codex"],
        },
      ],
    },
    {
      threadBudgets: [
        { thread: "t", provider: "codex", maxPerDay: 1, expiresAt: Date.now() + 300000 },
      ],
    },
  ];
  for (const change of variants) {
    const f = await fixture([{ ...migration, ...change }]);
    try {
      assert.equal((await f.call("status")).reason, "configuration_required");
    } finally {
      await f.close();
    }
  }
});
