// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
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
async function fixture(principals: unknown[]) {
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: readFileSync(new URL("../dist/worker.js", import.meta.url), "utf8"),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      bindings: { AUTH_POLICY: JSON.stringify({ revision: 1, fleet: "fixture", principals }) },
    }),
  );
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
