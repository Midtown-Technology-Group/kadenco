// SPDX-License-Identifier: AGPL-3.0-or-later
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { FleetState } from "../src/worker";
import { enrollmentPolicyDigest, type ControlPolicy } from "../src/owner-enrollment";
import { MAX_RENEWAL_MS } from "../src/policy-renewal";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const day = 86400000;
// Expiries are relative to the real clock: renewal bounds are measured from now.
const soon = Date.now() + day;
const later = Date.now() + 30 * day;
const grant = (host: string, purpose: "command" | "observation", g: string, expires = soon) => ({
  host,
  purpose,
  grant: g.repeat(64),
  revision: 1,
  expires,
  projects: null,
  providers: purpose === "command" ? ["codex", "opencode"] : null,
});
const old: ControlPolicy = {
  revision: 3,
  fleet: "test-fleet",
  principals: [
    {
      id: "owner",
      role: "owner",
      hosts: ["local", "remote"],
      nativeGrants: [grant("local", "command", "a"), grant("remote", "observation", "b")],
      scopes: [],
      maxPerDay: null,
      expiresAt: soon,
      tokenSha256: sha("synthetic-owner"),
    },
    {
      id: "executor",
      role: "executor",
      stateCustodian: true,
      hosts: ["local", "remote"],
      nativeGrants: [grant("local", "command", "a"), grant("remote", "observation", "b")],
      scopes: [],
      expiresAt: soon,
      tokenSha256: sha("synthetic-executor"),
    },
    {
      id: "migration",
      role: "migration",
      migrationAuthority: true,
      hosts: ["local"],
      maxPerDay: 0,
      expiresAt: 1,
      tokenSha256: sha("synthetic-migration"),
    },
  ],
};
/** The renewal an operator would deploy: a changed route for the local command
 * grant (new fingerprint), a dropped host, later owner/executor expiry. */
function next(): ControlPolicy {
  const p = structuredClone(old);
  p.revision++;
  for (const a of p.principals.slice(0, 2)) {
    a.hosts = ["local"];
    a.nativeGrants = [grant("local", "command", "c", later)];
    a.expiresAt = later;
  }
  return p;
}
const stub = () => env.FLEETS.getByName("policy-renewal-tests");
const request = "3b0f6c2e-5d0a-4a5e-9f43-2b7f1c0e8a11";
const input = (p = next()) => ({
  request_id: request,
  expected_revision: 3,
  expected_policy_sha256: enrollmentPolicyDigest(p),
});
async function call(op: string, body: object, configured = next(), token = "synthetic-owner") {
  return runInDurableObject(stub(), async (_obj, state) => {
    const service = new FleetState(state, { ...env, AUTH_POLICY: JSON.stringify(configured) });
    const response = await service.fetch(
      new Request("https://fixture.invalid/" + op, {
        method: "POST",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        body: JSON.stringify(body),
      }),
    );
    return { status: response.status, body: (await response.json()) as any };
  });
}
async function stored() {
  return runInDurableObject(stub(), (_obj, state) => ({
    policy: JSON.parse(
      state.storage.sql.exec<{ value: string }>("SELECT value FROM auth_policy WHERE id=1").one()
        .value,
    ),
    audits: state.storage.sql
      .exec<{ actor: string; subject: string }>(
        "SELECT actor,subject FROM audit WHERE action='renew_configured_policy'",
      )
      .toArray(),
  }));
}
describe("authenticated operator policy renewal", () => {
  beforeEach(async () => {
    await runInDurableObject(stub(), (_obj, state) => {
      new FleetState(state, env);
      state.storage.sql.exec(
        "DELETE FROM auth_policy; DELETE FROM audit; DELETE FROM revoked; DELETE FROM commands;",
      );
      state.storage.sql.exec("UPDATE control SET mode='staging' WHERE id=1");
      state.storage.sql.exec("INSERT INTO auth_policy VALUES(1,?)", JSON.stringify(old));
    });
  });
  it("challenge returns the exact current policy and both digests to owners only", async () => {
    expect((await call("policy_renewal_challenge", {})).body).toEqual({
      revision: 3,
      current_policy_sha256: enrollmentPolicyDigest(old),
      configured_revision: 4,
      configured_policy_sha256: enrollmentPolicyDigest(next()),
      current_policy: old,
    });
    expect(
      (await call("policy_renewal_challenge", {}, next(), "synthetic-executor")).body.reason,
    ).toBe("forbidden");
    expect((await call("policy_renewal_challenge", { extra: 1 })).body.reason).toBe(
      "invalid_request",
    );
  });
  it("adopts the configured renewal atomically and reconciles duplicate/lost responses", async () => {
    const results = await Promise.all([
      call("renew_configured_policy", input()),
      call("renew_configured_policy", input()),
    ]);
    expect(results[0]).toEqual(results[1]);
    expect(results[0]!.body).toMatchObject({
      committed: true,
      revision: 4,
      policy_sha256: enrollmentPolicyDigest(next()),
      previous_policy_sha256: enrollmentPolicyDigest(old),
    });
    expect((await call("policy_renewal_receipt", { request_id: request })).body).toEqual(
      results[0]!.body,
    );
    const s = await stored();
    expect(s.policy).toEqual(next());
    expect(s.audits).toHaveLength(1);
    expect(s.audits[0]!.actor).toBe("owner");
    expect(s.audits[0]!.subject).not.toContain("synthetic-");
    expect(
      (await call("renew_configured_policy", { ...input(), expected_revision: 4 })).body.reason,
    ).toBe("idempotency_conflict");
    // Renewed principals keep authenticating after their old expiry would have passed.
    expect((await call("status", {}, next(), "synthetic-executor")).status).toBe(200);
  });
  it("fences stale intent: revision, configured revision and digest", async () => {
    const skipped = next();
    skipped.revision = 5;
    for (const [body, configured] of [
      [{ ...input(), expected_revision: 2 }, next()],
      [input(skipped), skipped],
      [{ ...input(), expected_policy_sha256: "c".repeat(64) }, next()],
      [input(), old],
    ] as const)
      expect((await call("renew_configured_policy", body, configured)).body.reason).toBe("fenced");
    expect((await stored()).policy).toEqual(old);
    expect((await stored()).audits).toHaveLength(0);
  });
  it("refuses any widening, identity change or new principal without partial writes", async () => {
    const changes: ((p: ControlPolicy) => void)[] = [
      (p) => {
        p.fleet = "other-fleet";
      },
      (p) => {
        p.principals.push({ ...p.principals[0]!, id: "extra", tokenSha256: sha("extra") });
      },
      (p) => {
        p.principals[0]!.tokenSha256 = sha("changed");
      },
      (p) => {
        p.principals[0]!.role = "executor";
      },
      (p) => {
        p.principals[0]!.hosts.push("other");
      },
      (p) => {
        p.principals[0]!.hosts.push("other");
        p.principals[0]!.nativeGrants!.push(grant("other", "observation", "d", later));
      },
      (p) => {
        // An existing host with a purpose it never had.
        p.principals[0]!.hosts.push("remote");
        p.principals[0]!.nativeGrants!.push(grant("remote", "command", "d", later));
      },
      (p) => {
        p.principals[0]!.nativeGrants![0]!.providers = ["codex", "opencode", "pi"];
      },
      (p) => {
        p.principals[0]!.nativeGrants![0]!.expires = later + 1;
      },
      (p) => {
        p.principals[0]!.scopes = [
          {
            project: "p",
            provider: "codex",
            run: null,
            grant: "e".repeat(64),
            revision: 1,
            expires: later,
          },
        ];
      },
      (p) => {
        p.principals[1]!.maxPerDay = 5;
      },
      (p) => {
        p.principals[0]!.stateCustodian = true;
      },
      (p) => {
        p.principals[0]!.migrationAuthority = true;
      },
      (p) => {
        p.principals[2]!.expiresAt = later;
      },
      (p) => {
        p.principals[0]!.expiresAt = Date.now() + MAX_RENEWAL_MS + day;
      },
      (p) => {
        p.principals[0]!.threadBudgets = [
          { thread: "t", provider: "codex", maxPerDay: 1, expiresAt: later },
        ];
      },
    ];
    for (const change of changes) {
      const p = next();
      change(p);
      const r = await call("renew_configured_policy", input(p), p);
      expect(r.status, JSON.stringify(p)).not.toBe(200);
      expect((await stored()).policy).toEqual(old);
    }
    expect((await stored()).audits).toHaveLength(0);
  });
  it("permits dropping principals and keeping or shortening expiries", async () => {
    const p = next();
    p.principals.pop();
    p.principals[1]!.expiresAt = soon - 1000;
    p.principals[1]!.nativeGrants![0]!.expires = soon - 1000;
    expect((await call("renew_configured_policy", input(p), p)).body.committed).toBe(true);
    expect((await stored()).policy).toEqual(p);
  });
  it("refuses non-owners, revoked extensions and a quiesced recovery", async () => {
    expect(
      (await call("renew_configured_policy", input(), next(), "synthetic-executor")).body.reason,
    ).toBe("forbidden");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("INSERT INTO revoked VALUES('executor')");
    });
    expect((await call("renew_configured_policy", input())).body.reason).toBe("forbidden");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("DELETE FROM revoked");
      state.storage.sql.exec("UPDATE control SET mode='quiesced' WHERE id=1");
    });
    expect((await call("renew_configured_policy", input())).body.reason).toBe("fenced");
    expect((await stored()).policy).toEqual(old);
    expect((await stored()).audits).toHaveLength(0);
  });
  it("never turns a receipt lookup into renewal or lets another owner take a request identity", async () => {
    expect((await call("policy_renewal_receipt", { request_id: request })).body).toEqual({
      committed: false,
    });
    expect((await stored()).policy).toEqual(old);
    const second = structuredClone(old);
    second.principals.push({
      ...structuredClone(old.principals[0]!),
      id: "owner2",
      tokenSha256: sha("synthetic-owner2"),
    });
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(second));
    });
    const renewal = structuredClone(second);
    renewal.revision++;
    expect((await call("renew_configured_policy", input(renewal), renewal)).body.committed).toBe(
      true,
    );
    expect(
      (await call("policy_renewal_receipt", { request_id: request }, renewal, "synthetic-owner2"))
        .body.reason,
    ).toBe("forbidden");
  });
  it("tighten_policy still refuses an expiry extension", async () => {
    const p = structuredClone(old);
    p.revision++;
    p.principals[0]!.expiresAt = later;
    expect((await call("tighten_policy", { expected_revision: 3, policy: p })).body.reason).toBe(
      "forbidden",
    );
  });
});
