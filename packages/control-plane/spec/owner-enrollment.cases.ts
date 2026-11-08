// SPDX-License-Identifier: AGPL-3.0-or-later
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { FleetState } from "../src/worker";
import { enrollmentPolicyDigest, type ControlPolicy } from "../src/owner-enrollment";
const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const scope = {
  host: "local",
  purpose: "command" as const,
  grant: "a".repeat(64),
  revision: 1,
  expires: 4102444800000,
  projects: null,
  providers: ["codex"],
};
const old: ControlPolicy = {
  revision: 1,
  fleet: "test-fleet",
  principals: [
    {
      id: "owner",
      role: "owner",
      migrationAuthority: true,
      hosts: ["local"],
      nativeGrants: [scope],
      scopes: [],
      maxPerDay: 3,
      expiresAt: 4102444800000,
      tokenSha256: sha("synthetic-owner"),
    },
    {
      id: "executor",
      role: "executor",
      hosts: ["local"],
      nativeGrants: [scope],
      expiresAt: 4102444800000,
      tokenSha256: sha("synthetic-executor"),
    },
  ],
};
function next(): ControlPolicy {
  const p = structuredClone(old),
    target = {
      ...structuredClone(old.principals[0]!),
      id: "grok",
      migrationAuthority: false,
      tokenSha256: sha("synthetic-grok"),
      nativeGrants: [{ ...scope, grant: "b".repeat(64) }],
    };
  p.revision++;
  p.principals.push(target);
  p.principals[1]!.nativeGrants!.push(...target.nativeGrants);
  return p;
}
const stub = () => env.FLEETS.getByName("owner-enrollment-tests");
const request = "266a91b0-fb38-4c88-b89c-87951f322d44";
const input = (p = next()) => ({
  request_id: request,
  principal_id: "grok",
  executor_id: "executor",
  expected_revision: 1,
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
        "SELECT actor,subject FROM audit WHERE action='enroll_configured_owner'",
      )
      .toArray(),
    commands: state.storage.sql.exec<{ n: number }>("SELECT count(*) n FROM commands").one().n,
  }));
}
describe("authenticated operator owner enrollment", () => {
  beforeEach(async () => {
    await runInDurableObject(stub(), (_obj, state) => {
      new FleetState(state, env);
      state.storage.sql.exec(
        "DELETE FROM auth_policy; DELETE FROM audit; DELETE FROM revoked; DELETE FROM commands;",
      );
      state.storage.sql.exec("INSERT INTO auth_policy VALUES(1,?)", JSON.stringify(old));
    });
  });
  it("admits a distinct principal atomically, preserves sponsor and reconciles duplicate/lost responses", async () => {
    const results = await Promise.all([
      call("enroll_configured_owner", input()),
      call("enroll_configured_owner", input()),
    ]);
    expect(results[0]).toEqual(results[1]);
    expect(results[0]!.body).toMatchObject({ committed: true, principal_id: "grok", revision: 2 });
    expect((await call("owner_enrollment_receipt", { request_id: request })).body).toEqual(
      results[0]!.body,
    );
    const s = await stored();
    expect(s.policy).toEqual(next());
    expect(s.audits).toHaveLength(1);
    expect(s.commands).toBe(0);
    expect(s.audits[0]!.subject).not.toContain("synthetic-");
    expect((await call("status", {}, next(), "synthetic-grok")).status).toBe(200);
    expect(
      (await call("enroll_configured_owner", { ...input(), principal_id: "different" })).body
        .reason,
    ).toBe("idempotency_conflict");
  });
  it("requires operator configuration and rejects caller policy, fake role, executor and unadmitted credential", async () => {
    for (const [body, configured, token] of [
      [input(), old, "synthetic-owner"],
      [input(), next(), "synthetic-executor"],
      [{ ...input(), policy: next() }, next(), "synthetic-owner"],
      [{ ...input(), role: "owner" }, next(), "synthetic-owner"],
      [input(), next(), "synthetic-grok"],
    ] as const)
      expect((await call("enroll_configured_owner", body, configured, token)).status).not.toBe(200);
    expect((await stored()).policy).toEqual(old);
    expect((await stored()).audits).toHaveLength(0);
  });
  it("rejects scope/admin/budget/expiry expansion, changed old identities and extra principals without partial writes", async () => {
    const changes: ((p: ControlPolicy) => void)[] = [
      (p) => {
        p.principals[2]!.hosts.push("other");
      },
      (p) => {
        p.principals[2]!.maxPerDay = null;
      },
      (p) => {
        p.principals[2]!.migrationAuthority = true;
      },
      (p) => {
        p.principals[2]!.stateCustodian = true;
      },
      (p) => {
        p.principals[2]!.expiresAt++;
      },
      (p) => {
        p.principals[2]!.expiresAt = 1;
      },
      (p) => {
        p.principals[0]!.tokenSha256 = sha("changed");
      },
      (p) => {
        p.principals[1]!.hosts.push("other");
      },
      (p) => {
        p.principals[1]!.nativeGrants = [];
      },
      (p) => {
        p.principals.push({ ...p.principals[2]!, id: "extra", tokenSha256: sha("extra") });
      },
    ];
    for (const change of changes) {
      const p = next();
      change(p);
      expect((await call("enroll_configured_owner", input(p), p)).status).not.toBe(200);
      expect((await stored()).policy).toEqual(old);
    }
  });
  it("rechecks live revocation/expiry and fences stale policy intent", async () => {
    expect((await call("owner_enrollment_challenge", {})).body).toEqual({
      revision: 1,
      current_policy_sha256: enrollmentPolicyDigest(old),
      configured_policy_sha256: enrollmentPolicyDigest(next()),
    });
    expect(
      (await call("owner_enrollment_challenge", {}, next(), "synthetic-executor")).body.reason,
    ).toBe("forbidden");
    expect(
      (
        await call("enroll_configured_owner", {
          ...input(),
          expected_policy_sha256: "c".repeat(64),
        })
      ).body.reason,
    ).toBe("fenced");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("INSERT INTO revoked VALUES('owner')");
    });
    expect((await call("enroll_configured_owner", input())).body.reason).toBe("forbidden");
    expect((await stored()).policy).toEqual(old);
  });
  it("permits a shorter expiry and preserves revocation across immutable receipt replay", async () => {
    const p = next();
    p.principals[2]!.expiresAt -= 1000;
    p.principals[2]!.nativeGrants![0]!.expires -= 1000;
    p.principals[1]!.nativeGrants![1]!.expires -= 1000;
    const r = await call("enroll_configured_owner", input(p), p);
    expect(r.status).toBe(200);
    await call("revoke", { principal_id: "grok" }, p);
    expect(await call("enroll_configured_owner", input(p), p)).toEqual(r);
    expect((await call("status", {}, p, "synthetic-grok")).body.reason).toBe("forbidden");
    expect((await stored()).audits).toHaveLength(1);
  });
  it("never turns a receipt lookup into enrollment or lets another owner take a request identity", async () => {
    expect((await call("owner_enrollment_receipt", { request_id: request })).body).toEqual({
      committed: false,
    });
    await call("enroll_configured_owner", input());
    expect(
      (await call("owner_enrollment_receipt", { request_id: request }, next(), "synthetic-grok"))
        .body.reason,
    ).toBe("forbidden");
    expect((await stored()).audits).toHaveLength(1);
  });
  it("refuses expired sponsors and revoked target/executor identities without changing policy", async () => {
    for (const id of ["grok", "executor"]) {
      await runInDurableObject(stub(), (_obj, state) => {
        state.storage.sql.exec("DELETE FROM revoked");
        state.storage.sql.exec("INSERT INTO revoked VALUES(?)", id);
      });
      expect((await call("enroll_configured_owner", input())).body.reason).toBe("forbidden");
      expect((await stored()).policy).toEqual(old);
    }
    const expired = structuredClone(old);
    expired.principals[0]!.expiresAt = 1;
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("DELETE FROM revoked");
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(expired));
    });
    expect((await call("enroll_configured_owner", input())).body.reason).toBe("forbidden");
    expect((await stored()).policy).toEqual(expired);
    expect((await stored()).audits).toHaveLength(0);
  });
});
