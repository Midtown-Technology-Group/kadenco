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
    const service = new FleetState(state, {
      ...env,
      AUTH_POLICY: JSON.stringify(configured),
    });
    const response = await service.fetch(
      new Request("https://fixture.invalid/" + op, {
        method: "POST",
        headers: {
          authorization: "Bearer " + token,
          "content-type": "application/json",
        },
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
      // Created lazily by the first service operation.
      if (
        state.storage.sql
          .exec("SELECT name FROM sqlite_master WHERE name='subscriptions'")
          .toArray().length
      )
        state.storage.sql.exec("DELETE FROM subscriptions");
      state.storage.sql.exec("INSERT OR REPLACE INTO control VALUES(1,7,'active',NULL)");
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
      (
        await call("renew_configured_policy", {
          ...input(),
          expected_revision: 4,
        })
      ).body.reason,
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
        p.principals.push({
          ...p.principals[0]!,
          id: "extra",
          tokenSha256: sha("extra"),
        });
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
        // Successor kept beside the fingerprint it replaces.
        p.principals[0]!.nativeGrants!.push(grant("local", "command", "a", later));
      },
      (p) => {
        // The initiating owner expires itself.
        p.principals[0]!.expiresAt = 1;
        p.principals[0]!.nativeGrants = [];
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
  it("never extends a grant whose principal expiry is unchanged", async () => {
    // A grant shorter than its principal cannot be stretched to the principal's
    // expiry unless the principal itself is being renewed.
    const short = structuredClone(old);
    short.principals[0]!.nativeGrants![1]!.expires = soon - day / 2;
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(short));
    });
    const stretched = structuredClone(short);
    stretched.revision++;
    stretched.principals[0]!.nativeGrants![1]!.expires = soon;
    expect((await call("renew_configured_policy", input(stretched), stretched)).body.reason).toBe(
      "forbidden",
    );
    const renewed = structuredClone(stretched);
    renewed.principals[0]!.expiresAt = later;
    expect((await call("renew_configured_policy", input(renewed), renewed)).body.committed).toBe(
      true,
    );
  });
  it("moves tracking subscriptions to the renewed grant inside the renewal", async () => {
    const binding = (g: string, expires: number) => ({
      project: "__authorized_host_observation__",
      provider: "__observation__",
      run: null,
      grant: g.repeat(64),
      revision: 1,
      expires,
    });
    const subscription = (id: string, b: object, configured: ControlPolicy) =>
      call(
        "subscribe_central",
        {
          epoch: 7,
          id,
          host: "remote",
          thread_id: "thread",
          binding: b,
          expires: null,
          name: "t3.thread.activity",
          callback_reference: id,
        },
        configured,
      );
    const rows = () =>
      runInDurableObject(stub(), (_obj, state) =>
        Object.fromEntries(
          state.storage.sql
            .exec<{ id: string; binding: string; value: string }>(
              "SELECT id,binding,value FROM subscriptions",
            )
            .toArray()
            .map((r) => [r.id, { binding: JSON.parse(r.binding), value: JSON.parse(r.value) }]),
        ),
      );
    const renewal = structuredClone(old);
    renewal.revision++;
    for (const a of renewal.principals.slice(0, 2)) {
      a.nativeGrants = [
        grant("local", "command", "c", later),
        grant("remote", "observation", "d", later),
      ];
      a.expiresAt = later;
    }
    // One binding tracks the grant (as the edge derives it); one ends earlier;
    // one tracks it but the subscription itself has already ended.
    expect((await subscription("tracking", binding("b", soon), old)).body.stored).toBe(true);
    expect((await subscription("shorter", binding("b", soon - 1000), old)).body.stored).toBe(true);
    expect((await subscription("ended", binding("b", soon), old)).body.stored).toBe(true);
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE subscriptions SET expires=? WHERE id='ended'", Date.now() - 1);
    });
    const before = await rows();
    const r = await call("renew_configured_policy", input(renewal), renewal);
    expect(r.body).toMatchObject({ committed: true, rebound_subscriptions: 1 });
    const after = await rows();
    expect(after.tracking!.binding).toEqual(binding("d", later));
    expect(after.tracking!.value).toEqual({
      ...before.tracking!.value,
      binding: binding("d", later),
    });
    expect(after.shorter).toEqual(before.shorter);
    expect(after.ended).toEqual(before.ended);
    // The restarted edge resubmits exactly the stored subscription: no conflict.
    expect((await subscription("tracking", binding("d", later), renewal)).body).toMatchObject({
      id: "tracking",
      stored: true,
    });
    // The replaced fingerprint no longer authorizes anything.
    expect((await subscription("tracking", binding("b", soon), renewal)).body.reason).toBe(
      "forbidden",
    );
  });
  it("matches each renewed grant to its own predecessor's scope and expiry", async () => {
    const scoped = (g: string, project: string, expires: number) => ({
      ...grant("remote", "observation", g, expires),
      projects: [project],
    });
    const two = structuredClone(old);
    two.principals[0]!.nativeGrants = [
      grant("local", "command", "a"),
      scoped("b", "x", soon - day / 2),
      scoped("e", "y", soon),
    ];
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(two));
    });
    // Keep A for x, add A' for x borrowing B's later expiry, drop B.
    const borrowed = structuredClone(two);
    borrowed.revision++;
    borrowed.principals[0]!.nativeGrants = [
      grant("local", "command", "a"),
      scoped("b", "x", soon - day / 2),
      scoped("f", "x", soon),
    ];
    expect((await call("renew_configured_policy", input(borrowed), borrowed)).body.reason).toBe(
      "forbidden",
    );
    // A retained fingerprint cannot take another grant's scope and expiry while
    // a new fingerprint takes its place: prior b={x} until T1 and e={x,y} until
    // T2; proposed b={x,y} until T2 (matches e) plus f={x} until T1 (matches b).
    const three = structuredClone(old);
    three.principals[0]!.nativeGrants = [
      grant("local", "command", "a"),
      scoped("b", "x", soon - day / 2),
      { ...scoped("e", "x", soon), projects: ["x", "y"] },
    ];
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(three));
    });
    const swapped = structuredClone(three);
    swapped.revision++;
    swapped.principals[0]!.nativeGrants = [
      grant("local", "command", "a"),
      { ...scoped("b", "x", soon), projects: ["x", "y"] },
      scoped("f", "x", soon - day / 2),
    ];
    expect((await call("renew_configured_policy", input(swapped), swapped)).body.reason).toBe(
      "forbidden",
    );
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(two));
    });
    // Each successor matched to its own predecessor is accepted.
    const replaced = structuredClone(two);
    replaced.revision++;
    replaced.principals[0]!.nativeGrants = [
      grant("local", "command", "c"),
      scoped("f", "x", soon - day / 2),
      scoped("9", "y", soon),
    ];
    expect((await call("renew_configured_policy", input(replaced), replaced)).body.committed).toBe(
      true,
    );
  });
  it("never extends a thread budget, even with the principal expiry unchanged", async () => {
    const budgeted = structuredClone(old);
    budgeted.principals[0]!.threadBudgets = [
      {
        thread: "t",
        provider: "codex",
        maxPerDay: 2,
        expiresAt: Date.now() + 3600000,
      },
    ];
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(budgeted));
    });
    const extended = structuredClone(budgeted);
    extended.revision++;
    extended.principals[0]!.threadBudgets![0]!.expiresAt += day;
    expect((await call("renew_configured_policy", input(extended), extended)).body.reason).toBe(
      "forbidden",
    );
    const kept = structuredClone(budgeted);
    kept.revision++;
    kept.principals[0]!.threadBudgets![0]!.maxPerDay = 1;
    expect((await call("renew_configured_policy", input(kept), kept)).body.committed).toBe(true);
  });
  it("never revives an expired principal, even through another owner", async () => {
    const tightened = structuredClone(old);
    tightened.principals.push({
      ...structuredClone(old.principals[0]!),
      id: "owner2",
      tokenSha256: sha("synthetic-owner2"),
      expiresAt: Date.now() - 1000,
      nativeGrants: [grant("remote", "observation", "b", Date.now() - 1000)],
      hosts: ["remote"],
    });
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec(
        "UPDATE auth_policy SET value=? WHERE id=1",
        JSON.stringify(tightened),
      );
    });
    const revived = structuredClone(tightened);
    revived.revision++;
    revived.principals[3]!.expiresAt = later;
    revived.principals[3]!.nativeGrants = [grant("remote", "observation", "b", later)];
    expect((await call("renew_configured_policy", input(revived), revived)).body.reason).toBe(
      "forbidden",
    );
  });
  it("never revives an expired grant of a live principal", async () => {
    const tightened = structuredClone(old);
    tightened.principals[0]!.nativeGrants![1]!.expires = Date.now() - 1000;
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec(
        "UPDATE auth_policy SET value=? WHERE id=1",
        JSON.stringify(tightened),
      );
    });
    const revived = structuredClone(tightened);
    revived.revision++;
    revived.principals[0]!.expiresAt = later;
    revived.principals[0]!.nativeGrants![1]!.expires = later;
    expect((await call("renew_configured_policy", input(revived), revived)).body.reason).toBe(
      "forbidden",
    );
  });
  it("never makes a fenced stored binding usable again", async () => {
    const observation = (g: string, expires: number) => ({
      project: "__authorized_host_observation__",
      provider: "__observation__",
      run: null,
      grant: g.repeat(64),
      revision: 1,
      expires,
    });
    const subscribe = (id: string, b: object, configured: ControlPolicy) =>
      call(
        "subscribe_central",
        {
          epoch: 7,
          id,
          host: "remote",
          thread_id: "thread",
          binding: b,
          expires: null,
          name: "t3.thread.activity",
          callback_reference: id,
        },
        configured,
      );
    expect((await subscribe("fenced", observation("b", soon), old)).body.stored).toBe(true);
    // Tightening leaves the grant live but ends it before the stored binding.
    const tightened = structuredClone(old);
    tightened.principals[0]!.nativeGrants![1]!.expires = soon - day / 2;
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec(
        "UPDATE auth_policy SET value=? WHERE id=1",
        JSON.stringify(tightened),
      );
    });
    const extended = structuredClone(tightened);
    extended.revision++;
    extended.principals[0]!.expiresAt = later;
    extended.principals[0]!.nativeGrants![1]!.expires = later;
    expect((await call("renew_configured_policy", input(extended), extended)).body.reason).toBe(
      "forbidden",
    );
    // A retired fingerprint cannot come back: renew b -> d, then try d -> b.
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(old));
      state.storage.sql.exec("DELETE FROM subscriptions");
    });
    expect((await subscribe("tracking", observation("b", soon), old)).body.stored).toBe(true);
    expect((await subscribe("left", observation("b", soon - 1000), old)).body.stored).toBe(true);
    const moved = structuredClone(old);
    moved.revision++;
    for (const a of moved.principals.slice(0, 2)) {
      a.nativeGrants = [grant("local", "command", "a"), grant("remote", "observation", "d", later)];
      a.expiresAt = later;
    }
    expect((await call("renew_configured_policy", input(moved), moved)).body.committed).toBe(true);
    const back = structuredClone(moved);
    back.revision++;
    for (const a of back.principals.slice(0, 2))
      a.nativeGrants = [grant("local", "command", "a"), grant("remote", "observation", "b", later)];
    expect(
      (
        await call(
          "renew_configured_policy",
          {
            request_id: "rollback-request",
            expected_revision: 4,
            expected_policy_sha256: enrollmentPolicyDigest(back),
          },
          back,
        )
      ).body.reason,
    ).toBe("forbidden");
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
    // Staging may hold an uploaded recovery import whose commit compares policies.
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE control SET mode='staging' WHERE id=1");
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
    // The same ID under another credential cannot read the receipt either.
    const reused = structuredClone(renewal);
    reused.principals[0]!.tokenSha256 = sha("synthetic-owner-reissued");
    await runInDurableObject(stub(), (_obj, state) => {
      state.storage.sql.exec("UPDATE auth_policy SET value=? WHERE id=1", JSON.stringify(reused));
    });
    expect(
      (
        await call(
          "policy_renewal_receipt",
          { request_id: request },
          reused,
          "synthetic-owner-reissued",
        )
      ).body.reason,
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
