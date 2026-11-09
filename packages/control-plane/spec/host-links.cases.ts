// SPDX-License-Identifier: AGPL-3.0-or-later
import { env } from "cloudflare:workers";
import { runInDurableObject } from "cloudflare:test";
import { it, expect } from "vitest";
import { hostLinkSchema, hostLinkOperation } from "../src/host-links.ts";
import type { ServicePrincipal } from "../src/services.ts";

it("actual DO SQL transactions admit different hosts independently and roll back failed admissions", async () => {
  const stub = env.FLEETS.getByName("host-links-isolated-fixture");
  const run = (host: string, connection: string, rollback = false) =>
    runInDurableObject(stub, (_o, state) => {
      hostLinkSchema(state.storage.sql);
      const actor: ServicePrincipal = {
        id: host,
        role: "executor",
        hosts: [host],
        expiresAt: 1e12,
      };
      return state.storage.transactionSync(() => {
        const result = hostLinkOperation(
          {
            sql: state.storage.sql,
            now: 1000,
            actorId: host,
            principal: () => actor,
            authorize: (a, h) => {
              if (!a.hosts.includes(h)) throw Error("forbidden");
            },
            reference: () => {
              throw Error("no_command_in_fixture");
            },
          },
          "link_open",
          { host, connection },
        );
        if (rollback) throw Error("fixture_rollback");
        return result;
      });
    });
  const [a, b] = await Promise.all([run("a", crypto.randomUUID()), run("b", crypto.randomUUID())]);
  expect(a).toMatchObject({ host: "a", generation: 1 });
  expect(b).toMatchObject({ host: "b", generation: 1 });
  const c = crypto.randomUUID();
  await expect(run("c", c, true)).rejects.toThrow("fixture_rollback");
  expect(await run("c", c)).toMatchObject({ host: "c", generation: 1 });
});
