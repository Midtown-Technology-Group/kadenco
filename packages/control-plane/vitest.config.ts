import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";
import { createHash } from "node:crypto";
const hash = (s: string) => createHash("sha256").update(s).digest("hex");
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          AUTH_POLICY: JSON.stringify({
            revision: 1,
            fleet: "test-fleet",
            principals: [
              {
                id: "owner2",
                role: "owner",
                maxPerDay: null,
                hosts: ["local"],
                scopes: [
                  {
                    project: "project",
                    provider: "provider",
                    run: "run",
                    grant: "grant",
                    revision: 1,
                    expires: 4102444800000,
                  },
                ],
                tokenSha256: hash("synthetic-owner2"),
                expiresAt: 4102444800000,
              },
              {
                id: "agent2",
                role: "executor",
                hosts: ["local"],
                scopes: [
                  {
                    project: "project",
                    provider: "provider",
                    run: "run",
                    grant: "grant",
                    revision: 1,
                    expires: 4102444800000,
                  },
                ],
                tokenSha256: hash("synthetic-agent2"),
                expiresAt: 4102444800000,
              },
              {
                id: "owner",
                role: "owner",
                maxPerDay: null,
                hosts: ["local"],
                scopes: [
                  {
                    project: "project",
                    provider: "provider",
                    run: "run",
                    grant: "grant",
                    revision: 1,
                    expires: 4102444800000,
                  },
                ],
                tokenSha256: hash("synthetic-owner"),
                expiresAt: 4102444800000,
              },
              {
                id: "agent",
                role: "executor",
                hosts: ["local"],
                scopes: [
                  {
                    project: "project",
                    provider: "provider",
                    run: "run",
                    grant: "grant",
                    revision: 1,
                    expires: 4102444800000,
                  },
                ],
                tokenSha256: hash("synthetic-agent"),
                expiresAt: 4102444800000,
              },
            ],
          }),
        },
      },
    }),
  ],
  test: { include: ["spec/**/*.cases.ts"] },
});
