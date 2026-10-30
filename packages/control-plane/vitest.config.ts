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
            fleet: "test-fleet",
            principals: [
              {
                id: "owner",
                role: "owner",
                hosts: ["local"],
                tokenSha256: hash("synthetic-owner"),
                expiresAt: 4102444800000,
              },
              {
                id: "agent",
                role: "executor",
                hosts: ["local"],
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
