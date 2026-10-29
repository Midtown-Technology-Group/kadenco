// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, statSync } from "node:fs";
import { fleetBackend } from "./backend.mjs";

// Consume the operator's EXISTING refresher output. Never issue, refresh, copy,
// persist or log a credential. The T3 server authenticates the bearer itself.
export function localClientOptions(config, now = Date.now, scope = "operate", host = "local") {
  if (!["read", "operate"].includes(scope)) throw new Error("invalid_local_scope");
  const u = new URL(config.origin);
  if (
    u.protocol !== "http:" ||
    u.hostname !== "127.0.0.1" ||
    !u.port ||
    u.pathname !== "/" ||
    u.search ||
    u.hash ||
    u.username ||
    u.password
  )
    throw new Error("local_client_origin_denied");
  const base = u.origin;
  return {
    hostsProvider: () => ({ hosts: [{ name: host, url: base + "/mcp" }] }),
    cacheProvider: () => {
      try {
        const stat = statSync(config.tokenFile),
          at = now(),
          age = at - stat.mtimeMs;
        if (!stat.isFile() || stat.size > 16384 || age < -60000 || age > 1200000) throw new Error();
        const token = readFileSync(config.tokenFile, "utf8").trim();
        if (token.length < 100 || /\s/.test(token) || token.split(".").length !== 2)
          throw new Error();
        const claims = JSON.parse(Buffer.from(token.split(".")[0], "base64url").toString());
        if (
          claims.sub !== "mcp-client" ||
          !Number.isFinite(claims.exp) ||
          claims.exp <= at + 30000 ||
          !Array.isArray(claims.scopes) ||
          !(
            scope === "read"
              ? ["orchestration:read"]
              : ["orchestration:read", "orchestration:operate"]
          ).every((s) => claims.scopes.includes(s))
        )
          throw new Error();
        return {
          [host + "|mcp-client|existing-file|" + base]: {
            host,
            base,
            token,
            scopes: claims.scopes,
            access: "approval-required",
            expiresAt: claims.exp,
          },
        };
      } catch {
        throw new Error("existing_local_credential_unavailable_or_stale");
      }
    },
  };
}

export async function withLocalFollowup(source, helperPath, config) {
  const native = await fleetBackend(helperPath, localClientOptions(config));
  return {
    ...source,
    supportsFollowup: true,
    read: (session, activity = false, options = {}) =>
      activity ? native.read(session, true, options) : source.read(session, false, options),
    preflight: (...args) => native.preflight(...args),
    followup: (...args) => native.followup(...args),
    close: async () => {
      await native.close();
      await source.close();
    },
  };
}
