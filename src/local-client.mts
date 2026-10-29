// SPDX-License-Identifier: AGPL-3.0-or-later
import { openSync, closeSync, fstatSync, readSync, constants } from "node:fs";
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
      let descriptor;
      try {
        // Inspect/read the same opened object. Nonblocking/no-follow flags are
        // used where supported; neither a swapped path nor file growth may
        // bypass freshness/size checks. Native authentication remains required.
        descriptor = openSync(
          config.tokenFile,
          constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
        );
        const stat = fstatSync(descriptor, { bigint: true }),
          at = now(),
          age = at - Number(stat.mtimeMs);
        if (!stat.isFile() || stat.size > 16384n || age < -60000 || age > 1200000)
          throw new Error();
        const bytes = Buffer.alloc(Number(stat.size) + 1),
          count = readSync(descriptor, bytes, 0, bytes.length, 0);
        const after = fstatSync(descriptor, { bigint: true });
        if (
          count > 16384 ||
          BigInt(count) !== stat.size ||
          after.size !== stat.size ||
          after.mtimeNs !== stat.mtimeNs ||
          after.ctimeNs !== stat.ctimeNs
        )
          throw new Error();
        const token = bytes.toString("utf8", 0, count).trim();
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
      } finally {
        if (descriptor !== undefined) closeSync(descriptor);
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
    preflight: (...args: Parameters<typeof native.preflight>) => native.preflight(...args),
    followup: (...args: Parameters<typeof native.followup>) => native.followup(...args),
    close: async () => {
      try {
        await native.close();
      } finally {
        await source.close();
      }
    },
  };
}
