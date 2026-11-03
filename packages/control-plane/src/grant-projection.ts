// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { Policy } from "../../../dist/config.mjs";
import { nativeGrantScope, type NativeGrantScope } from "./binding.ts";
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, canonical(v)]),
    );
  return value;
}
/** Project current ORIGINAL native permissions, not guessed inventory defaults.
 * observationExpiresAt is the separately approved central service ceiling; it
 * does not edit a subscription or introduce expiry into the original read grant.
 * Any authority/route change changes the fingerprint and fails existing mappings
 * closed until explicitly reconciled. No policy write or credential is created. */
export function projectNativeGrant(
  policy: Policy,
  owner: string,
  host: string,
  purpose: NativeGrantScope["purpose"],
  observationExpiresAt?: number,
  now = Date.now(),
): NativeGrantScope {
  const principal = policy.principals.find((p) => p.id === owner && p.enabled !== false);
  const readGrant = principal?.readHosts?.find((g) => g.host === host);
  const readRoute = policy.fleetRead?.hosts.find((r) => r.name === host);
  if (!principal || !readGrant || !readRoute) throw Error("grant_projection_forbidden");
  const command =
    purpose === "command" ? principal.commandHosts?.find((g) => g.host === host) : undefined;
  const nativeRoute =
    purpose === "command" ? policy.nativeDelivery?.hosts.find((r) => r.name === host) : undefined;
  if (purpose === "command" && (!command || !nativeRoute))
    throw Error("grant_projection_forbidden");
  const expires = purpose === "command" ? command!.expiresAt : observationExpiresAt;
  if (!Number.isSafeInteger(expires) || Number(expires) <= now)
    throw Error("grant_projection_expired_or_unbound");
  const projects = command?.projectIds
    ? command.projectIds.filter((p) => !readGrant.projectIds || readGrant.projectIds.includes(p))
    : (readGrant.projectIds ?? null);
  if (projects?.length === 0) throw Error("grant_projection_empty_scope");
  const grant = createHash("sha256")
    .update(
      JSON.stringify(
        canonical({
          version: 1,
          owner,
          host,
          purpose,
          readGrant,
          readRoute,
          ...(purpose === "command" ? { command, nativeRoute } : {}),
        }),
      ),
    )
    .digest("hex");
  return nativeGrantScope({
    host,
    purpose,
    grant,
    revision: 1,
    expires,
    projects,
    providers: purpose === "command" ? command!.providerInstanceIds : null,
  });
}
