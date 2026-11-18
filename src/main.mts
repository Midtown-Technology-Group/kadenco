// SPDX-License-Identifier: AGPL-3.0-or-later
import { startSidecar } from "./sidecar.mjs";
import { buildIdentity } from "./status.mjs";
// Resolve the version before listening so the ready line follows immediately.
const version = buildIdentity().package_version ?? "unknown version";
const sidecar = await startSidecar();
const shutdown = async () => {
  await sidecar.shutdown();
  process.exit(0);
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
console.error(`Kadenco ${version} listening on loopback; no model calls in event worker`);
