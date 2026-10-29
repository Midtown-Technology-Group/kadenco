// SPDX-License-Identifier: AGPL-3.0-or-later
import { startSidecar } from "./sidecar.mjs";
const sidecar = await startSidecar();
const shutdown = async () => {
  await sidecar.shutdown();
  process.exit(0);
};
process.once("SIGTERM", shutdown);
process.once("SIGINT", shutdown);
console.error("Kadenco 0.1.0-alpha.2 listening on loopback; no model calls in event worker");
