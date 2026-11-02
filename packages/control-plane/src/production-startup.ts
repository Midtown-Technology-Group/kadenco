// SPDX-License-Identifier: AGPL-3.0-or-later
import { realpathSync } from "node:fs";
import { dirname, basename, isAbsolute, relative, sep } from "node:path";
import { timingSafeEqual } from "node:crypto";
import { startSidecar, type SidecarOptions } from "../../../dist/sidecar.mjs";
import type { Policy } from "../../../dist/config.mjs";
import { createProductionRuntime, type BootstrapConfig } from "./production-bootstrap.ts";

export type ProductionStartup = {
  configPath: string;
  historicalStateDirectory: string;
  cacheStateDirectory: string;
  stateKey: Buffer;
  bootstrap: BootstrapConfig;
  backendFactory?: SidecarOptions["backendFactory"];
};
const inside = (parent: string, child: string) => {
  const p = relative(parent, child);
  return p === "" || (!isAbsolute(p) && p !== ".." && !p.startsWith(".." + sep));
};
/** Resolve real directories, not textual aliases. A cache may not contain the
 * historical archive either: cleanup of one must not remove the other. */
export function cachePolicyGuard(historical: string, cache: string) {
  if (!isAbsolute(historical) || !isAbsolute(cache)) throw Error("absolute_state_paths_required");
  const archive = realpathSync(historical),
    target = realpathSync(cache);
  if (inside(archive, target) || inside(target, archive)) throw Error("historical_state_overlap");
  return (policy: Policy) => {
    // Re-resolve on every policy read to catch a changed path or directory alias.
    if (
      realpathSync(historical) !== archive ||
      realpathSync(cache) !== target ||
      realpathSync(policy.stateDirectory) !== target
    )
      throw Error("production_state_directory_changed");
  };
}

/** Supported operator startup. Does not write configuration, install signals,
 * create credentials, alter native routes or fall back to local delivery.
 * The service supervisor owns signals and awaits the returned shutdown handle. */
export async function startProductionSidecar(input: ProductionStartup) {
  if (
    !isAbsolute(input.configPath) ||
    !Buffer.isBuffer(input.stateKey) ||
    input.stateKey.length !== 32 ||
    !Buffer.isBuffer(input.bootstrap.key) ||
    input.bootstrap.key.length !== 32 ||
    !timingSafeEqual(input.stateKey, input.bootstrap.key)
  )
    throw Error("production_startup_configuration_required");
  const validatePolicy = cachePolicyGuard(
    input.historicalStateDirectory,
    input.cacheStateDirectory,
  );
  if (
    !isAbsolute(input.bootstrap.journalPath) ||
    realpathSync(dirname(input.bootstrap.journalPath)) !==
      realpathSync(input.cacheStateDirectory) ||
    basename(input.bootstrap.journalPath) !== "central-attempts.db"
  )
    throw Error("production_journal_directory_mismatch");
  const bootstrap = Object.freeze({
    ...input.bootstrap,
    key: Buffer.from(input.bootstrap.key),
    ownerTokens: new Map(input.bootstrap.ownerTokens),
  });
  return startSidecar({
    configPath: input.configPath,
    stateKey: Buffer.from(input.stateKey),
    backendFactory: input.backendFactory,
    validatePolicy,
    runtimeFactory: (bridge) => createProductionRuntime(bridge, bootstrap),
  });
}
