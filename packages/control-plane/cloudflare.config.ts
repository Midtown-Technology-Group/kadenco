// SPDX-License-Identifier: AGPL-3.0-or-later
import { bindings, defineConfig, exports as lifecycle } from "cf/config";

/** A new isolated staging namespace, never a production namespace migration. */
export function selectStagingConfig(mode: string | undefined) {
  if (mode !== "staging")
    throw Error("explicit_staging_mode_required: production deployment is disabled");
  const name = "kadenco-control-plane-staging";
  return {
    worker: {
      name,
      entrypoint: "src/worker.ts",
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      workersDev: false,
      previewUrls: false,
      exports: { FleetState: lifecycle.durableObject({ storage: "sqlite" }) },
      env: { FLEETS: bindings.durableObject({ worker: name, exportName: "FleetState" }) },
    },
  };
}
export default defineConfig(({ mode }) => selectStagingConfig(mode));
