// SPDX-License-Identifier: AGPL-3.0-or-later
import { bindings, defineConfig, exports as lifecycle } from "cf/config";

/** A new isolated staging namespace, never a production namespace migration. */
export function selectStagingConfig(mode: string | undefined, isPreview = false) {
  if (isPreview) throw Error("preview_deployment_disabled");
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
/** Explicit production profile. Separate Worker/SQLite lifecycle from staging;
 * no trust is embedded. Missing AUTH_POLICY refuses every request before DO use.
 * Deployment does not activate a fleet: authenticated import and retirement
 * verification remain mandatory transaction boundaries. */
export function selectDeploymentConfig(mode: string | undefined, isPreview = false) {
  if (mode !== "production") return selectStagingConfig(mode, isPreview);
  if (isPreview) throw Error("preview_deployment_disabled");
  const staging = selectStagingConfig("staging");
  const name = "kadenco-control-plane";
  return {
    worker: {
      ...staging.worker,
      name,
      workersDev: true,
      env: { FLEETS: bindings.durableObject({ worker: name, exportName: "FleetState" }) },
    },
  };
}
export default defineConfig(({ mode, isPreview }) => selectDeploymentConfig(mode, isPreview));
