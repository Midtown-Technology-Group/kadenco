// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
const known = new Set([
  "supervisor_configuration_required",
  "supervisor_secret_input_too_large",
  "supervisor_identity_required",
  "central_activation_required",
  "central_transport_uncertain",
  "edge_lease_unavailable",
  "replica_inventory_changed",
  "replica_inventory_limit",
  "replica_current_state_required",
  "replica_epoch_changed",
  "replica_encryption_provenance_changed",
  "replica_invalid_record",
  "replica_inventory_loop",
  "replica_central_unavailable",
  "replica_orphaned_journal",
  "bootstrap_owner_identity_changed",
  "bootstrap_owner_identity_mismatch",
  "bootstrap_executor_identity_mismatch",
  "production_state_directory_changed",
  "production_cache_file_alias",
  "historical_state_overlap",
]);
/** Static reasons only. Unknown text is fingerprinted, never printed: fetch,
 * parser and provider errors can contain credentials, paths or private data. */
export function startupFailure(error) {
  const message = typeof error?.message === "string" ? error.message : "unknown";
  return {
    event: "startup_refused",
    reason: known.has(message) ? message : "unclassified_startup_failure",
    error_code: ["EADDRINUSE", "ENOENT", "SQLITE_BUSY", "SQLITE_ERROR"].includes(error?.code)
      ? error.code
      : null,
    fingerprint: createHash("sha256").update(message).digest("hex"),
    local_fallback: false,
  };
}
