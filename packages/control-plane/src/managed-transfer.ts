// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { createHash } from "node:crypto";
import type { Policy } from "../../../dist/config.mjs";
import { verifyManagedRetirement, type ManagedRetirementInput } from "./managed-retirement.ts";
import { sourcePreflight } from "./source-preflight.ts";
import { localArchiveReference } from "./local-archive.ts";
import { manifestOf, type Snapshot } from "./snapshot.ts";
import { segmentSnapshot } from "./import-service.ts";
import { prepareLegacyRecovery } from "./legacy-recovery.ts";

/** Initial transfer only. Real managed retirement is verified on both sides of
 * a read-only transaction. History is referenced, not exported. This never opens
 * a writable historical Store or uploads state. Use CURRENT central recovery
 * for rollback after activation, never this initial-source preparer. */
export async function prepareManagedRecovery(input: {
  source: ManagedRetirementInput;
  migrationId: string;
  encryptionProvenance: string;
  key: Buffer;
  originalPolicy: Policy;
  centralPolicy: unknown;
  serviceExpiresAt: number;
}) {
  if (!input.migrationId || !input.encryptionProvenance || input.key.length !== 32)
    throw Error("managed_transfer_configuration_required");
  await verifyManagedRetirement(input.source);
  const db = new DatabaseSync(input.source.archivePath, { readOnly: true });
  let snapshot: Snapshot;
  try {
    db.exec("BEGIN");
    const p = sourcePreflight(db, "local_archive");
    if (!p.fits_current_materialized_path)
      throw Error("source_volume_requires_streaming_migration");
    const records = db
      .prepare("SELECT kind,id,value FROM records ORDER BY kind,id")
      .all()
      .map((r) => ({ kind: String(r.kind), id: String(r.id), ciphertext: String(r.value) }));
    const archive = localArchiveReference(input.source.archivePath);
    if (
      archive.archive_sha256 !== input.source.archiveSha256 ||
      archive.operational_sha256 !==
        createHash("sha256").update(JSON.stringify(records)).digest("hex")
    )
      throw Error("historical_archive_changed");
    records.push({
      kind: "$history_archive",
      id: archive.archive_sha256,
      ciphertext: JSON.stringify(archive),
    });
    snapshot = {
      migration_id: input.migrationId,
      encryption_provenance: input.encryptionProvenance,
      source_snapshot: createHash("sha256").update(JSON.stringify(records)).digest("hex"),
      records,
    };
    db.exec("ROLLBACK");
  } finally {
    db.close();
  }
  await verifyManagedRetirement(input.source);
  const manifest = manifestOf(snapshot);
  return prepareLegacyRecovery(
    segmentSnapshot(snapshot, input.key),
    input.key,
    manifest,
    input.originalPolicy,
    input.centralPolicy,
    input.serviceExpiresAt,
  );
}
