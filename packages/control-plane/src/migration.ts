// SPDX-License-Identifier: AGPL-3.0-or-later
export type ManifestRecord = { kind: string; id: string; sha256: string };
export type Manifest = {
  migration_id: string;
  source_snapshot: string;
  encryption_provenance: string;
  records: ManifestRecord[];
};
/** Pure comparison only. A report cannot authorize activation or attest retirement. */
export function verifyMigration(
  expected: Manifest,
  actual: Manifest,
  quiescence: {
    snapshot: string;
    pending_native_effects: number;
    old_writer_retirement: "unverified" | "externally_enforced";
  },
) {
  const errors: string[] = [];
  const index = (records: ManifestRecord[]) => {
    const map = new Map<string, string>();
    if (records.length > 100000) throw Error("manifest_too_large");
    for (const r of records) {
      const key = JSON.stringify([r.kind, r.id]);
      if (!r.kind || !r.id || !/^[a-f0-9]{64}$/.test(r.sha256) || map.has(key))
        errors.push("invalid_or_duplicate_record");
      map.set(key, r.sha256);
    }
    return map;
  };
  if (!expected.migration_id || expected.migration_id !== actual.migration_id)
    errors.push("migration_mismatch");
  if (
    !expected.source_snapshot ||
    expected.source_snapshot !== actual.source_snapshot ||
    quiescence.snapshot !== expected.source_snapshot
  )
    errors.push("snapshot_mismatch");
  if (
    !expected.encryption_provenance ||
    expected.encryption_provenance !== actual.encryption_provenance
  )
    errors.push("encryption_mismatch");
  const a = index(expected.records),
    b = index(actual.records);
  if (a.size !== b.size || [...a].some(([key, hash]) => b.get(key) !== hash))
    errors.push("record_mismatch");
  if (quiescence.pending_native_effects !== 0) errors.push("unreconciled_effects");
  if (quiescence.old_writer_retirement !== "externally_enforced")
    errors.push("old_writer_not_retired");
  return {
    consistent: errors.length === 0,
    errors: [...new Set(errors)],
    activation_permitted: false as const,
  };
}
