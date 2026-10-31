// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { seal, unseal } from "./authorization.ts";
import { verifyMigration, type Manifest } from "./migration.ts";
export type Snapshot = {
  migration_id: string;
  source_snapshot: string;
  encryption_provenance: string;
  records: { kind: string; id: string; ciphertext: string }[];
};
export function manifestOf(s: Snapshot): Manifest {
  if (!Array.isArray(s.records) || s.records.length > 100000) throw Error("invalid_snapshot");
  return {
    migration_id: s.migration_id,
    source_snapshot: s.source_snapshot,
    encryption_provenance: s.encryption_provenance,
    records: s.records.map((r) => {
      if (typeof r.ciphertext !== "string" || r.ciphertext.length > 32768)
        throw Error("invalid_snapshot");
      return {
        kind: r.kind,
        id: r.id,
        sha256: createHash("sha256").update(r.ciphertext).digest("hex"),
      };
    }),
  };
}
export function signedSnapshot(s: Snapshot, key: Buffer) {
  return seal({ snapshot: s, manifest: manifestOf(s) }, key);
}
export function verifySnapshot(
  packet: { body: string; mac: string },
  key: Buffer,
  expected: Manifest,
) {
  const value = unseal(packet, key) as { snapshot: Snapshot; manifest: Manifest };
  const actual = manifestOf(value.snapshot);
  const check = (a: Manifest, b: Manifest) =>
    verifyMigration(a, b, {
      snapshot: expected.source_snapshot,
      pending_native_effects: 0,
      old_writer_retirement: "unverified",
    });
  const errors = [
    ...check(expected, actual).errors,
    ...check(value.manifest, actual).errors,
  ].filter((e) => e !== "old_writer_not_retired");
  if (errors.length) throw Error("snapshot_manifest_mismatch");
  return { snapshot: value.snapshot, authenticated: true, activation_permitted: false as const };
}
