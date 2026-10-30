// SPDX-License-Identifier: AGPL-3.0-or-later
import { manifestOf, verifySnapshot, type Snapshot } from "./snapshot.ts";
import { seal, unseal } from "./authorization.ts";
import { createHash } from "node:crypto";
export async function importVerified(
  packet: { body: string; mac: string },
  key: Buffer,
  expected: ReturnType<typeof manifestOf>,
  call: (op: string, p: object) => Promise<Record<string, unknown>>,
) {
  const { snapshot } = verifySnapshot(packet, key, expected);
  return importSnapshot(snapshot, expected, call);
}
async function importSnapshot(
  snapshot: Snapshot,
  expected: ReturnType<typeof manifestOf>,
  call: (op: string, p: object) => Promise<Record<string, unknown>>,
) {
  for (let i = 0; i < snapshot.records.length;) {
    const batch: Snapshot["records"] = [];
    let size = 128;
    while (i < snapshot.records.length && batch.length < 100) {
      const row = snapshot.records[i],
        bytes = Buffer.byteLength(JSON.stringify(row)) + 1;
      if (size + bytes > 60000) {
        if (!batch.length) throw Error("record_too_large");
        break;
      }
      batch.push(row);
      size += bytes;
      i++;
    }
    const r = await call("import", { migration_id: snapshot.migration_id, records: batch });
    if (r.stored !== batch.length || r.active !== false) throw Error("partial_import");
  }
  const records: Snapshot["records"] = [];
  let cursor: object = {},
    pages = 0;
  const seen = new Set<string>();
  for (;;) {
    if (++pages > 1001) throw Error("inventory_limit");
    const r = await call("inventory", cursor);
    if (!Array.isArray(r.records) || r.active !== false) throw Error("inventory_failed");
    records.push(...(r.records as Snapshot["records"]));
    if (r.next === null) break;
    const token = JSON.stringify(r.next);
    if (seen.has(token)) throw Error("inventory_loop");
    seen.add(token);
    cursor = r.next as object;
  }
  const actual = manifestOf({ ...snapshot, records });
  const normalize = (m: ReturnType<typeof manifestOf>) =>
    JSON.stringify(
      [...m.records].sort((a, b) =>
        JSON.stringify([a.kind, a.id]).localeCompare(JSON.stringify([b.kind, b.id])),
      ),
    );
  if (normalize(actual) !== normalize(expected)) throw Error("incomplete_or_changed_inventory");
  return { verified_records: records.length, activation_permitted: false as const };
}

/** Segments bind sequence, total count and the independently retained manifest digest. */
export function segmentSnapshot(snapshot: Snapshot, key: Buffer) {
  const digest = createHash("sha256")
    .update(JSON.stringify(manifestOf(snapshot)))
    .digest("hex");
  const chunks: Snapshot["records"][] = [];
  let batch: Snapshot["records"] = [],
    size = 0;
  for (const row of snapshot.records) {
    const bytes = Buffer.byteLength(JSON.stringify(row));
    if (bytes > 60000) throw Error("record_too_large");
    if (size + bytes > 400000) {
      chunks.push(batch);
      batch = [];
      size = 0;
    }
    batch.push(row);
    size += bytes;
  }
  if (batch.length || !chunks.length) chunks.push(batch);
  const { records: _records, ...meta } = snapshot;
  return chunks.map((records, index) =>
    seal({ meta, digest, index, total: chunks.length, records }, key),
  );
}
export async function importSegments(
  packets: { body: string; mac: string }[],
  key: Buffer,
  expected: ReturnType<typeof manifestOf>,
  call: (op: string, p: object) => Promise<Record<string, unknown>>,
) {
  if (!packets.length || packets.length > 10000) throw Error("invalid_segments");
  const digest = createHash("sha256").update(JSON.stringify(expected)).digest("hex");
  const records: Snapshot["records"] = [];
  for (let index = 0; index < packets.length; index++) {
    const part = unseal(packets[index], key) as {
      meta: Omit<Snapshot, "records">;
      digest: string;
      index: number;
      total: number;
      records: Snapshot["records"];
    };
    if (
      part.digest !== digest ||
      part.index !== index ||
      part.total !== packets.length ||
      part.meta.migration_id !== expected.migration_id ||
      part.meta.source_snapshot !== expected.source_snapshot ||
      part.meta.encryption_provenance !== expected.encryption_provenance ||
      !Array.isArray(part.records)
    )
      throw Error("incomplete_or_mixed_segments");
    records.push(...part.records);
    if (records.length > 100000) throw Error("inventory_limit");
  }
  const snapshot: Snapshot = {
    migration_id: expected.migration_id,
    source_snapshot: expected.source_snapshot,
    encryption_provenance: expected.encryption_provenance,
    records,
  };
  if (JSON.stringify(manifestOf(snapshot)) !== JSON.stringify(expected))
    throw Error("snapshot_manifest_mismatch");
  return importSnapshot(snapshot, expected, call);
}
