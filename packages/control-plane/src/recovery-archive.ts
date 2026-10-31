// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { seal, unseal } from "./authorization.ts";
import { recoveryTables, type RecoveryRow } from "./recovery.ts";
export type RecoveryHeader = { epoch: number; watermark: number; counts: Record<string, number> };
export function packRecovery(header: RecoveryHeader, rows: RecoveryRow[], key: Buffer) {
  const digest = createHash("sha256").update(JSON.stringify({ header, rows })).digest("hex");
  const batches: RecoveryRow[][] = [];
  let batch: RecoveryRow[] = [],
    size = 0;
  for (const row of rows) {
    const bytes = Buffer.byteLength(JSON.stringify(row));
    if (bytes > 60000) throw Error("recovery_row_too_large");
    if (size + bytes > 400000) {
      batches.push(batch);
      batch = [];
      size = 0;
    }
    batch.push(row);
    size += bytes;
  }
  if (batch.length || !batches.length) batches.push(batch);
  return {
    header: seal({ kind: "kadenco-recovery-v1", header, digest, pages: batches.length }, key),
    pages: batches.map((rows, index) =>
      seal({ kind: "kadenco-recovery-page-v1", digest, index, total: batches.length, rows }, key),
    ),
  };
}
export function verifyRecovery(
  archive: ReturnType<typeof packRecovery>,
  key: Buffer,
  expected: { epoch: number; watermark: number },
) {
  const root = unseal(archive.header, key) as {
    kind: string;
    header: RecoveryHeader;
    digest: string;
    pages: number;
  };
  if (
    root.kind !== "kadenco-recovery-v1" ||
    root.header.epoch !== expected.epoch ||
    root.header.watermark !== expected.watermark ||
    root.pages !== archive.pages.length ||
    root.pages < 1 ||
    root.pages > 10000
  )
    throw Error("recovery_identity_mismatch");
  const rows: RecoveryRow[] = [];
  for (let index = 0; index < archive.pages.length; index++) {
    const page = unseal(archive.pages[index], key) as {
      kind: string;
      digest: string;
      index: number;
      total: number;
      rows: RecoveryRow[];
    };
    if (
      page.kind !== "kadenco-recovery-page-v1" ||
      page.digest !== root.digest ||
      page.index !== index ||
      page.total !== root.pages ||
      !Array.isArray(page.rows)
    )
      throw Error("incomplete_recovery");
    rows.push(...page.rows);
    if (rows.length > 100000) throw Error("recovery_too_large");
  }
  if (
    createHash("sha256")
      .update(JSON.stringify({ header: root.header, rows }))
      .digest("hex") !== root.digest
  )
    throw Error("recovery_digest_mismatch");
  for (const table of recoveryTables)
    if (rows.filter((r) => r.table === table).length !== root.header.counts[table])
      throw Error("incomplete_recovery");
  return { header: root.header, rows, activation_permitted: false };
}
export async function captureRecovery(
  call: (op: string, p: object) => Promise<Record<string, unknown>>,
  epoch: number,
  key: Buffer,
) {
  const header = (await call("freeze_recovery", { expected_epoch: epoch })) as RecoveryHeader;
  if (
    !Number.isSafeInteger(header.epoch) ||
    !Number.isSafeInteger(header.watermark) ||
    !header.counts
  )
    throw Error("freeze_not_proven");
  const rows: RecoveryRow[] = [];
  let cursor: { table: number; after: number } | null = { table: 0, after: 0 },
    pages = 0;
  while (cursor) {
    if (++pages > 10001) throw Error("recovery_too_large");
    const page = await call("export_recovery", {
      epoch: header.epoch,
      watermark: header.watermark,
      ...cursor,
    });
    if (
      page.epoch !== header.epoch ||
      page.watermark !== header.watermark ||
      !Array.isArray(page.rows)
    )
      throw Error("recovery_changed");
    rows.push(...(page.rows as RecoveryRow[]));
    cursor = page.next as typeof cursor;
    if (rows.length > 100000) throw Error("recovery_too_large");
  }
  const archive = packRecovery(header, rows, key);
  verifyRecovery(archive, key, header);
  return archive;
}
