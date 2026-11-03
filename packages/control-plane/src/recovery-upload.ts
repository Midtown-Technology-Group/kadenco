// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { verifyRecovery, type packRecovery } from "./recovery-archive.ts";
function refused(stage: string, result: Record<string, unknown>): never {
  const reason =
    typeof result.reason === "string" && /^[a-z_]{1,80}$/.test(result.reason)
      ? result.reason
      : "unverified_response";
  throw Error(stage + ":" + reason);
}
/** Upload only a locally authenticated CURRENT archive. Stable import/chunk IDs
 * permit explicit same-input recovery after lost responses. Never auto-retry a
 * native effect or activate a destination. The key never enters the API body. */
export async function uploadRecovery(
  archive: ReturnType<typeof packRecovery>,
  key: Buffer,
  expected: { epoch: number; watermark: number },
  target: {
    importId: string;
    expectedEpoch: number;
    call: (op: string, p: object) => Promise<Record<string, unknown>>;
  },
) {
  const { header, rows } = verifyRecovery(archive, key, expected);
  const digest = createHash("sha256").update(JSON.stringify({ header, rows })).digest("hex");
  const prior = await target.call("recovery_import_receipt", { import_id: target.importId });
  if (prior.committed === true) {
    if (prior.digest !== digest || prior.epoch !== header.epoch + 1)
      throw Error("recovery_receipt_mismatch");
    return prior;
  }
  if (prior.committed !== false) refused("recovery_receipt_unavailable", prior);
  const chunks: (typeof rows)[] = [];
  let batch: typeof rows = [],
    bytes = 2;
  for (const row of rows) {
    const size = Buffer.byteLength(JSON.stringify(row)) + 1;
    if (size > 56000) throw Error("recovery_row_too_large");
    if (bytes + size > 56000 || batch.length >= 100) {
      chunks.push(batch);
      batch = [];
      bytes = 2;
    }
    batch.push(row);
    bytes += size;
  }
  if (batch.length) chunks.push(batch);
  const staged = await target.call("stage_recovery", {
    import_id: target.importId,
    expected_epoch: target.expectedEpoch,
    header,
    digest,
    chunks: chunks.length,
  });
  if (staged.staged !== true) refused("recovery_stage_refused", staged);
  for (let sequence = 0; sequence < chunks.length; sequence++) {
    const r = await target.call("recovery_chunk", {
      import_id: target.importId,
      sequence,
      rows: chunks[sequence],
    });
    if (r.stored !== true || r.sequence !== sequence) refused("recovery_chunk_refused", r);
  }
  const result = await target.call("commit_recovery", { import_id: target.importId, digest });
  if (
    result.epoch !== header.epoch + 1 ||
    result.digest !== digest ||
    result.activation_permitted !== false ||
    result.restored_rows !== rows.length
  )
    refused("recovery_commit_unverified", result);
  return result;
}
