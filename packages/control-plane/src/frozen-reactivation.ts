// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { recoveryPage, recoveryTables } from "./recovery.ts";
import { verifyRetirement } from "./authorization.ts";
import type { RetirementEvidence } from "./activation.ts";
const fail = (reason: string): never => {
  throw Error(reason);
};
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const keys = (p: object, allowed: string[]) => {
  if (Object.keys(p).some((k) => !allowed.includes(k))) fail("invalid_request");
};
type Actor = { id: string; role: string; hosts: string[]; migrationAuthority?: boolean };
type Challenge = {
  nonce: string;
  epoch: number;
  digest: string;
  watermark: number;
  policy: string;
  created: number;
  expires: number;
  migration: string;
  freeze: string;
};
/** Reopens the SAME current frozen SQL state. Never restores an old import or
 * bypasses physical managed-writer retirement. Runs inside the DO transaction. */
export function frozenReactivation(
  sql: SqlStorage,
  a: Actor,
  policy: unknown,
  op: string,
  p: Record<string, unknown>,
  proof?: RetirementEvidence,
) {
  if (!["recovery_resume_challenge", "recovery_resume_receipt", "resume_recovery"].includes(op))
    return undefined;
  if (!["owner", "migration"].includes(a.role) || a.migrationAuthority !== true) fail("forbidden");
  const id =
    typeof p.resume_id === "string" && /^[a-zA-Z0-9-]{1,100}$/.test(p.resume_id)
      ? "recovery:" + p.resume_id
      : fail("invalid_request");
  const prior = sql
    .exec<{ actor: string; value: string }>(
      "SELECT actor,value FROM activation_receipts WHERE id=?",
      id,
    )
    .toArray()[0];
  if (prior && prior.actor !== a.id) fail("forbidden");
  if (prior && JSON.parse(prior.value).kind !== "current_recovery_resume")
    fail("idempotency_conflict");
  if (op === "recovery_resume_receipt") {
    keys(p, ["resume_id"]);
    return prior ? { committed: true, ...JSON.parse(prior.value) } : { committed: false };
  }
  keys(p, [
    "resume_id",
    "expected_epoch",
    "digest",
    ...(op === "resume_recovery" ? ["retirement"] : []),
  ]);
  if (
    !Number.isSafeInteger(p.expected_epoch) ||
    Number(p.expected_epoch) < 1 ||
    typeof p.digest !== "string" ||
    !/^[a-f0-9]{64}$/.test(p.digest)
  )
    fail("invalid_request");
  if (prior) {
    const r = JSON.parse(prior.value);
    if (r.previous_epoch !== p.expected_epoch || r.digest !== p.digest)
      fail("idempotency_conflict");
    return r;
  }
  const state = sql
    .exec<{ mode: string; epoch: number; migration: string | null }>(
      "SELECT mode,epoch,migration FROM control WHERE id=1",
    )
    .one();
  if (state.mode !== "quiesced" || state.epoch !== p.expected_epoch || !state.migration)
    fail("fenced");
  const freezes = sql
    .exec<{ id: string; owner: string; epoch: number; watermark: number; counts: string }>(
      "SELECT * FROM recovery_freezes WHERE epoch=? AND owner=?",
      state.epoch,
      a.id,
    )
    .toArray();
  if (freezes.length !== 1) fail("forbidden");
  const frozen = freezes[0];
  const watermark = sql.exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one().n;
  if (watermark !== frozen.watermark) fail("activation_state_changed");
  const saved = sql
    .exec<{ actor: string; value: string }>(
      "SELECT actor,value FROM activation_challenges WHERE id=?",
      id,
    )
    .toArray()[0];
  let c: Challenge | undefined = saved ? JSON.parse(saved.value) : undefined;
  if (
    c &&
    (saved!.actor !== a.id ||
      c.epoch !== state.epoch ||
      c.digest !== p.digest ||
      c.watermark !== watermark ||
      c.policy !== hash(policy) ||
      c.migration !== state.migration ||
      c.freeze !== frozen.id)
  )
    fail("fenced");
  if (c && c.expires <= Date.now()) fail("activation_expired");
  if (op === "recovery_resume_challenge") {
    if (c) return c;
    const counts = JSON.parse(frozen.counts) as Record<string, number>;
    const rows: ReturnType<typeof recoveryPage>["rows"] = [];
    let cursor: { table: number; after: number } | null = { table: 0, after: 0 };
    let bytes = Buffer.byteLength(
      JSON.stringify({
        header: { epoch: state.epoch, watermark, counts, activation_permitted: false },
        rows: [],
      }),
    );
    while (cursor) {
      const page = recoveryPage(sql, cursor.table, cursor.after);
      for (const row of page.rows) {
        bytes += Buffer.byteLength(JSON.stringify(row)) + 1;
        if (bytes > 32 * 1024 * 1024 || rows.length >= 100000) fail("recovery_too_large");
        rows.push(row);
      }
      cursor = page.next;
    }
    for (const table of recoveryTables)
      if (rows.filter((r) => r.table === table).length !== counts[table])
        fail("incomplete_recovery");
    const digest = hash({
      header: { epoch: state.epoch, watermark, counts, activation_permitted: false },
      rows,
    });
    if (digest !== p.digest) fail("recovery_digest_mismatch");
    const now = Date.now();
    c = {
      nonce: crypto.randomUUID(),
      epoch: state.epoch,
      digest,
      watermark,
      policy: hash(policy),
      created: now,
      expires: now + 120000,
      migration: state.migration!,
      freeze: frozen.id,
    };
    sql.exec("INSERT INTO activation_challenges VALUES(?,?,?)", id, a.id, JSON.stringify(c));
    return c;
  }
  if (!c || !proof) fail("retirement_proof_required");
  const now = Date.now();
  if (
    proof!.issued < c!.created ||
    proof!.expires > c!.expires ||
    proof!.expires - proof!.issued > 60000
  )
    fail("activation_expired");
  const routes = [...a.hosts.map((h) => "native:" + h), "callback", "restart"];
  verifyRetirement(
    proof!,
    { migration_id: c!.migration, snapshot: c!.digest, routes, issuer: a.id },
    now,
  );
  if (
    proof!.kind !== "managed_bootstrap_retirement" ||
    proof!.challenge !== c!.nonce ||
    proof!.epoch !== c!.epoch ||
    proof!.import_id !== "freeze:" + c!.epoch ||
    proof!.processes !== 0 ||
    proof!.ingress_closed !== true ||
    [
      proof!.archive_sha256,
      proof!.source_release_sha256,
      proof!.bootstrap_sha256,
      proof!.credential_path_sha256,
    ].some((v) => !/^[a-f0-9]{64}$/.test(v))
  )
    fail("retirement_not_proven");
  const archive = sql
    .exec<{ ciphertext: string }>(
      "SELECT ciphertext FROM imported WHERE kind='$history_archive' AND id=?",
      proof!.archive_sha256,
    )
    .toArray()[0];
  if (!archive || JSON.parse(archive.ciphertext).archive_sha256 !== proof!.archive_sha256)
    fail("retirement_not_proven");
  if (!Number.isSafeInteger(state.epoch + 1)) fail("fenced");
  const result = {
    kind: "current_recovery_resume",
    activated: true,
    previous_epoch: state.epoch,
    epoch: state.epoch + 1,
    digest: c!.digest,
    retirement_evidence_sha256: hash(proof),
  };
  sql.exec("UPDATE control SET mode='active',epoch=epoch+1 WHERE id=1");
  sql.exec("INSERT INTO activation_receipts VALUES(?,?,?)", id, a.id, JSON.stringify(result));
  sql.exec(
    "INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)",
    a.id,
    "resume_recovery",
    id,
    now,
  );
  return result;
}
