// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { verifyRetirement, seal, unseal, type Retirement } from "./authorization.ts";
export const activationSchema = `
CREATE TABLE IF NOT EXISTS activation_challenges(id TEXT PRIMARY KEY,actor TEXT NOT NULL,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS activation_receipts(id TEXT PRIMARY KEY,actor TEXT NOT NULL,value TEXT NOT NULL);
`;
export type RetirementEvidence = Retirement & {
  kind: "managed_bootstrap_retirement";
  challenge: string;
  epoch: number;
  import_id: string;
  archive_sha256: string;
  source_release_sha256: string;
  bootstrap_sha256: string;
  credential_path_sha256: string;
  processes: 0;
  ingress_closed: true;
};
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const fail = (s: string): never => {
  throw Error(s);
};
const text = (v: unknown) =>
  typeof v === "string" && v.length > 0 && v.length <= 200 ? v : fail("invalid_request");
function keys(p: object, allowed: string[]) {
  if (
    !p ||
    typeof p !== "object" ||
    Array.isArray(p) ||
    Object.keys(p).some((k) => !allowed.includes(k))
  )
    fail("invalid_request");
}
function signingKey(token: string) {
  return createHash("sha256").update("kadenco-retirement-authority-v1\0").update(token).digest();
}
/** Authenticates operator observations, NOT physical retirement. The production
 * operator must enforce and probe the managed bootstrap boundary separately. */
export function signRetirement(e: RetirementEvidence, token: string) {
  return seal(e, signingKey(token));
}
export function readRetirement(packet: { body: string; mac: string }, token: string) {
  if (!packet || typeof packet.body !== "string" || typeof packet.mac !== "string")
    fail("retirement_proof_required");
  const e = unseal(packet, signingKey(token)) as RetirementEvidence;
  keys(e, [
    "migration_id",
    "snapshot",
    "issued",
    "expires",
    "routes",
    "denied",
    "revival_denied",
    "issuer",
    "kind",
    "challenge",
    "epoch",
    "import_id",
    "archive_sha256",
    "source_release_sha256",
    "bootstrap_sha256",
    "credential_path_sha256",
    "processes",
    "ingress_closed",
  ]);
  if (
    !Number.isSafeInteger(e.issued) ||
    !Number.isSafeInteger(e.expires) ||
    !Number.isSafeInteger(e.epoch) ||
    !Array.isArray(e.routes) ||
    !Array.isArray(e.denied) ||
    [e.routes, e.denied].some(
      (a) => a.length > 100 || a.some((v) => typeof v !== "string" || v.length > 200),
    )
  )
    fail("retirement_not_proven");
  return e;
}
type Actor = { id: string; role: string; hosts: string[]; migrationAuthority?: boolean };
type Challenge = {
  nonce: string;
  epoch: number;
  import_id: string;
  digest: string;
  migration_id: string;
  created: number;
  expires: number;
  policy: string;
  watermark: number;
};
/** Current-policy SQL transaction only; proof is authenticated by the HTTP path. */
export function activationOperation(
  sql: SqlStorage,
  a: Actor,
  policy: unknown,
  op: string,
  p: Record<string, unknown>,
  proof?: RetirementEvidence,
) {
  if (!["activation_challenge", "activation_receipt", "activate"].includes(op)) return undefined;
  if (a.role !== "owner" || a.migrationAuthority !== true) fail("forbidden");
  const id = text(p.activation_id);
  const prior = sql
    .exec<{ actor: string; value: string }>(
      "SELECT actor,value FROM activation_receipts WHERE id=?",
      id,
    )
    .toArray()[0];
  if (prior && prior.actor !== a.id) fail("forbidden");
  if (op === "activation_receipt") {
    keys(p, ["activation_id"]);
    return prior ? { committed: true, ...JSON.parse(prior.value) } : { committed: false };
  }
  const state = sql
    .exec<{ epoch: number; mode: string; migration: string | null }>(
      "SELECT epoch,mode,migration FROM control WHERE id=1",
    )
    .one();
  if (op === "activation_challenge") {
    keys(p, ["activation_id", "expected_epoch", "import_id", "digest"]);
    if (prior) {
      const r = JSON.parse(prior.value);
      if (
        r.import_id !== p.import_id ||
        r.digest !== p.digest ||
        r.previous_epoch !== p.expected_epoch
      )
        fail("idempotency_conflict");
      return r;
    }
    if (state.mode !== "quiesced" || state.epoch !== p.expected_epoch || !state.migration)
      fail("fenced");
    const imported = sql
      .exec<{ actor: string; digest: string; value: string }>(
        "SELECT actor,digest,value FROM recovery_import_receipts WHERE id=?",
        text(p.import_id),
      )
      .toArray()[0];
    if (
      !imported ||
      imported.actor !== a.id ||
      imported.digest !== p.digest ||
      JSON.parse(imported.value).epoch !== state.epoch
    )
      fail("fenced");
    const old = sql
      .exec<{ actor: string; value: string }>(
        "SELECT actor,value FROM activation_challenges WHERE id=?",
        id,
      )
      .toArray()[0];
    const watermark = sql.exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one().n;
    if (old) {
      const c = JSON.parse(old.value) as Challenge;
      if (
        old.actor !== a.id ||
        c.epoch !== state.epoch ||
        c.import_id !== p.import_id ||
        c.digest !== p.digest ||
        c.policy !== hash(policy) ||
        c.watermark !== watermark
      )
        fail("fenced");
      if (c.expires <= Date.now()) fail("activation_expired");
      return c;
    }
    const created = Date.now(),
      c: Challenge = {
        nonce: crypto.randomUUID(),
        epoch: state.epoch,
        import_id: String(p.import_id),
        digest: imported.digest,
        migration_id: text(state.migration),
        created,
        expires: created + 120000,
        policy: hash(policy),
        watermark,
      };
    sql.exec("INSERT INTO activation_challenges VALUES(?,?,?)", id, a.id, JSON.stringify(c));
    return c;
  }
  keys(p, ["activation_id", "expected_epoch", "import_id", "digest", "retirement"]);
  if (prior) {
    const r = JSON.parse(prior.value);
    if (
      r.import_id !== p.import_id ||
      r.digest !== p.digest ||
      r.previous_epoch !== p.expected_epoch
    )
      fail("idempotency_conflict");
    return r;
  }
  if (!proof) fail("retirement_proof_required");
  const saved = sql
    .exec<{ actor: string; value: string }>(
      "SELECT actor,value FROM activation_challenges WHERE id=?",
      id,
    )
    .toArray()[0];
  if (!saved || saved.actor !== a.id) fail("fenced");
  const c = JSON.parse(saved!.value) as Challenge,
    now = Date.now();
  if (
    state.mode !== "quiesced" ||
    state.epoch !== p.expected_epoch ||
    state.epoch !== c.epoch ||
    state.migration !== c.migration_id ||
    p.import_id !== c.import_id ||
    p.digest !== c.digest
  )
    fail("fenced");
  if (
    c.expires <= now ||
    proof!.issued < c.created ||
    proof!.expires > c.expires ||
    proof!.expires - proof!.issued > 60000
  )
    fail("activation_expired");
  if (
    c.policy !== hash(policy) ||
    c.watermark !== sql.exec<{ n: number }>("SELECT COALESCE(MAX(seq),0) n FROM audit").one().n
  )
    fail("activation_state_changed");
  const routes = [...a.hosts.map((h) => "native:" + h), "callback", "restart"];
  verifyRetirement(
    proof!,
    { migration_id: c.migration_id, snapshot: c.digest, routes, issuer: a.id },
    now,
  );
  if (
    proof!.kind !== "managed_bootstrap_retirement" ||
    proof!.challenge !== c.nonce ||
    proof!.epoch !== c.epoch ||
    proof!.import_id !== c.import_id ||
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
    activated: true,
    previous_epoch: state.epoch,
    epoch: state.epoch + 1,
    import_id: c.import_id,
    digest: c.digest,
    retirement_evidence_sha256: hash(proof),
  };
  sql.exec("UPDATE control SET mode='active',epoch=epoch+1 WHERE id=1");
  sql.exec("INSERT INTO activation_receipts VALUES(?,?,?)", id, a.id, JSON.stringify(result));
  sql.exec("INSERT INTO audit(actor,action,subject,at) VALUES(?,?,?,?)", a.id, "activate", id, now);
  return result;
}
