// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

// base64 of nonce (12 bytes) + GCM tag (16 bytes) + 2 ciphertext bytes = 40 chars.
const SIGNATURE_CHARS = 40;

export class Store {
  declare key: Buffer;
  declare db: DatabaseSync;
  declare diagnosticWrites: number;
  declare verdicts: Map<string, Map<string, [string, boolean]>> | undefined;
  constructor(path: string, key: Buffer) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("32_byte_state_key_required");
    this.key = key;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value TEXT NOT NULL, PRIMARY KEY(kind,id));
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, at TEXT, action TEXT, subject TEXT, outcome TEXT);
      CREATE TABLE IF NOT EXISTS diagnostics (seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, host TEXT NOT NULL, value TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS diagnostics_host_seq ON diagnostics(host,seq);`);
    this.db.exec("CREATE INDEX IF NOT EXISTS audit_subject_seq ON audit(subject,seq)");
    // Covering index for select(): reading signatures never touches row values.
    // The expression must match select()'s query exactly to be used.
    this.db.exec(
      `CREATE INDEX IF NOT EXISTS records_signature ON records(kind, id, substr(value,1,${SIGNATURE_CHARS}))`,
    );
    this.diagnosticWrites = 0;
  }
  encode(value) {
    const nonce = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    return Buffer.concat([nonce, ...this.seal(cipher, value)]).toString("base64");
  }
  seal(cipher, value) {
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return [cipher.getAuthTag(), ciphertext];
  }
  decode(raw) {
    const b = Buffer.from(raw, "base64"),
      d = createDecipheriv("aes-256-gcm", this.key, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    return JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString());
  }
  get(kind, id) {
    const r = this.db.prepare("SELECT value FROM records WHERE kind=? AND id=?").get(kind, id);
    return r ? this.decode(r.value) : undefined;
  }
  all(kind) {
    return this.db
      .prepare("SELECT value FROM records WHERE kind=? ORDER BY id")
      .all(kind)
      .map((r) => this.decode(r.value));
  }
  /**
   * Records of `kind` matching `predicate`, in id order, without decrypting the
   * whole kind on every call. Hot paths (the edge cycle's delivery passes) need
   * only the few pending/centralized rows among many thousands.
   *
   * The predicate's verdict is cached per record, keyed by the ciphertext's
   * leading bytes (12-byte random nonce + 16-byte GCM tag). Every write encodes
   * with a fresh nonce, so any change to a row, by any writer (including
   * rollbacks, replica rehydration or direct SQL), changes that signature and
   * forces re-evaluation. Only verdicts are cached, never plaintext; matching
   * rows are decoded fresh, so callers get independent objects.
   *
   * `name` identifies the predicate. It must be a pure function of the record
   * (no clock, policy or other state): such conditions belong after selection.
   */
  select(kind: string, name: string, predicate: (value: any) => boolean) {
    const key = kind + "\u0000" + name,
      prior = (this.verdicts ??= new Map()).get(key) ?? new Map<string, [string, boolean]>(),
      next = new Map<string, [string, boolean]>(),
      out = [];
    const rows = this.db
      .prepare(
        `SELECT id, substr(value,1,${SIGNATURE_CHARS}) AS sig FROM records WHERE kind=? ORDER BY id`,
      )
      .all(kind) as { id: string; sig: string }[];
    const one = this.db.prepare("SELECT value FROM records WHERE kind=? AND id=?");
    for (const { id, sig } of rows) {
      const cached = prior.get(id);
      if (cached && cached[0] === sig) {
        next.set(id, cached);
        if (!cached[1]) continue;
      }
      const raw = (one.get(kind, id) as { value: string } | undefined)?.value;
      if (raw === undefined) continue;
      const value = this.decode(raw);
      const match = predicate(value) === true;
      next.set(id, [raw.slice(0, SIGNATURE_CHARS), match]);
      if (match) out.push(value);
    }
    this.verdicts.set(key, next);
    return out;
  }
  commandBudgetRecords() {
    return this.all("command").concat(this.all("settings_mutation").filter((r) => r.submitted_at));
  }
  put(kind, id, value) {
    this.db
      .prepare(
        "INSERT INTO records VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET value=excluded.value",
      )
      .run(kind, id, this.encode(value));
  }
  insert(kind, id, value) {
    return (
      this.db
        .prepare("INSERT OR IGNORE INTO records VALUES(?,?,?)")
        .run(kind, id, this.encode(value)).changes === 1
    );
  }
  audit(action, subject, outcome) {
    this.db
      .prepare("INSERT INTO audit(at,action,subject,outcome) VALUES(?,?,?,?)")
      .run(new Date().toISOString(), action, subject, outcome);
  }
  diagnostic(value) {
    // Encrypted like all other operational records. Seven days / 25,000 rows,
    // with at most 127 transient excess rows between pruning operations.
    this.db
      .prepare("INSERT INTO diagnostics(at,host,value) VALUES(?,?,?)")
      .run(value.at, value.host, this.encode(value));
    if (this.diagnosticWrites++ % 128 === 0) {
      this.db
        .prepare(
          "DELETE FROM diagnostics WHERE at<? OR seq <= (SELECT COALESCE(MAX(seq),0)-25000 FROM diagnostics)",
        )
        .run(new Date(Date.now() - 7 * 86400000).toISOString());
    }
  }
  diagnostics(host, after = 0, limit = 50) {
    return this.db
      .prepare(
        "SELECT seq,value FROM diagnostics WHERE host=? AND seq>? AND at>=? ORDER BY seq LIMIT ?",
      )
      .all(host, after, new Date(Date.now() - 7 * 86400000).toISOString(), limit + 1)
      .map((r) => ({ sequence: r.seq, ...this.decode(r.value) }));
  }
  deliveryHistory(id: string, after: number, limit: number, since: string) {
    return this.db
      .prepare(
        "SELECT seq,at,outcome FROM audit WHERE subject=? AND seq>? AND at>=? AND action='webhook.delivery' ORDER BY seq LIMIT ?",
      )
      .all(id, after, since, limit + 1);
  }
  /** For exactly these delivery IDs (ownership precedes selection), the newest
   * acknowledgement, the newest terminal failure (stopped/revoked) and the
   * newest failure of any kind, each found independently of age or volume.
   * "Newest" is by outcome time (then sequence), matching how /status compares
   * them, so a wall-clock rollback cannot make selection and comparison disagree. */
  latestDeliveryOutcomes(ids: string[]) {
    type Row = { seq: number; subject: string; at: string; outcome: string };
    if (!ids.length) return { ack: undefined, terminal: undefined, failure: undefined };
    const pick = (filter: string) =>
      this.db
        .prepare(
          `SELECT seq,subject,at,outcome FROM audit WHERE action IN ('webhook.delivery','webhook.delivery.revoked') AND subject IN (SELECT value FROM json_each(?)) AND ${filter} ORDER BY at DESC, seq DESC LIMIT 1`,
        )
        .get(JSON.stringify(ids)) as Row | undefined;
    return {
      ack: pick("outcome LIKE 'acknowledged:%'"),
      terminal: pick("(outcome LIKE 'stopped:%' OR outcome LIKE 'revoked:%')"),
      failure: pick("outcome NOT LIKE 'acknowledged:%'"),
    };
  }
  latestDiagnostic(host) {
    const r = this.db
      .prepare("SELECT value FROM diagnostics WHERE host=? ORDER BY seq DESC LIMIT 1")
      .get(host);
    return r ? this.decode(r.value) : undefined;
  }
  transaction(fn) {
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      this.db.exec("ROLLBACK");
      throw e;
    }
  }
  close() {
    this.db.close();
  }
}
