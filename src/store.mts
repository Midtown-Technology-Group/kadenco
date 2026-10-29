// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

export class Store {
  declare key: Buffer;
  declare db: DatabaseSync;
  declare diagnosticWrites: number;
  constructor(path: string, key: Buffer) {
    if (!Buffer.isBuffer(key) || key.length !== 32) throw new Error("32_byte_state_key_required");
    this.key = key;
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT, value TEXT NOT NULL, PRIMARY KEY(kind,id));
      CREATE TABLE IF NOT EXISTS audit (seq INTEGER PRIMARY KEY, at TEXT, action TEXT, subject TEXT, outcome TEXT);
      CREATE TABLE IF NOT EXISTS diagnostics (seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, host TEXT NOT NULL, value TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS diagnostics_host_seq ON diagnostics(host,seq);`);
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
