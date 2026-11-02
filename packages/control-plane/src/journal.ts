// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import type { AttemptJournal, Outcome } from "./edge.ts";
/** One persistent file per executor identity/fleet. Never replace it to recover availability. */
export class SqliteJournal implements AttemptJournal {
  private db: DatabaseSync;
  private key?: Buffer;
  constructor(path: string, key?: Buffer) {
    if (key && key.length !== 32) throw Error("32_byte_journal_key_required");
    if (key)
      this.key = Buffer.from(
        hkdfSync("sha256", key, Buffer.alloc(0), "kadenco-edge-journal-v1", 32),
      );
    this.db = new DatabaseSync(path);
    this.db.exec(
      "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,outcome TEXT)",
    );
  }
  async reserve(id: string) {
    return this.db.prepare("INSERT OR IGNORE INTO attempts(id) VALUES(?)").run(id).changes === 1;
  }
  async finish(id: string, outcome: Outcome) {
    const value = JSON.stringify(outcome);
    const changed = this.db
      .prepare("UPDATE attempts SET outcome=? WHERE id=? AND outcome IS NULL")
      .run(this.encode(value, id), id).changes;
    if (!changed && this.read(id)?.outcome !== value) throw Error("immutable_or_missing_attempt");
  }
  read(id: string) {
    const row = this.db.prepare("SELECT outcome FROM attempts WHERE id=?").get(id);
    if (!row || row.outcome === null) return row;
    return { ...row, outcome: this.decode(String(row.outcome), id) };
  }
  private encode(value: string, id: string) {
    if (!this.key) return value; // Existing fixture/backward-compatible interface only.
    const nonce = randomBytes(12),
      cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(Buffer.from(id, "utf8"));
    const bytes = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return "v1:" + Buffer.concat([nonce, cipher.getAuthTag(), bytes]).toString("base64");
  }
  private decode(value: string, id: string) {
    if (!this.key) return value;
    if (!value.startsWith("v1:")) throw Error("unencrypted_journal_refused");
    const bytes = Buffer.from(value.slice(3), "base64");
    if (bytes.length < 28) throw Error("invalid_journal_envelope");
    const cipher = createDecipheriv("aes-256-gcm", this.key, bytes.subarray(0, 12));
    cipher.setAAD(Buffer.from(id, "utf8"));
    cipher.setAuthTag(bytes.subarray(12, 28));
    return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString("utf8");
  }
  close() {
    this.db.close();
  }
}
