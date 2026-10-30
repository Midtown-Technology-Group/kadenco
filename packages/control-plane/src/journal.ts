// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";
import type { AttemptJournal, Outcome } from "./edge.ts";
/** One persistent file per executor identity/fleet. Never replace it to recover availability. */
export class SqliteJournal implements AttemptJournal {
  private db: DatabaseSync;
  constructor(path: string) {
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
      .run(value, id).changes;
    if (!changed && this.read(id)?.outcome !== value) throw Error("immutable_or_missing_attempt");
  }
  read(id: string) {
    return this.db.prepare("SELECT outcome FROM attempts WHERE id=?").get(id);
  }
  close() {
    this.db.close();
  }
}
