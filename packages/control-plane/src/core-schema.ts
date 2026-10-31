// SPDX-License-Identifier: AGPL-3.0-or-later
export const coreSchema = `
    CREATE TABLE IF NOT EXISTS recovery_freezes(id TEXT PRIMARY KEY,owner TEXT NOT NULL,epoch INTEGER NOT NULL,watermark INTEGER NOT NULL,counts TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS auth_policy(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS revoked(id TEXT PRIMARY KEY);
    CREATE TABLE IF NOT EXISTS control(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,mode TEXT NOT NULL,migration TEXT);
    INSERT OR IGNORE INTO control VALUES(1,0,'staging',NULL);
    CREATE TABLE IF NOT EXISTS commands(id TEXT PRIMARY KEY,host TEXT NOT NULL,thread TEXT NOT NULL,kind TEXT NOT NULL,digest TEXT NOT NULL,originator TEXT,binding TEXT,state TEXT NOT NULL,executor TEXT,generation INTEGER NOT NULL DEFAULT 0,lease_until INTEGER,receipt TEXT);
    CREATE TABLE IF NOT EXISTS imported(kind TEXT NOT NULL,id TEXT NOT NULL,ciphertext TEXT NOT NULL,PRIMARY KEY(kind,id));
    CREATE TABLE IF NOT EXISTS budget_reservations(id TEXT PRIMARY KEY,owner TEXT NOT NULL,host TEXT NOT NULL,thread TEXT NOT NULL,day TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS budget_host_day ON budget_reservations(owner,host,day);
    CREATE INDEX IF NOT EXISTS budget_thread_day ON budget_reservations(owner,host,thread,day);
    CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,subject TEXT NOT NULL,at INTEGER NOT NULL);
  `;
