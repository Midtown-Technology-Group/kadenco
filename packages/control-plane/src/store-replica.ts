// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomUUID } from "node:crypto";
import type { Store } from "../../../dist/store.mjs";
type Row = { kind: string; id: string; ciphertext: string };
type Pending = { request_id: string; expected_revision: number; through: number; records: Row[] };
type Call = (operation: string, body: object) => Promise<Record<string, unknown>>;
function validBatch(records: Row[]) {
  const value = JSON.stringify({ expected_revision: Number.MAX_SAFE_INTEGER, records });
  return (
    Buffer.byteLength(JSON.stringify(records)) <= 35000 &&
    Buffer.byteLength(value) <= 40000 &&
    Buffer.byteLength(JSON.stringify(value)) <= 56000
  );
}
function validRow(row: Row) {
  return (
    typeof row.kind === "string" &&
    row.kind.length > 0 &&
    row.kind.length <= 200 &&
    !row.kind.startsWith("$") &&
    typeof row.id === "string" &&
    row.id.length > 0 &&
    row.id.length <= 2048 &&
    typeof row.ciphertext === "string" &&
    row.ciphertext.length > 0 &&
    row.ciphertext.length <= 32768 &&
    validBatch([row])
  );
}

/** Single-edge encrypted cache with a durable change log. HTTP acknowledgement
 * must await flush(); native dispatch still requires the separate command gate.
 * No old local snapshot is automatically restored over newer central state. */
export async function openStoreReplica(store: Store, epoch: number, call: Call) {
  if (!Number.isSafeInteger(epoch) || epoch < 1) throw Error("invalid_replica_epoch");
  const db = store.db;
  db.exec(`PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS edge_replica_meta(id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL,revision INTEGER NOT NULL,key_check TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS edge_replica_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT NOT NULL,id TEXT NOT NULL,ciphertext TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS edge_replica_pending(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL);
`);
  const checked = async (op: string, p: object) => {
    const r = await call(op, p);
    if (r.reason !== undefined) throw Error("replica_central_unavailable");
    return r;
  };
  const head = async () => {
    const r = await checked("replica_head", {});
    if (!Number.isSafeInteger(r.revision) || Number(r.revision) < 0)
      throw Error("replica_invalid_head");
    return Number(r.revision);
  };
  const meta = () =>
    db.prepare("SELECT epoch,revision,key_check FROM edge_replica_meta WHERE id=1").get() as
      | { epoch: number; revision: number; key_check: string }
      | undefined;
  const remote = await head();
  if (!meta()) {
    if (
      db
        .prepare(
          "SELECT 1 FROM edge_replica_pending UNION ALL SELECT 1 FROM edge_replica_changes LIMIT 1",
        )
        .get()
    )
      throw Error("replica_orphaned_journal");
    const records: Row[] = [];
    let cursor: object = {};
    const seen = new Set<string>();
    for (let pages = 0; ; pages++) {
      if (pages > 1000) throw Error("replica_inventory_limit");
      const page = await checked("replica_page", { revision: remote, ...cursor });
      if (
        page.revision !== remote ||
        !Array.isArray(page.records) ||
        !(page.next === null || typeof page.next === "object")
      )
        throw Error("replica_inventory_changed");
      for (const raw of page.records) {
        const row = raw as Row;
        if (!row || !validRow(row)) throw Error("replica_invalid_record");
        const key = JSON.stringify([row.kind, row.id]);
        if (seen.has(key)) throw Error("replica_duplicate_record");
        seen.add(key);
        store.decode(row.ciphertext); // Prove existing encryption custody without logging plaintext.
        records.push(row);
        if (records.length > 10000) throw Error("replica_inventory_limit");
      }
      if (page.next === null) break;
      const next = page.next as Record<string, unknown>;
      if (
        typeof next.after_kind !== "string" ||
        typeof next.after_id !== "string" ||
        JSON.stringify(next) === JSON.stringify(cursor)
      )
        throw Error("replica_inventory_loop");
      cursor = next;
    }
    if ((await head()) !== remote) throw Error("replica_inventory_changed");
    store.transaction(() => {
      if (meta()) throw Error("replica_bootstrap_raced");
      const local = db
        .prepare("SELECT kind,id,value AS ciphertext FROM records ORDER BY kind,id")
        .all() as Row[];
      const canonical = (rows: Row[]) =>
        JSON.stringify(
          [...rows].sort((a, b) =>
            JSON.stringify([a.kind, a.id]).localeCompare(JSON.stringify([b.kind, b.id])),
          ),
        );
      if (local.length && canonical(local) !== canonical(records))
        throw Error("replica_current_state_required");
      if (!local.length)
        for (const r of records)
          db.prepare("INSERT INTO records VALUES(?,?,?)").run(r.kind, r.id, r.ciphertext);
      db.prepare("INSERT INTO edge_replica_meta VALUES(1,?,?,?)").run(
        epoch,
        remote,
        store.encode({ purpose: "kadenco-replica-key-v1", epoch }),
      );
    });
  }
  if (meta()!.epoch !== epoch) throw Error("replica_epoch_changed");
  const keyCheck = store.decode(meta()!.key_check);
  if (keyCheck?.purpose !== "kadenco-replica-key-v1" || keyCheck.epoch !== epoch)
    throw Error("replica_encryption_provenance_changed");
  db.function("kadenco_replica_row_valid", { deterministic: true }, (kind, id, value) =>
    typeof kind === "string" &&
    typeof id === "string" &&
    typeof value === "string" &&
    validRow({ kind, id, ciphertext: value })
      ? 1
      : 0,
  );
  db.exec(`
CREATE TRIGGER IF NOT EXISTS edge_replica_insert_bound BEFORE INSERT ON records
WHEN kadenco_replica_row_valid(new.kind,new.id,new.value)<>1 BEGIN
 SELECT RAISE(ABORT,'replica_record_exceeds_central_limit'); END;
CREATE TRIGGER IF NOT EXISTS edge_replica_update_bound BEFORE UPDATE ON records
WHEN kadenco_replica_row_valid(new.kind,new.id,new.value)<>1 BEGIN
 SELECT RAISE(ABORT,'replica_record_exceeds_central_limit'); END;
CREATE TRIGGER IF NOT EXISTS edge_replica_no_identity_update BEFORE UPDATE ON records
WHEN new.kind<>old.kind OR new.id<>old.id BEGIN
 SELECT RAISE(ABORT,'replica_identity_mutation_not_supported'); END;
CREATE TRIGGER IF NOT EXISTS edge_replica_insert AFTER INSERT ON records BEGIN
 INSERT INTO edge_replica_changes(kind,id,ciphertext) VALUES(new.kind,new.id,new.value); END;
CREATE TRIGGER IF NOT EXISTS edge_replica_update AFTER UPDATE OF value ON records WHEN old.value<>new.value BEGIN
 INSERT INTO edge_replica_changes(kind,id,ciphertext) VALUES(new.kind,new.id,new.value); END;
CREATE TRIGGER IF NOT EXISTS edge_replica_no_delete BEFORE DELETE ON records BEGIN
 SELECT RAISE(ABORT,'replica_delete_not_supported'); END;
`);
  const pending = () => {
    const row = db.prepare("SELECT value FROM edge_replica_pending WHERE id=1").get();
    return row ? (JSON.parse(String(row.value)) as Pending) : undefined;
  };
  const finish = (p: Pending, revision: number) =>
    store.transaction(() => {
      if (revision !== p.expected_revision + 1 || meta()!.revision !== p.expected_revision)
        throw Error("replica_current_state_required");
      db.prepare("UPDATE edge_replica_meta SET revision=? WHERE id=1").run(revision);
      db.prepare("DELETE FROM edge_replica_changes WHERE seq<=?").run(p.through);
      db.exec("DELETE FROM edge_replica_pending WHERE id=1");
    });
  const reconcile = async () => {
    const p = pending();
    if (!p) return;
    const receipt = await checked("replica_receipt", { request_id: p.request_id });
    if (receipt.committed === true) {
      finish(p, Number(receipt.revision));
      return;
    }
    if (receipt.committed !== false) throw Error("replica_receipt_unknown");
    if (
      !Array.isArray(p.records) ||
      p.records.some((row) => !validRow(row)) ||
      !validBatch(p.records)
    )
      throw Error("replica_record_exceeds_central_limit");
    const result = await checked("replica_apply", {
      request_id: p.request_id,
      expected_revision: p.expected_revision,
      records: p.records,
    });
    if (result.committed !== true) throw Error("replica_commit_unknown");
    finish(p, Number(result.revision));
  };
  await reconcile();
  if (meta()!.revision !== (await head())) throw Error("replica_current_state_required");
  let tail = Promise.resolve();
  const flush = () => {
    const target = Number(
      db.prepare("SELECT COALESCE(MAX(seq),0) n FROM edge_replica_changes").get()!.n,
    );
    const work = async () => {
      await reconcile();
      for (;;) {
        const changes = db
          .prepare(`SELECT seq,kind,id,ciphertext FROM edge_replica_changes
WHERE seq IN (SELECT MAX(seq) FROM edge_replica_changes WHERE seq<=? GROUP BY kind,id)
ORDER BY seq LIMIT 100`)
          .all(target) as (Row & { seq: number })[];
        if (!changes.length) return;
        const records: Row[] = [];
        let through = 0;
        for (const { seq, ...row } of changes) {
          if (!validRow(row)) throw Error("replica_record_exceeds_central_limit");
          if (!validBatch([...records, row])) break;
          records.push(row);
          through = seq;
        }
        if (!records.length) throw Error("replica_record_too_large");
        const p = {
          request_id: randomUUID(),
          expected_revision: meta()!.revision,
          through,
          records,
        };
        // Durable request identity and exact payload precede the network attempt.
        db.prepare("INSERT INTO edge_replica_pending VALUES(1,?)").run(JSON.stringify(p));
        await reconcile();
      }
    };
    tail = tail.catch(() => {}).then(work);
    return tail;
  };
  await flush();
  return { flush, revision: () => meta()!.revision };
}
