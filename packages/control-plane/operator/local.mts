// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  mkdtempSync,
  realpathSync,
  readFileSync,
  writeFileSync,
  openSync,
  closeSync,
  readdirSync,
  lstatSync,
} from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { join, relative, isAbsolute, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { randomBytes, createHash } from "node:crypto";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { extractSnapshot } from "../src/migration-service.ts";
import { manifestOf } from "../src/snapshot.ts";
import { segmentSnapshot, importSegments } from "../src/import-service.ts";
const marker = "kadenco-local-fixture-v1";
const save = (path: string, value: unknown) =>
  writeFileSync(path, JSON.stringify(value, null, 2), { mode: 0o600 });
export function fixtureRoot(path: string) {
  const root = realpathSync(path),
    rel = relative(realpathSync(tmpdir()), root);
  if (
    !rel ||
    rel.startsWith("..") ||
    isAbsolute(rel) ||
    readFileSync(join(root, "FIXTURE_ONLY"), "utf8") !== marker
  )
    throw Error("fixture_path_required");
  const inspect = (dir: string) => {
    for (const entry of readdirSync(dir)) {
      const item = join(dir, entry),
        stat = lstatSync(item);
      if (stat.isSymbolicLink()) throw Error("fixture_symlink_refused");
      if (stat.isDirectory()) inspect(item);
    }
  };
  inspect(root);
  return root;
}
export function bootstrap() {
  const root = mkdtempSync(join(tmpdir(), "kadenco-staging-"));
  writeFileSync(join(root, "FIXTURE_ONLY"), marker, { mode: 0o600 });
  writeFileSync(join(root, "test-only-key"), randomBytes(32), { mode: 0o600 });
  const db = new DatabaseSync(join(root, "fixture.db"));
  db.exec(
    "CREATE TABLE records(kind TEXT,id TEXT,value TEXT,PRIMARY KEY(kind,id));CREATE TABLE audit(seq INTEGER PRIMARY KEY,action TEXT);CREATE TABLE fixture_control(id INTEGER PRIMARY KEY,quiesced INTEGER);INSERT INTO fixture_control VALUES(1,0)",
  );
  const put = db.prepare("INSERT INTO records VALUES(?,?,?)");
  for (const [kind, id] of [
    ["subscription", "standing-fixture"],
    ["command", "uncertain-fixture"],
    ["collaboration.grant", "guest-fixture"],
  ])
    put.run(kind, id, "opaque-test-envelope-" + id);
  db.close();
  save(join(root, "deployment.json"), {
    fixture_only: true,
    production_enabled: false,
    callback_delivery: false,
    native_effects: "mock_only",
  });
  return root;
}
export function quiesce(path: string) {
  const root = fixtureRoot(path),
    db = new DatabaseSync(join(root, "fixture.db"));
  db.exec("UPDATE fixture_control SET quiesced=1 WHERE id=1");
  db.close();
  return { fixture_quiesced: true, real_old_writer_retired: false };
}
export function snapshot(path: string) {
  const root = fixtureRoot(path),
    db = new DatabaseSync(join(root, "fixture.db"));
  try {
    const value = extractSnapshot(db, "fixture-migration", "test-only-key-lineage", () => {
      if (db.prepare("SELECT quiesced FROM fixture_control WHERE id=1").get()?.quiesced !== 1)
        throw Error("fixture_not_quiesced");
    });
    save(join(root, "manifest.json"), manifestOf(value));
    save(
      join(root, "segments.json"),
      segmentSnapshot(value, readFileSync(join(root, "test-only-key"))),
    );
    return { records: value.records.length, snapshot: value.source_snapshot };
  } finally {
    db.close();
  }
}
export async function migrate(path: string) {
  const root = fixtureRoot(path),
    token = "synthetic-local-owner",
    hash = createHash("sha256").update(token).digest("hex");
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      scriptPath: fileURLToPath(new URL("../dist/worker.js", import.meta.url)),
      compatibilityDate: "2026-10-30",
      compatibilityFlags: ["nodejs_compat"],
      durableObjects: { FLEETS: { className: "FleetState", useSQLite: true } },
      durableObjectsPersist: join(root, "workerd-state"),
      bindings: {
        AUTH_POLICY: JSON.stringify({
          revision: 1,
          fleet: "fixture",
          principals: [
            {
              id: "owner",
              role: "owner",
              tokenSha256: hash,
              hosts: ["fixture"],
              expiresAt: 4102444800000,
            },
          ],
        }),
      },
    }),
  );
  try {
    const call = async (op: string, p: object) => {
      const r = await mf.dispatchFetch("https://fixture.invalid/" + op, {
        method: "POST",
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        body: JSON.stringify(p),
      });
      return (await r.json()) as Record<string, unknown>;
    };
    const result = await importSegments(
      JSON.parse(readFileSync(join(root, "segments.json"), "utf8")),
      readFileSync(join(root, "test-only-key")),
      JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")),
      call,
    );
    const denied = await call("activate", { expected_epoch: 0, migration_id: "fixture-migration" });
    if (denied.reason !== "cutover_not_implemented") throw Error("activation_guard_failed");
    save(join(root, "acceptance.json"), {
      ...result,
      activation_denied: true,
      production_changed: false,
    });
    return result;
  } finally {
    await mf.dispose();
  }
}
/** Export CURRENT fixture state to a fresh candidate. Never overwrite source or restore an old snapshot. */
export function rollback(path: string) {
  const root = fixtureRoot(path),
    output = join(root, "rollback-current.db");
  try {
    closeSync(openSync(output, "wx", 0o600));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      throw Error("rollback_candidate_exists");
    throw error;
  }
  const source = new DatabaseSync(join(root, "fixture.db"), { readOnly: true }),
    target = new DatabaseSync(output);
  try {
    source.exec("BEGIN");
    target.exec(
      "CREATE TABLE records(kind TEXT,id TEXT,value TEXT,PRIMARY KEY(kind,id));BEGIN IMMEDIATE",
    );
    const rows = source.prepare("SELECT kind,id,value FROM records ORDER BY kind,id").all();
    const insert = target.prepare("INSERT INTO records VALUES(?,?,?)");
    for (const r of rows) insert.run(r.kind, r.id, r.value);
    target.exec("COMMIT");
    source.exec("COMMIT");
    save(join(root, "rollback-report.json"), {
      source: "CURRENT fixture.db",
      records: rows.length,
      production_rollback_permitted: false,
    });
    return { records: rows.length, production_rollback_permitted: false };
  } finally {
    source.close();
    target.close();
  }
}
const args = process.argv.slice(2);
if (args[0] === "--fixture") {
  const [_, action, path] = args;
  if (action === "bootstrap")
    console.log(JSON.stringify({ fixture: bootstrap(), production_enabled: false }));
  else if (action === "quiesce") console.log(JSON.stringify(quiesce(path)));
  else if (action === "snapshot") console.log(JSON.stringify(snapshot(path)));
  else if (action === "migrate") console.log(JSON.stringify(await migrate(path)));
  else if (action === "rollback") console.log(JSON.stringify(rollback(path)));
  else throw Error("unknown_fixture_action");
} else if (import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  throw Error("fixture_mode_required");
