// SPDX-License-Identifier: AGPL-3.0-or-later
import { isDeepStrictEqual } from "node:util";
import { DatabaseSync } from "node:sqlite";
import { randomUUID } from "node:crypto";

export function releaseIdentity(value) {
  if (
    !value ||
    Object.keys(value).some(
      (k) => !["repository", "source", "version", "request_id"].includes(k),
    ) ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(value.repository) ||
    !/^[a-f0-9]{40}$/.test(value.source) ||
    !/^\d+\.\d+\.\d+(?:-(?:alpha|beta|rc)\.\d+)?$/.test(value.version) ||
    !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(value.request_id)
  )
    throw Error("invalid_release_identity");
  return value;
}

/** One owner, one immutable identity. A pending external effect is reconciled,
 * never reissued merely because its response or the process was lost. */
export class ReleaseState {
  constructor(path, identity) {
    releaseIdentity(identity);
    this.db = new DatabaseSync(path);
    this.nonce = randomUUID();
    try {
      const names = this.db
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .all()
        .map((r) => r.name);
      if (names.some((n) => !["release_state", "release_owner"].includes(n)))
        throw Error("release_state_refused");
      this.db.exec(
        "PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000; CREATE TABLE IF NOT EXISTS release_state(id INTEGER PRIMARY KEY CHECK(id=1),value TEXT NOT NULL); CREATE TABLE IF NOT EXISTS release_owner(id INTEGER PRIMARY KEY CHECK(id=1),pid INTEGER NOT NULL,nonce TEXT NOT NULL)",
      );
      this.db.exec("BEGIN IMMEDIATE");
      const owner = this.db.prepare("SELECT pid FROM release_owner WHERE id=1").get();
      if (owner) {
        try {
          process.kill(owner.pid, 0);
          throw Error("release_already_running");
        } catch (e) {
          if (e.code !== "ESRCH") throw e;
        }
      }
      const row = this.db.prepare("SELECT value FROM release_state WHERE id=1").get();
      this.value = row ? JSON.parse(row.value) : { schema: 1, identity, pending: null, phases: {} };
      if (this.value.schema !== 1 || !isDeepStrictEqual(this.value.identity, identity))
        throw Error("release_identity_changed");
      this.db
        .prepare("INSERT OR REPLACE INTO release_owner VALUES(1,?,?)")
        .run(process.pid, this.nonce);
      this.db
        .prepare("INSERT OR IGNORE INTO release_state VALUES(1,?)")
        .run(JSON.stringify(this.value));
      this.db.exec("COMMIT");
    } catch (e) {
      if (this.db.isTransaction) this.db.exec("ROLLBACK");
      this.db.close();
      throw e;
    }
  }
  save() {
    const changed = this.db
      .prepare(
        "UPDATE release_state SET value=? WHERE id=1 AND EXISTS(SELECT 1 FROM release_owner WHERE id=1 AND nonce=?)",
      )
      .run(JSON.stringify(this.value), this.nonce).changes;
    if (changed !== 1) throw Error("release_owner_changed");
  }
  close() {
    this.db.prepare("DELETE FROM release_owner WHERE nonce=?").run(this.nonce);
    this.db.close();
  }
  async effect(name, probe, execute) {
    const observed = await probe();
    if (observed?.done === true) {
      const prior = this.value.phases[name];
      if (prior && !isDeepStrictEqual(prior, observed.receipt))
        throw Error("release_receipt_changed:" + name);
      this.value.phases[name] = observed.receipt;
      if (this.value.pending === name) this.value.pending = null;
      this.save();
      return observed.receipt;
    }
    if (this.value.phases[name]) throw Error("release_evidence_missing:" + name);
    if (observed?.pending === true) {
      if (this.value.pending && this.value.pending !== name)
        throw Error("release_outcome_unknown:" + this.value.pending);
      this.value.pending = name;
      this.save();
      return null;
    }
    if (this.value.pending) throw Error("release_outcome_unknown:" + this.value.pending);
    this.value.pending = name;
    this.save();
    await execute();
    const result = await probe();
    if (result?.pending === true) return null;
    if (result?.done !== true) throw Error("release_outcome_unknown:" + name);
    this.value.phases[name] = result.receipt;
    this.value.pending = null;
    this.save();
    return result.receipt;
  }
}

export async function advanceRelease(state, ports, deploy = false) {
  await ports.preflight(state.value.identity);
  const run = await state.effect(
    "dispatch",
    () => ports.findRun(),
    () => ports.dispatch(),
  );
  const build = await ports.build(run);
  if (build.status !== "completed") return { state: "waiting", stage: "build", run_id: run.id };
  if (build.conclusion !== "success") throw Error("release_build_failed");
  // Always revalidate consumed bytes, including on a resumed published release.
  const artifacts = await ports.qualify(run);
  if (state.value.qualification && state.value.qualification !== artifacts.manifest)
    throw Error("release_qualification_changed");
  if (artifacts.manifest) {
    state.value.qualification = artifacts.manifest;
    state.save();
  }
  for (const stage of [
    "tag",
    "release",
    ...Object.keys(artifacts.files).map((n) => "asset:" + n),
    "publish",
  ]) {
    await state.effect(
      stage,
      () => ports.probe(stage, artifacts),
      () => ports.apply(stage, artifacts),
    );
  }
  if (deploy) {
    const deployed = await state.effect(
      "deploy",
      () => ports.probe("deploy", artifacts),
      () => ports.apply("deploy", artifacts),
    );
    if (!deployed)
      return { state: "waiting", stage: "deploy", ...state.value.identity, run_id: run.id };
  }
  return { state: deploy ? "deployed" : "published", ...state.value.identity, run_id: run.id };
}
