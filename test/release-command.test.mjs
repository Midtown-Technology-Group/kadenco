// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { ReleaseState, advanceRelease } from "../scripts/release-state.mjs";
import {
  verifyArtifacts,
  safeArchiveListing,
  installationDigest,
  assertReleaseMain,
} from "../scripts/release.mjs";
test("advanced main refuses before recording or dispatching any release effect", () =>
  fixture(async (dir) => {
    const state = new ReleaseState(join(dir, "state.db"), identity),
      p = ports();
    try {
      p.preflight = async () => assertReleaseMain("b".repeat(40), identity.source);
      await assert.rejects(advanceRelease(state, p), /release_main_not_at_source/);
      assert.equal(state.value.pending, null);
      assert.deepEqual(p.writes, []);
      assertReleaseMain(identity.source, identity.source);
    } finally {
      state.close();
    }
  }));
const identity = {
  repository: "fixture/kadenco",
  source: "a".repeat(40),
  version: "0.1.0-beta.1",
  request_id: "00000000-0000-4000-8000-000000000001",
};
function fixture(fn) {
  const dir = mkdtempSync(join(tmpdir(), "kadenco-release-test-"));
  return Promise.resolve()
    .then(() => fn(dir))
    .finally(() => rmSync(dir, { recursive: true, force: true }));
}
function ports() {
  const receipts = new Map(),
    writes = [];
  const p = {
    receipts,
    writes,
    preflight: async () => {},
    findRun: async () =>
      receipts.has("dispatch")
        ? { done: true, receipt: receipts.get("dispatch") }
        : { done: false },
    dispatch: async () => {
      writes.push("dispatch");
      receipts.set("dispatch", { id: 42 });
    },
    build: async () => ({ status: "completed", conclusion: "success" }),
    qualify: async () => ({ files: { "artifact.tgz": { digest: "fixture" } } }),
    probe: async (stage) =>
      receipts.has(stage) ? { done: true, receipt: receipts.get(stage) } : { done: false },
    apply: async (stage) => {
      writes.push(stage);
      receipts.set(stage, { stage, source: identity.source });
    },
  };
  return p;
}
test("release command resumes after a lost write response without repeating any external effect", () =>
  fixture(async (dir) => {
    const path = join(dir, "state.db"),
      p = ports();
    let state = new ReleaseState(path, identity);
    const apply = p.apply;
    p.apply = async (stage) => {
      await apply(stage);
      if (stage === "release") throw Error("lost_response");
    };
    await assert.rejects(advanceRelease(state, p, true), /lost_response/);
    state.close();
    state = new ReleaseState(path, identity);
    p.apply = apply;
    assert.equal((await advanceRelease(state, p, true)).state, "deployed");
    const before = [...p.writes];
    assert.equal((await advanceRelease(state, p, true)).state, "deployed");
    assert.deepEqual(p.writes, before);
    assert.equal(p.writes.filter((x) => x === "release").length, 1);
    state.close();
  }));
test("unknown dispatch remains pending across reopen; a missing response never dispatches again", () =>
  fixture(async (dir) => {
    const path = join(dir, "state.db"),
      p = ports();
    p.dispatch = async () => {
      p.writes.push("dispatch");
      throw Error("uncertain");
    };
    let state = new ReleaseState(path, identity);
    await assert.rejects(advanceRelease(state, p), /uncertain/);
    state.close();
    state = new ReleaseState(path, identity);
    await assert.rejects(advanceRelease(state, p), /release_outcome_unknown:dispatch/);
    assert.deepEqual(p.writes, ["dispatch"]);
    state.close();
  }));
test("an actual crashed release process retains the pending dispatch and can be reconciled by a new owner", () =>
  fixture(async (dir) => {
    const path = join(dir, "state.db"),
      script = join(dir, "crash.mjs");
    writeFileSync(
      script,
      `import {ReleaseState} from ${JSON.stringify(new URL("../scripts/release-state.mjs", import.meta.url).href)};const s=new ReleaseState(${JSON.stringify(path)},${JSON.stringify(identity)});await s.effect('dispatch',async()=>({done:false}),async()=>process.exit(17));`,
    );
    assert.equal(
      spawnSync(process.execPath, [script], { encoding: "utf8", timeout: 10000, windowsHide: true })
        .status,
      17,
    );
    const state = new ReleaseState(path, identity);
    assert.equal(state.value.pending, "dispatch");
    const p = ports();
    p.receipts.set("dispatch", { id: 42 });
    assert.equal((await advanceRelease(state, p)).state, "published");
    assert.equal(p.writes.includes("dispatch"), false);
    state.close();
  }));
test("active release ownership, changed identity and changed retained receipts fail closed", () =>
  fixture(async (dir) => {
    const path = join(dir, "state.db"),
      s = new ReleaseState(path, identity);
    assert.throws(() => new ReleaseState(path, identity), /release_already_running/);
    const p = ports();
    await advanceRelease(s, p);
    p.receipts.set("tag", { stage: "tag", source: "b".repeat(40) });
    await assert.rejects(advanceRelease(s, p), /release_receipt_changed:tag/);
    s.close();
    assert.throws(
      () => new ReleaseState(path, { ...identity, source: "b".repeat(40) }),
      /release_identity_changed/,
    );
  }));
test("pending or failed builds cannot publish; consumed artifacts are revalidated on every resume", () =>
  fixture(async (dir) => {
    const s = new ReleaseState(join(dir, "state.db"), identity),
      p = ports();
    p.build = async () => ({ status: "in_progress" });
    assert.equal((await advanceRelease(s, p)).state, "waiting");
    assert.deepEqual(p.writes, ["dispatch"]);
    p.build = async () => ({ status: "completed", conclusion: "failure" });
    await assert.rejects(advanceRelease(s, p), /release_build_failed/);
    p.build = async () => ({ status: "completed", conclusion: "success" });
    p.qualify = async () => {
      throw Error("tampered_artifact");
    };
    await assert.rejects(advanceRelease(s, p), /tampered_artifact/);
    assert.deepEqual(p.writes, ["dispatch"]);
    s.close();
  }));
test("artifact qualification binds source/run/attempt and all bytes; archive traversal and links refuse", () =>
  fixture(async (dir) => {
    const names = [
      "BUILD.json",
      "CHANGELOG.md",
      "sbom.cdx.json",
      `kadenco-${identity.version}.tgz`,
      `kadenco-control-plane-${identity.version}.tar.gz`,
    ];
    for (const n of names)
      writeFileSync(
        join(dir, n),
        n === "BUILD.json"
          ? JSON.stringify({
              ...identity,
              run_id: "42",
              run_attempt: "1",
              workflow: "Release artifact",
            })
          : "fixture bytes",
      );
    const { readFileSync } = await import("node:fs");
    writeFileSync(
      join(dir, "SHA256SUMS"),
      names
        .map(
          (n) =>
            createHash("sha256")
              .update(readFileSync(join(dir, n)))
              .digest("hex") +
            "  " +
            n,
        )
        .join("\n"),
    );
    assert.equal(Object.keys(verifyArtifacts(dir, identity, { id: 42 })).length, 6);
    assert.throws(() => verifyArtifacts(dir, identity, { id: 43 }), /release_producer_mismatch/);
    writeFileSync(join(dir, "CHANGELOG.md"), "changed");
    assert.throws(() => verifyArtifacts(dir, identity, { id: 42 }), /release_checksum_mismatch/);
    for (const entry of ["../bad", "/absolute", "C:/absolute", "dir/../../bad", "..\\bad"])
      assert.throws(() => safeArchiveListing([entry], []), /release_unsafe_archive/);
    assert.throws(
      () => safeArchiveListing(["package/file"], ["lrwxrwx link"]),
      /release_unsafe_archive/,
    );
  }));

test("accepted deployment waits for real readiness and never reexecutes the promotion", () =>
  fixture(async (dir) => {
    const path = join(dir, "state.db"),
      p = ports();
    let ready = false;
    const probe = p.probe;
    p.probe = async (stage) =>
      stage === "deploy" && p.receipts.has(stage) && !ready ? { pending: true } : probe(stage);
    let state = new ReleaseState(path, identity);
    assert.equal((await advanceRelease(state, p, true)).stage, "deploy");
    state.close();
    state = new ReleaseState(path, identity);
    assert.equal((await advanceRelease(state, p, true)).stage, "deploy");
    ready = true;
    assert.equal((await advanceRelease(state, p, true)).state, "deployed");
    assert.equal(p.writes.filter((x) => x === "deploy").length, 1);
    state.close();
  }));
test("extracted installation fingerprint includes operator scripts and rejects changes after qualification", () =>
  fixture(async (dir) => {
    writeFileSync(join(dir, "run-edge.mjs"), "original");
    const before = installationDigest(dir);
    writeFileSync(join(dir, "QUALIFIED.json"), "metadata");
    assert.equal(installationDigest(dir), before);
    writeFileSync(join(dir, "run-edge.mjs"), "modified");
    assert.notEqual(installationDigest(dir), before);
  }));
