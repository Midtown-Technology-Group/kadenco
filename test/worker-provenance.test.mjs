// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, unlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { recordWorkerBuild, verifyWorkerBuild } from "../scripts/worker-provenance.mjs";
const identity = { source: "1".repeat(40), version: "0.1.0-alpha.7" };
function fixture(run) {
  const root = mkdtempSync(join(tmpdir(), "kadenco-worker-provenance-"));
  const worker = join(root, "v0/workers/default");
  mkdirSync(worker, { recursive: true });
  writeFileSync(
    join(worker, "worker.config.json"),
    JSON.stringify({ name: "kadenco-control-plane", previewUrls: false }),
  );
  writeFileSync(
    join(worker, "worker.js"),
    'export default {fetch(){return new Response("fixture")}}',
  );
  recordWorkerBuild(root, { ...identity, dirty: false });
  try {
    run(root, worker);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
test("production Worker provenance binds exact source, version and output bytes", () =>
  fixture((root) => {
    const verified = verifyWorkerBuild(root, identity);
    assert.equal(Object.keys(verified.files).length, 2);
    assert.equal(verified.source, identity.source);
  }));
test("stale source, wrong version and dirty Worker output cannot be packaged", () =>
  fixture((root) => {
    assert.throws(
      () => verifyWorkerBuild(root, { ...identity, source: "2".repeat(40) }),
      /worker_release_provenance_mismatch/,
    );
    assert.throws(
      () => verifyWorkerBuild(root, { ...identity, version: "0.1.0-alpha.6" }),
      /worker_release_provenance_mismatch/,
    );
    recordWorkerBuild(root, { ...identity, dirty: true });
    assert.throws(() => verifyWorkerBuild(root, identity), /worker_release_provenance_mismatch/);
  }));
test("modified Worker module refuses promotion", () =>
  fixture((root, worker) => {
    writeFileSync(join(worker, "worker.js"), "changed after build");
    assert.throws(() => verifyWorkerBuild(root, identity), /worker_release_bytes_mismatch/);
  }));
test("missing Worker module refuses promotion", () =>
  fixture((root, worker) => {
    unlinkSync(join(worker, "worker.js"));
    assert.throws(() => verifyWorkerBuild(root, identity), /worker_release_bytes_mismatch/);
  }));
test("unrecorded Worker output refuses promotion", () =>
  fixture((root, worker) => {
    writeFileSync(join(worker, "extra.js"), "unexpected module");
    assert.throws(() => verifyWorkerBuild(root, identity), /worker_release_bytes_mismatch/);
  }));
test("a recorded staging Worker cannot masquerade as production", () =>
  fixture((root, worker) => {
    writeFileSync(
      join(worker, "worker.config.json"),
      JSON.stringify({ name: "kadenco-control-plane-staging", previewUrls: false }),
    );
    recordWorkerBuild(root, { ...identity, dirty: false });
    assert.throws(() => verifyWorkerBuild(root, identity), /production_worker_artifact_required/);
  }));
