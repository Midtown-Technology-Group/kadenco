// SPDX-License-Identifier: AGPL-3.0-or-later
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { recordWorkerBuild } from "../../../scripts/worker-provenance.mjs";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const directory = fileURLToPath(new URL("../", import.meta.url));
const git = (args) =>
  execFileSync("git", args, { cwd: root, encoding: "utf8", windowsHide: true }).trim();
const source = git(["rev-parse", "HEAD"]),
  before = git(["status", "--porcelain"]);
execFileSync(
  process.execPath,
  [join(directory, "node_modules/cf/bin/cf"), "build", "--mode", "production"],
  { cwd: directory, stdio: "inherit", windowsHide: true },
);
const after = git(["status", "--porcelain"]);
if (source !== git(["rev-parse", "HEAD"]) || before !== after)
  throw Error("worker_source_changed_during_build");
const manifest = recordWorkerBuild(join(directory, ".cloudflare/output"), {
  source,
  version: JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version,
  dirty: before !== "",
});
console.log(
  JSON.stringify({
    worker_build_source: manifest.source,
    files: Object.keys(manifest.files).length,
    dirty: manifest.dirty,
  }),
);
