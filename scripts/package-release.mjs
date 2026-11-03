// SPDX-License-Identifier: AGPL-3.0-or-later
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { checkRelease } from "./release-check.mjs";
import { verifyWorkerBuild } from "./worker-provenance.mjs";

const root = resolve(import.meta.dirname, ".."),
  output = join(root, "release-output");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
checkRelease(
  pkg,
  JSON.parse(readFileSync(join(root, "package-lock.json"), "utf8")),
  readFileSync(join(root, "CHANGELOG.md"), "utf8"),
);
const run = (command, args, cwd, capture = false) => {
  const r = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: capture ? "pipe" : "inherit",
    windowsHide: true,
  });
  if (r.error) throw r.error;
  if (r.status !== 0) {
    if (capture && r.stderr) process.stderr.write(r.stderr.slice(-8192));
    throw Error(`release_command_failed:${command}:${r.status}`);
  }
  return r.stdout?.trim();
};
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
// Release production is intentionally Linux CI; avoid shell execution on Windows.
if (process.platform === "win32") throw Error("release_builder_requires_linux_ci");
const source = run("git", ["rev-parse", "HEAD"], root, true);
if (run("git", ["status", "--porcelain", "--untracked-files=normal"], root, true))
  throw Error("release_requires_clean_checkout");
const central = join(root, "packages/control-plane"),
  centralBuild = JSON.parse(readFileSync(join(central, "dist/edge-build.json"), "utf8"));
const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
if (
  centralBuild.source !== source ||
  centralBuild.dirty ||
  centralBuild.package_version !== pkg.version ||
  centralBuild.sha256 !== digest(join(central, "dist/edge-runtime.mjs"))
)
  throw Error("central_release_provenance_mismatch");
for (const [name, hash] of Object.entries(centralBuild.sidecar_modules))
  if (digest(join(root, "dist", name)) !== hash) throw Error("central_sidecar_artifact_mismatch");
for (const [name, hash] of Object.entries(centralBuild.dependency_locks))
  if (digest(join(root, name)) !== hash) throw Error("central_dependency_lock_mismatch");
verifyWorkerBuild(join(central, ".cloudflare/output"), { source, version: pkg.version });
mkdirSync(output); // Refuse replacement of an earlier artifact set.
const temp = mkdtempSync(join(tmpdir(), "kadenco-release-"));
try {
  const stage = join(temp, "stage"),
    extracted = join(temp, "extracted");
  mkdirSync(stage);
  mkdirSync(extracted);
  for (const file of [
    "dist",
    "src",
    "docs",
    "package.json",
    "package-lock.json",
    "README.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "COMPATIBILITY.md",
    "CHANGELOG.md",
    "RELEASE.md",
  ])
    cpSync(join(root, file), join(stage, file), { recursive: true });
  mkdirSync(join(stage, "scripts"));
  const stagedCentral = join(stage, "packages/control-plane");
  mkdirSync(stagedCentral, { recursive: true });
  cpSync(join(central, "dist"), join(stagedCentral, "dist"), { recursive: true });
  mkdirSync(join(stagedCentral, "operator"));
  cpSync(join(central, "operator/run-edge.mjs"), join(stagedCentral, "operator/run-edge.mjs"));
  for (const file of [
    "agent-client.mjs",
    "agent-tool.mjs",
    "caller-client.mjs",
    "caller-mcp.mjs",
    "caller.mjs",
    "pi-eddie.mjs",
    "worker-provenance.mjs",
  ])
    cpSync(join(root, "scripts", file), join(stage, "scripts", file));
  const provenance = {
    version: pkg.version,
    source,
    workflow: process.env.GITHUB_WORKFLOW ?? null,
    run_id: process.env.GITHUB_RUN_ID ?? null,
    run_attempt: process.env.GITHUB_RUN_ATTEMPT ?? null,
    node: process.version,
  };
  writeFileSync(join(stage, "BUILD.json"), JSON.stringify(provenance, null, 2) + "\n");
  cpSync(join(root, "package-lock.json"), join(stage, "npm-shrinkwrap.json"));
  const staged = {
    ...pkg,
    scripts: { start: "node dist/main.mjs" },
    files: [
      "dist",
      "packages/control-plane/dist",
      "packages/control-plane/operator/run-edge.mjs",
      "scripts",
      "src",
      "docs",
      "npm-shrinkwrap.json",
      "BUILD.json",
      "README.md",
      "LICENSE",
      "NOTICE",
      "SECURITY.md",
      "COMPATIBILITY.md",
      "CHANGELOG.md",
      "RELEASE.md",
    ],
  };
  writeFileSync(join(stage, "package.json"), JSON.stringify(staged, null, 2) + "\n");
  const packed = JSON.parse(
    run(npm, ["pack", "--ignore-scripts", "--json", "--pack-destination", output], stage, true),
  );
  const filename = packed[0].filename;
  run("tar", ["-xzf", join(output, filename), "-C", extracted], root);
  const unpacked = join(extracted, "package");
  run(npm, ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], unpacked);
  run(process.execPath, [join(root, "scripts/smoke-package.mjs"), unpacked], root);
  writeFileSync(
    join(output, "sbom.cdx.json"),
    run(
      npm,
      ["sbom", "--omit=dev", "--package-lock-only", "--sbom-format=cyclonedx"],
      unpacked,
      true,
    ) + "\n",
  );
  writeFileSync(join(output, "BUILD.json"), JSON.stringify(provenance, null, 2) + "\n");
  cpSync(join(root, "CHANGELOG.md"), join(output, "CHANGELOG.md"));
  const workerArchive = `kadenco-control-plane-${pkg.version}.tar.gz`;
  run("tar", ["-czf", join(output, workerArchive), "-C", central, ".cloudflare/output"], root);
  const names = [filename, workerArchive, "sbom.cdx.json", "BUILD.json", "CHANGELOG.md"];
  writeFileSync(
    join(output, "SHA256SUMS"),
    names
      .map(
        (name) =>
          createHash("sha256")
            .update(readFileSync(join(output, name)))
            .digest("hex") +
          "  " +
          name,
      )
      .join("\n") + "\n",
  );
  console.log(JSON.stringify({ ...provenance, artifact: filename, smoke: "passed" }));
} finally {
  rmSync(temp, { recursive: true, force: true });
}
