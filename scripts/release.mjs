// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  readFileSync,
  writeFileSync,
  mkdirSync,
  existsSync,
  readdirSync,
  lstatSync,
} from "node:fs";
import { join, resolve, dirname, isAbsolute } from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { ReleaseState, advanceRelease, releaseIdentity } from "./release-state.mjs";
import { verifyWorkerBuild } from "./worker-provenance.mjs";

const digest = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
export function installationDigest(root) {
  const files = {};
  const walk = (directory, prefix = "") => {
    for (const name of readdirSync(directory).sort()) {
      if (!prefix && ["node_modules", "QUALIFIED.json"].includes(name)) continue;
      const path = join(directory, name),
        relative = prefix + name,
        stat = lstatSync(path);
      if (stat.isSymbolicLink() || (!stat.isDirectory() && (!stat.isFile() || stat.nlink !== 1)))
        throw Error("release_installation_alias");
      if (stat.isDirectory()) walk(path, relative + "/");
      else files[relative] = digest(path);
    }
  };
  walk(root);
  return createHash("sha256").update(JSON.stringify(files)).digest("hex");
}
export function verifyArtifacts(directory, identity, run) {
  const build = JSON.parse(readFileSync(join(directory, "BUILD.json"), "utf8"));
  if (
    build.source !== identity.source ||
    build.version !== identity.version ||
    build.run_id !== String(run.id) ||
    build.run_attempt !== "1" ||
    build.workflow !== "Release artifact"
  )
    throw Error("release_producer_mismatch");
  const names = [
    "BUILD.json",
    "CHANGELOG.md",
    "sbom.cdx.json",
    "SHA256SUMS",
    `kadenco-${identity.version}.tgz`,
    `kadenco-control-plane-${identity.version}.tar.gz`,
  ];
  const lines = readFileSync(join(directory, "SHA256SUMS"), "utf8").trim().split(/\r?\n/);
  const checked = new Set();
  for (const line of lines) {
    const m = /^([a-f0-9]{64})\s+\*?([^/\\]+)$/.exec(line);
    if (!m || !names.includes(m[2]) || checked.has(m[2]) || digest(join(directory, m[2])) !== m[1])
      throw Error("release_checksum_mismatch");
    checked.add(m[2]);
  }
  if (checked.size !== 5 || names.filter((n) => n !== "SHA256SUMS").some((n) => !checked.has(n)))
    throw Error("release_incomplete_artifacts");
  return Object.fromEntries(
    names.map((n) => [
      n,
      {
        size: readFileSync(join(directory, n)).length,
        digest: "sha256:" + digest(join(directory, n)),
      },
    ]),
  );
}
export function safeArchiveListing(entries, details) {
  if (
    !entries.length ||
    entries.some((p) => /^[\\/]|^[A-Za-z]:|(^|[\\/])\.\.([\\/]|$)/.test(p)) ||
    details.some((p) => /^[lh]/.test(p))
  )
    throw Error("release_unsafe_archive");
}
function run(command, args, cwd, input) {
  const r = spawnSync(command, args, {
    cwd,
    input,
    encoding: "utf8",
    windowsHide: true,
    timeout: 180000,
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.error || r.status !== 0)
    throw Error(
      "release_command_failed:" + command.replace(/^.*[\\/]/, "") + ":" + (r.status ?? "unknown"),
    );
  return r.stdout.trim(); // Never print stderr, private operator input or auth state.
}
export function githubPorts(plan, root, directory) {
  const identity = releaseIdentity(plan.identity),
    repo = identity.repository;
  const gh = (args) => run("gh", args, root);
  const api = (path) => JSON.parse(gh(["api", `repos/${repo}/${path}`]));
  const tag = "v" + identity.version,
    marker = "Release " + identity.request_id;
  const artifacts = join(directory, "artifacts"),
    installation = join(directory, "installation");
  let release, files;
  const releases = () => {
    const found = [];
    for (let page = 1; page <= 100; page++) {
      const rows = api(`releases?per_page=100&page=${page}`);
      found.push(...rows.filter((r) => r.tag_name === tag));
      if (rows.length < 100) break;
      if (page === 100) throw Error("release_inventory_incomplete");
    }
    if (found.length > 1) throw Error("release_identity_ambiguous");
    return found[0];
  };
  const jsonWrite = (path, body) => {
    const file = join(directory, "api-input.json");
    writeFileSync(file, JSON.stringify(body));
    return JSON.parse(gh(["api", "--method", "POST", `repos/${repo}/${path}`, "--input", file]));
  };
  return {
    async preflight() {
      const main = api("git/ref/heads/main").object.sha;
      run("git", ["fetch", "--no-tags", "origin", "main"], root);
      if (run("git", ["rev-parse", "FETCH_HEAD"], root) !== main) throw Error("release_main_raced");
      run("git", ["merge-base", "--is-ancestor", identity.source, main], root);
      if (run("git", ["rev-parse", "HEAD"], root) !== identity.source)
        throw Error("release_checkout_source_mismatch");
      const pkg = JSON.parse(run("git", ["show", identity.source + ":package.json"], root));
      if (pkg.version !== identity.version) throw Error("release_source_version_mismatch");
      if (
        gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]).toLowerCase() !==
        repo.toLowerCase()
      )
        throw Error("release_repository_mismatch");
      if (run("git", ["status", "--porcelain", "--untracked-files=normal"], root))
        throw Error("release_dirty_checkout");
    },
    async findRun() {
      const runs = api(
        "actions/workflows/release.yml/runs?event=workflow_dispatch&per_page=100",
      ).workflow_runs.filter((r) => r.head_sha === identity.source && r.display_title === marker);
      if (runs.length > 1) throw Error("release_duplicate_builds");
      return runs.length ? { done: true, receipt: { id: runs[0].id } } : { done: false };
    },
    async dispatch() {
      gh([
        "workflow",
        "run",
        "release.yml",
        "--repo",
        repo,
        "--ref",
        "main",
        "-f",
        "release_request_id=" + identity.request_id,
      ]);
    },
    async build(receipt) {
      const r = api("actions/runs/" + receipt.id);
      if (
        r.head_sha !== identity.source ||
        r.run_attempt !== 1 ||
        r.event !== "workflow_dispatch" ||
        r.display_title !== marker
      )
        throw Error("release_build_identity_changed");
      return r;
    },
    async qualify(receipt) {
      if (!existsSync(artifacts)) {
        mkdirSync(artifacts);
        gh([
          "run",
          "download",
          String(receipt.id),
          "--repo",
          repo,
          "--name",
          `kadenco-release-${identity.source}-1`,
          "--dir",
          artifacts,
        ]);
      }
      files = verifyArtifacts(artifacts, identity, receipt);
      if (!existsSync(installation)) {
        mkdirSync(installation);
        for (const [file, strip] of [
          [`kadenco-${identity.version}.tgz`, true],
          [`kadenco-control-plane-${identity.version}.tar.gz`, false],
        ]) {
          const path = join(artifacts, file);
          safeArchiveListing(
            run("tar", ["-tf", path], root).split(/\r?\n/),
            run("tar", ["-tvf", path], root).split(/\r?\n/),
          );
          run(
            "tar",
            ["-xf", path, "-C", installation, ...(strip ? ["--strip-components=1"] : [])],
            root,
          );
        }
        const npm = [
          join(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
          join(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
        ].find(existsSync);
        if (!npm) throw Error("release_existing_npm_required");
        run(process.execPath, [npm, "ci", "--omit=dev", "--ignore-scripts"], installation);
        run(process.execPath, [join(root, "scripts/smoke-package.mjs"), installation], root);
        writeFileSync(
          join(installation, "QUALIFIED.json"),
          JSON.stringify({
            source: identity.source,
            version: identity.version,
            manifest: installationDigest(installation),
          }),
        );
      }
      const qualified = JSON.parse(readFileSync(join(installation, "QUALIFIED.json"), "utf8"));
      if (qualified.source !== identity.source || qualified.version !== identity.version)
        throw Error("release_installation_unqualified");
      if (qualified.manifest !== installationDigest(installation))
        throw Error("release_installation_changed");
      verifyWorkerBuild(join(installation, ".cloudflare/output"), identity);
      const edge = JSON.parse(
        readFileSync(join(installation, "packages/control-plane/dist/edge-build.json"), "utf8"),
      );
      if (
        edge.source !== identity.source ||
        edge.package_version !== identity.version ||
        edge.dirty ||
        edge.sha256 !== digest(join(installation, "packages/control-plane/dist/edge-runtime.mjs"))
      )
        throw Error("release_edge_provenance_mismatch");
      for (const [name, hash] of Object.entries(edge.sidecar_modules))
        if (digest(join(installation, "dist", name)) !== hash)
          throw Error("release_sidecar_bytes_changed");
      return { files, installation, manifest: qualified.manifest };
    },
    async probe(stage) {
      if (stage === "tag") {
        const refs = run(
          "git",
          ["ls-remote", "origin", `refs/tags/${tag}`, `refs/tags/${tag}^{}`],
          root,
        )
          .split(/\r?\n/)
          .filter(Boolean);
        if (!refs.length) return { done: false };
        const target = (refs.find((r) => r.endsWith("^{}")) ?? refs[0]).split(/\s/)[0];
        if (target !== identity.source) throw Error("release_tag_changed");
        return { done: true, receipt: { tag, source: target } };
      }
      release = releases();
      if (stage === "release")
        return release ? { done: true, receipt: { id: release.id, tag } } : { done: false };
      if (!release) throw Error("release_missing");
      if (stage.startsWith("asset:") || stage === "publish") {
        for (const a of release.assets)
          if (!files[a.name] || a.digest !== files[a.name].digest || a.size !== files[a.name].size)
            throw Error("release_remote_asset_changed");
        if (stage.startsWith("asset:")) {
          const name = stage.slice(6);
          if (!files[name]) throw Error("unsupported_release_asset");
          return release.assets.some((a) => a.name === name)
            ? { done: true, receipt: { release: release.id, name, ...files[name] } }
            : { done: false };
        }
        if (release.assets.length !== Object.keys(files).length)
          throw Error("release_incomplete_remote_assets");
        if (!release.prerelease && identity.version.includes("-"))
          throw Error("release_prerelease_changed");
        return !release.draft
          ? { done: true, receipt: { id: release.id, published: true } }
          : { done: false };
      }
      if (stage === "deploy") {
        if (!plan.operatorRuntimeDirectory || !isAbsolute(plan.operatorRuntimeDirectory))
          throw Error("release_operator_binding_required");
        const path = join(
          plan.operatorRuntimeDirectory,
          "central-custody/promotions",
          identity.source + ".json",
        );
        if (!existsSync(path)) return { done: false };
        const bound = JSON.parse(readFileSync(path, "utf8"));
        if (bound.source !== identity.source || bound.version !== identity.version)
          throw Error("release_deployment_identity_changed");
        const r = JSON.parse(
          run(
            "powershell.exe",
            [
              "-NoProfile",
              "-NonInteractive",
              "-File",
              join(plan.operatorRuntimeDirectory, "central-promote-release.candidate.ps1"),
              "-Mode",
              "inspect",
              "-RuntimeDirectory",
              plan.operatorRuntimeDirectory,
              "-ReleaseRoot",
              installation,
              "-Source",
              identity.source,
              "-Version",
              identity.version,
            ],
            root,
          ),
        );
        if (r.source !== identity.source || r.version !== identity.version || !r.worker_version)
          throw Error("release_deployment_unverified");
        return r.verified === true
          ? { done: true, receipt: r }
          : r.pending === true
            ? { pending: true }
            : (() => {
                throw Error("release_deployment_unverified");
              })();
      }
      throw Error("unsupported_release_stage");
    },
    async apply(stage, qualified) {
      if (stage === "tag") {
        const local = run("git", ["tag", "-l", tag], root);
        if (local && run("git", ["rev-parse", tag + "^{}"], root) !== identity.source)
          throw Error("release_local_tag_changed");
        if (!local)
          run(
            "git",
            ["tag", "-a", tag, identity.source, "-m", "Kadenco " + identity.version],
            root,
          );
        run("git", ["push", "origin", "refs/tags/" + tag], root);
      } else if (stage === "release") {
        jsonWrite("releases", {
          tag_name: tag,
          target_commitish: identity.source,
          name: "Kadenco " + identity.version,
          draft: true,
          prerelease: identity.version.includes("-"),
          body: `Source: ${identity.source}\nProducer: Release artifact run ${plan.run_id ?? "recorded in BUILD.json"}, attempt 1.\nVerify SHA256SUMS and Worker provenance before deployment.`,
        });
      } else if (stage.startsWith("asset:")) {
        const name = stage.slice(6);
        if (!files[name]) throw Error("unsupported_release_asset");
        gh([
          "api",
          "--method",
          "POST",
          `https://uploads.github.com/repos/${repo}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`,
          "-H",
          "Content-Type: application/octet-stream",
          "--input",
          join(artifacts, name),
        ]);
      } else if (stage === "publish") {
        const file = join(directory, "api-input.json");
        writeFileSync(file, JSON.stringify({ draft: false }));
        gh(["api", "--method", "PATCH", `repos/${repo}/releases/${release.id}`, "--input", file]);
      } else if (stage === "deploy") {
        if (
          process.platform !== "win32" ||
          !plan.operatorRuntimeDirectory ||
          !isAbsolute(plan.operatorRuntimeDirectory)
        )
          throw Error("release_windows_operator_required");
        run(
          "powershell.exe",
          [
            "-NoProfile",
            "-NonInteractive",
            "-File",
            join(plan.operatorRuntimeDirectory, "central-promote-release.candidate.ps1"),
            "-RuntimeDirectory",
            plan.operatorRuntimeDirectory,
            "-ReleaseRoot",
            qualified.installation,
            "-Source",
            identity.source,
            "-Version",
            identity.version,
          ],
          root,
        );
      } else throw Error("unsupported_release_stage");
    },
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let state;
  try {
    const [path, flag, deployFlag] = process.argv.slice(2);
    if (
      !path ||
      !isAbsolute(path) ||
      flag !== "--apply" ||
      (deployFlag && deployFlag !== "--deploy") ||
      process.argv.length > 5
    )
      throw Error("usage: release.mjs ABSOLUTE_PLAN_JSON --apply [--deploy]");
    const plan = JSON.parse(readFileSync(path, "utf8"));
    releaseIdentity(plan.identity);
    const root = resolve(import.meta.dirname, ".."),
      directory = dirname(path);
    if (directory === root || directory.startsWith(root + "/") || directory.startsWith(root + "\\"))
      throw Error("release_state_must_be_outside_checkout");
    state = new ReleaseState(join(directory, "release-state.db"), plan.identity);
    console.log(
      JSON.stringify(
        await advanceRelease(state, githubPorts(plan, root, directory), deployFlag === "--deploy"),
      ),
    );
  } catch (e) {
    const reason = /^[a-zA-Z0-9_: .-]{1,160}$/.test(e.message) ? e.message : "release_failed";
    console.error(JSON.stringify({ reason, safe_to_reissue_unknown_effect: false }));
    process.exitCode = 1;
  } finally {
    state?.close();
  }
}
