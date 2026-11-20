// SPDX-License-Identifier: AGPL-3.0-or-later
// Fleet member self-update for the Eddie caller (MCP server, CLI, Pi extension).
// Installs the newest published Kadenco release whose package carries GitHub
// build provenance from this repository's release workflow on main, checks the
// new caller against the live Eddie server, then switches the stable `current`
// link that every provider catalog launches through. Never reads or logs the
// caller credential; the launcher reads it. See docs/fleet-update.md.
import { createHash, randomBytes } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import {
  appendFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const REPOSITORY = "Midtown-Technology-Group/kadenco";
export const SIGNER = `https://github.com/${REPOSITORY}/.github/workflows/release.yml@refs/heads/main`;
export const ISSUER = "https://token.actions.githubusercontent.com";
export const REQUIRED_TOOLS = [
  "ask_eddie",
  "get_eddie_reply",
  "acknowledge_eddie_reply",
  "acknowledge_thread_delivery",
  "get_eddie_conversation",
  "get_eddie_capabilities",
];
const API = "https://api.github.com";
const DOWNLOAD_PREFIX = `https://github.com/${REPOSITORY}/releases/download/`;
const DOWNLOAD_HOSTS = new Set([
  "github.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
]);
const isWindows = process.platform === "win32";
const LOCK_STALE_MS = 45 * 60 * 1000;

// ---------------------------------------------------------------- versions --
export function parseVersion(text) {
  const m =
    /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(
      text ?? "",
    );
  return m ? { core: [+m[1], +m[2], +m[3]], pre: m[4] ? m[4].split(".") : [] } : null;
}
/** SemVer 2.0 precedence. */
export function compareVersions(a, b) {
  const x = parseVersion(a),
    y = parseVersion(b);
  if (!x || !y) throw Error("update_version_invalid");
  for (let i = 0; i < 3; i++) if (x.core[i] !== y.core[i]) return x.core[i] < y.core[i] ? -1 : 1;
  // A prerelease sorts before its release.
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i],
      q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p),
      qn = /^\d+$/.test(q);
    if (pn && qn) {
      if (+p !== +q) return +p < +q ? -1 : 1;
    } else if (pn !== qn) return pn ? -1 : 1;
    else if (p !== q) return p < q ? -1 : 1;
  }
  return 0;
}
/** Newest published (non-draft) release strictly newer than `installed`. */
export function selectRelease(releases, installed) {
  let best = null;
  for (const release of releases) {
    if (!release || release.draft) continue;
    const m = /^v(.+)$/.exec(release.tag_name ?? "");
    if (!m || !parseVersion(m[1])) continue;
    if (installed && compareVersions(m[1], installed) <= 0) continue;
    if (!best || compareVersions(m[1], best.version) > 0) best = { version: m[1], release };
  }
  return best;
}

// --------------------------------------------------------------- integrity --
export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export function checksumFor(sums, name) {
  let found = null;
  for (const line of sums.trim().split(/\r?\n/)) {
    const m = /^([a-f0-9]{64})\s+\*?([^/\\\s]+)$/.exec(line);
    if (!m) throw Error("update_checksums_invalid");
    if (m[2] !== name) continue;
    if (found) throw Error("update_checksums_invalid");
    found = m[1];
  }
  if (!found) throw Error("update_checksum_missing");
  return found;
}
/** Checks the SLSA provenance statement GitHub signed for the package. */
export function checkStatement(statement, { digest, source, repository = REPOSITORY }) {
  if (
    statement?._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== "https://slsa.dev/provenance/v1"
  )
    throw Error("update_provenance_type");
  if (
    !Array.isArray(statement.subject) ||
    !statement.subject.some((s) => s?.digest?.sha256 === digest)
  )
    throw Error("update_provenance_subject");
  const build = statement.predicate?.buildDefinition,
    workflow = build?.externalParameters?.workflow;
  if (
    workflow?.repository !== `https://github.com/${repository}` ||
    workflow?.path !== ".github/workflows/release.yml" ||
    workflow?.ref !== "refs/heads/main"
  )
    throw Error("update_provenance_workflow");
  if (build?.internalParameters?.github?.runner_environment !== "github-hosted")
    throw Error("update_provenance_runner");
  if (
    !Array.isArray(build.resolvedDependencies) ||
    !build.resolvedDependencies.some((d) => d?.digest?.gitCommit === source)
  )
    throw Error("update_provenance_source");
}
/**
 * Accepts the package when at least one attestation bundle is signed by the
 * release workflow on main (Sigstore, GitHub OIDC issuer) and its statement
 * names this package digest and source commit.
 */
export async function verifyProvenance(
  bundles,
  { digest, source, verify, signer = SIGNER, repository },
) {
  for (const bundle of bundles) {
    try {
      if (bundle?.dsseEnvelope?.payloadType !== "application/vnd.in-toto+json") continue;
      await verify(bundle, { certificateIdentityURI: signer, certificateIssuer: ISSUER });
      const statement = JSON.parse(
        Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"),
      );
      checkStatement(statement, { digest, source, repository });
      return true;
    } catch {
      // Try the next attestation; none verifying refuses the update.
    }
  }
  throw Error("update_provenance_unverified");
}
/** Snappy block decoding (GitHub serves attestation bundles snappy-compressed). */
export function snappyDecode(input, max = 8 << 20) {
  const fail = () => {
    throw Error("update_bundle_encoding");
  };
  let pos = 0,
    length = 0;
  for (let shift = 0; ; shift += 7) {
    if (pos >= input.length || shift > 28) fail();
    const b = input[pos++];
    length += (b & 0x7f) * 2 ** shift;
    if (b < 0x80) break;
  }
  if (length > max) fail();
  const out = Buffer.alloc(length);
  let o = 0;
  const le = (at, n) => {
    if (at + n > input.length) fail();
    let v = 0;
    for (let i = 0; i < n; i++) v += input[at + i] * 2 ** (8 * i);
    return v;
  };
  while (pos < input.length) {
    const tag = input[pos++],
      type = tag & 3;
    if (type === 0) {
      let n = tag >> 2;
      if (n >= 60) {
        const k = n - 59;
        n = le(pos, k);
        pos += k;
      }
      n += 1;
      if (pos + n > input.length || o + n > length) fail();
      input.copy(out, o, pos, pos + n);
      pos += n;
      o += n;
      continue;
    }
    let n, offset;
    if (type === 1) {
      n = 4 + ((tag >> 2) & 7);
      offset = ((tag >> 5) << 8) | le(pos, 1);
      pos += 1;
    } else {
      const k = type === 2 ? 2 : 4;
      n = (tag >> 2) + 1;
      offset = le(pos, k);
      pos += k;
    }
    if (offset === 0 || offset > o || o + n > length) fail();
    for (let i = 0; i < n; i++, o++) out[o] = out[o - offset];
  }
  if (o !== length) fail();
  return out;
}
/** npm pack archives: regular files and directories under package/ only. */
export function checkArchiveListing(names, details) {
  if (
    !names.length ||
    names.some((p) => !/^package(\/|$)/.test(p) || /(^|\/)\.\.(\/|$)|\\/.test(p)) ||
    details.some((d) => !/^[-d]/.test(d))
  )
    throw Error("update_archive_unsafe");
}

// ----------------------------------------------------------------- network --
const headers = {
  Accept: "application/vnd.github+json",
  "User-Agent": "kadenco-fleet-update",
  "X-GitHub-Api-Version": "2022-11-28",
};
async function fetchBytes(url, cap, { hosts } = {}) {
  const r = await fetch(url, { headers, redirect: "follow", signal: AbortSignal.timeout(120000) });
  if (!r.ok) throw Error(`update_fetch_status:${r.status}`);
  if (hosts && !hosts.has(new URL(r.url).hostname)) throw Error("update_fetch_host");
  const declared = Number(r.headers.get("content-length") ?? 0);
  if (declared > cap) throw Error("update_fetch_too_large");
  const bytes = Buffer.from(await r.arrayBuffer());
  if (bytes.length > cap) throw Error("update_fetch_too_large");
  return bytes;
}
const fetchJson = async (url, cap = 4 << 20, opts) =>
  JSON.parse((await fetchBytes(url, cap, opts)).toString("utf8"));
async function attestationBundles(digest) {
  let body;
  try {
    body = await fetchJson(`${API}/repos/${REPOSITORY}/attestations/sha256:${digest}?per_page=30`);
  } catch (error) {
    // GitHub answers 404 when no attestation exists for the digest.
    if (error.message === "update_fetch_status:404") return [];
    throw error;
  }
  const bundles = [];
  for (const a of body.attestations ?? []) {
    if (a.bundle) bundles.push(a.bundle);
    else if (typeof a.bundle_url === "string" && a.bundle_url.startsWith("https://"))
      bundles.push(
        JSON.parse(snappyDecode(await fetchBytes(a.bundle_url, 4 << 20)).toString("utf8")),
      );
  }
  return bundles;
}

// ------------------------------------------------------------- filesystem --
export function defaultBase(home = homedir()) {
  return isWindows
    ? join(home, ".t3", "runtime", "eddie-t3")
    : join(home, ".local", "share", "eddie-t3");
}
const readJson = (path) => JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
function writeJson(path, value) {
  const temp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}`;
  writeFileSync(temp, JSON.stringify(value, null, 2) + "\n", { mode: 0o600, flag: "wx" });
  renameSync(temp, path);
}
function log(base, entry) {
  const path = join(base, "update.log");
  try {
    if (existsSync(path) && statSync(path).size > 1 << 20) renameSync(path, path + ".1");
    appendFileSync(path, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n", {
      mode: 0o600,
    });
  } catch {
    // Logging never blocks an update decision.
  }
}
function lock(base) {
  const path = join(base, "update.lock");
  try {
    mkdirSync(path);
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    if (Date.now() - statSync(path).mtimeMs < LOCK_STALE_MS) throw Error("update_locked");
    rmSync(path, { recursive: true, force: true });
    mkdirSync(path);
  }
  return () => rmSync(path, { recursive: true, force: true });
}
/** Points base/current at a release directory under base/releases. */
export function switchCurrent(base, releaseDir) {
  const current = join(base, "current"),
    rel = relative(join(base, "releases"), releaseDir);
  if (!rel || rel.startsWith("..") || isAbsolute(rel) || rel.includes("/") || rel.includes("\\"))
    throw Error("update_release_outside_base");
  if (existsSync(current) || isLink(current)) {
    if (!isLink(current)) throw Error("update_current_not_link");
  }
  if (isWindows) {
    // Directory junctions cannot be replaced atomically; the gap is only the
    // next provider launch and is bounded by this call.
    if (isLink(current)) unlinkSync(current);
    symlinkSync(releaseDir, current, "junction");
  } else {
    const temp = join(base, `.current-${randomBytes(6).toString("hex")}`);
    symlinkSync(join("releases", basename(releaseDir)), temp);
    renameSync(temp, current);
  }
}
function isLink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}
export function currentTarget(base) {
  const current = join(base, "current");
  if (!isLink(current)) return null;
  const target = readlinkSync(current);
  return resolve(isAbsolute(target) ? target : join(base, target));
}

// ----------------------------------------------------------------- process --
function runChecked(command, args, options = {}) {
  const r = spawnSync(command, args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: options.timeout ?? 120000,
    maxBuffer: 16 << 20,
    ...options,
  });
  if (r.error || r.status !== 0)
    throw Error(
      `update_command_failed:${basename(command)}:${r.status ?? r.error?.code ?? "unknown"}`,
    );
  return r.stdout;
}
function npmCommand() {
  if (!isWindows) return ["npm", []];
  const cli = join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  if (!existsSync(cli)) throw Error("update_npm_unavailable");
  return [process.execPath, [cli]];
}
/** The provider launch for a release root (versioned for checks, `current` in catalogs). */
export function launcher(config, root) {
  if (config.launcher === "windows")
    return {
      command: join(
        process.env.SystemRoot ?? "C:\\Windows",
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
      ),
      args: [
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-File",
        join(root, "scripts", "invoke-eddie.ps1"),
        "-CredentialFile",
        config.credential,
        "-Mcp",
        "-NodePath",
        config.node,
      ],
    };
  return {
    command: config.node,
    args: [join(root, "scripts", "invoke-eddie-posix.mjs"), config.credential],
  };
}
/**
 * Starts the release's caller MCP exactly as a provider would and requires the
 * full tool surface and an authenticated host binding from the live server.
 */
export function healthCheck({ command, args }, timeoutMs = 90000) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { stdio: ["pipe", "pipe", "ignore"], windowsHide: true });
    const pending = new Map();
    let buffer = "",
      settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill();
      if (error) reject(error);
      else resolvePromise(value);
    };
    const timer = setTimeout(() => finish(Error("update_health_timeout")), timeoutMs);
    child.on("error", () => finish(Error("update_health_spawn")));
    child.on("exit", () => finish(Error("update_health_exited")));
    child.stdin.on("error", () => {});
    child.stdout.on("data", (chunk) => {
      buffer += chunk;
      if (buffer.length > 4 << 20) return finish(Error("update_health_output"));
      let i;
      while ((i = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, i).trim();
        buffer = buffer.slice(i + 1);
        if (!line) continue;
        let message;
        try {
          message = JSON.parse(line);
        } catch {
          continue;
        }
        pending.get(message.id)?.(message);
      }
    });
    const send = (message) =>
      child.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
    const request = (id, method, params) =>
      new Promise((ok) => {
        pending.set(id, ok);
        send({ id, method, params });
      });
    (async () => {
      const init = await request(1, "initialize", {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "kadenco-fleet-update", version: "1" },
      });
      if (init.error) throw Error("update_health_initialize");
      send({ method: "notifications/initialized" });
      const list = await request(2, "tools/list", {});
      const names = (list.result?.tools ?? []).map((t) => t.name);
      const missing = REQUIRED_TOOLS.filter((t) => !names.includes(t));
      if (missing.length) throw Error("update_health_tools_missing:" + missing.join(","));
      const caps = await request(3, "tools/call", {
        name: "get_eddie_capabilities",
        arguments: {},
      });
      const text = caps.result?.content?.find((c) => c.type === "text")?.text;
      let parsed = null;
      try {
        parsed = JSON.parse(text);
      } catch {
        // Not JSON: refused below.
      }
      if (
        caps.result?.isError ||
        parsed?.host_caller !== true ||
        parsed?.delivery_acknowledgement?.available !== true
      )
        throw Error("update_health_capabilities");
      return { tools: names.length, host: parsed.host, backend: parsed.backend_version };
    })().then(
      (v) => finish(null, v),
      (e) => finish(e),
    );
  });
}

// ----------------------------------------------------------------- install --
function releaseIdentity(dir) {
  const pkg = readJson(join(dir, "package.json")),
    build = readJson(join(dir, "BUILD.json"));
  if (
    pkg.name !== "kadenco" ||
    build.version !== pkg.version ||
    !/^[a-f0-9]{40}$/.test(build.source ?? "")
  )
    throw Error("update_release_identity");
  return { version: pkg.version, source: build.source };
}
async function installRelease(base, config, selected, state) {
  const { version, release } = selected;
  const asset = (name) => {
    const a = (release.assets ?? []).find((x) => x.name === name);
    if (
      !a ||
      typeof a.browser_download_url !== "string" ||
      !a.browser_download_url.startsWith(DOWNLOAD_PREFIX)
    )
      throw Error("update_asset_missing:" + name);
    return a;
  };
  const tgzName = `kadenco-${version}.tgz`,
    tgzAsset = asset(tgzName);
  const sums = (
    await fetchBytes(asset("SHA256SUMS").browser_download_url, 64 << 10, { hosts: DOWNLOAD_HOSTS })
  ).toString("utf8");
  const build = JSON.parse(
    (
      await fetchBytes(asset("BUILD.json").browser_download_url, 64 << 10, {
        hosts: DOWNLOAD_HOSTS,
      })
    ).toString("utf8"),
  );
  if (build.version !== version || !/^[a-f0-9]{40}$/.test(build.source ?? ""))
    throw Error("update_build_identity");
  const tgz = await fetchBytes(tgzAsset.browser_download_url, 64 << 20, { hosts: DOWNLOAD_HOSTS });
  const digest = sha256(tgz);
  if (checksumFor(sums, tgzName) !== digest) throw Error("update_checksum_mismatch");
  if (tgzAsset.digest && tgzAsset.digest !== "sha256:" + digest)
    throw Error("update_checksum_mismatch");
  const { verify } = await import("sigstore");
  await verifyProvenance(await attestationBundles(digest), {
    digest,
    source: build.source,
    verify: (bundle, options) =>
      verify(bundle, { ...options, tufCachePath: join(base, "sigstore-cache") }),
  });

  const releases = join(base, "releases"),
    name = `kadenco-${version}-${build.source.slice(0, 7)}`,
    finalDir = join(releases, name);
  mkdirSync(releases, { recursive: true });
  if (existsSync(finalDir)) {
    // Installed by an earlier run that did not switch (for example a failed health check).
    const id = releaseIdentity(finalDir);
    if (id.version !== version || id.source !== build.source)
      throw Error("update_release_collision");
    if (!state.installed?.includes(name)) throw Error("update_release_unowned");
    return { dir: finalDir, name, version, source: build.source, digest };
  }
  const stage = join(releases, `.stage-${randomBytes(6).toString("hex")}`);
  mkdirSync(stage);
  try {
    const archive = join(stage, tgzName);
    writeFileSync(archive, tgz, { flag: "wx" });
    const names = runChecked("tar", ["-tzf", tgzName], { cwd: stage })
      .split(/\r?\n/)
      .filter(Boolean);
    const details = runChecked("tar", ["-tvzf", tgzName], { cwd: stage })
      .split(/\r?\n/)
      .filter(Boolean);
    checkArchiveListing(names, details);
    runChecked("tar", ["-xzf", tgzName, ...(isWindows ? [] : ["--no-same-owner"])], { cwd: stage });
    rmSync(archive);
    const pkgDir = join(stage, "package");
    const id = releaseIdentity(pkgDir);
    if (id.version !== version || id.source !== build.source)
      throw Error("update_release_identity");
    const [npm, prefix] = npmCommand();
    runChecked(
      npm,
      [
        ...prefix,
        "ci",
        "--omit=dev",
        "--ignore-scripts",
        "--no-audit",
        "--no-fund",
        "--loglevel=error",
      ],
      {
        cwd: pkgDir,
        timeout: 15 * 60 * 1000,
      },
    );
    // The next run uses this release's updater: it must load before we switch.
    runChecked(config.node, [join(pkgDir, "scripts", "fleet-update.mjs"), "self-test"], {
      cwd: pkgDir,
      timeout: 60000,
    });
    renameSync(pkgDir, finalDir);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
  state.installed = [...new Set([...(state.installed ?? []), name])];
  return { dir: finalDir, name, version, source: build.source, digest };
}
function prune(base, state, keep = 3) {
  const releases = join(base, "releases");
  const protectedNames = new Set([state.current?.name, state.previous?.name].filter(Boolean));
  const owned = (state.installed ?? []).filter((n) => existsSync(join(releases, n)));
  const removable = owned.filter((n) => !protectedNames.has(n));
  const excess = removable.slice(0, Math.max(0, owned.length - keep));
  for (const n of excess) {
    try {
      rmSync(join(releases, n), { recursive: true, force: true });
    } catch {
      continue; // In use (Windows); retried on a later run.
    }
    state.installed = state.installed.filter((x) => x !== n);
  }
  state.installed = state.installed.filter((n) => existsSync(join(releases, n)));
}

// ---------------------------------------------------------------- commands --
function loadConfig(base) {
  const path = join(base, "update.json");
  if (!existsSync(path)) throw Error("update_not_configured");
  const c = readJson(path);
  if (
    c.schema !== 1 ||
    !["posix", "windows"].includes(c.launcher) ||
    !isAbsolute(c.credential ?? "") ||
    !isAbsolute(c.node ?? "") ||
    typeof c.host !== "string"
  )
    throw Error("update_config_invalid");
  return c;
}
const loadState = (base) =>
  existsSync(join(base, "update-state.json")) ? readJson(join(base, "update-state.json")) : {};

export async function runUpdate(base) {
  const config = loadConfig(base);
  if (existsSync(join(base, "update.hold"))) return { result: "held" };
  const unlock = lock(base);
  try {
    const state = loadState(base);
    if (!state.current?.version) throw Error("update_not_configured");
    const releases = await fetchJson(`${API}/repos/${REPOSITORY}/releases?per_page=30`);
    if (!Array.isArray(releases)) throw Error("update_releases_unreadable");
    const selected = selectRelease(releases, state.current.version);
    state.checked_at = new Date().toISOString();
    if (!selected) {
      writeJson(join(base, "update-state.json"), state);
      return { result: "current", version: state.current.version };
    }
    const installed = await installRelease(base, config, selected, state);
    writeJson(join(base, "update-state.json"), state);
    const health = await healthCheck(launcher(config, installed.dir));
    switchCurrent(base, installed.dir);
    state.previous = state.current;
    state.current = { name: installed.name, version: installed.version, source: installed.source };
    state.updated_at = new Date().toISOString();
    prune(base, state);
    writeJson(join(base, "update-state.json"), state);
    return {
      result: "updated",
      from: state.previous.version,
      to: installed.version,
      digest: installed.digest,
      health,
    };
  } finally {
    unlock();
  }
}
export function rollback(base) {
  const unlock = lock(base);
  try {
    const state = loadState(base);
    if (!state.previous?.name) throw Error("update_no_previous");
    const dir = join(base, "releases", state.previous.name);
    releaseIdentity(dir);
    switchCurrent(base, dir);
    [state.current, state.previous] = [state.previous, state.current];
    // Stay on the rolled-back release until an operator removes the hold.
    writeFileSync(join(base, "update.hold"), "rollback " + new Date().toISOString() + "\n");
    writeJson(join(base, "update-state.json"), state);
    return { result: "rolled_back", to: state.current.version, held: true };
  } finally {
    unlock();
  }
}
function option(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}
function setupConfig(args) {
  const credential = option(args, "--credential"),
    host = option(args, "--host");
  if (!credential || !isAbsolute(credential) || !host || !/^[A-Za-z0-9._-]+$/.test(host))
    throw Error("update_setup_usage");
  return {
    schema: 1,
    host,
    launcher: isWindows ? "windows" : "posix",
    credential,
    node: process.execPath,
  };
}
/**
 * Bootstrap through the same verified path as an update: downloads the named
 * release, checks its provenance, installs it under base/releases, then adopts it.
 */
export async function installVersion(base, version, args) {
  if (!parseVersion(version)) throw Error("update_setup_usage");
  const config = setupConfig(args);
  mkdirSync(base, { recursive: true });
  const unlock = lock(base);
  let dir;
  try {
    const release = await fetchJson(`${API}/repos/${REPOSITORY}/releases/tags/v${version}`);
    if (release.draft || release.tag_name !== `v${version}`) throw Error("update_release_missing");
    const state = loadState(base);
    dir = (await installRelease(base, config, { version, release }, state)).dir;
    writeJson(join(base, "update-state.json"), state);
  } finally {
    unlock();
  }
  return setup(base, args, dir);
}
/**
 * One-time adoption of an installed release under base/releases: records the
 * configuration, points `current` at it, rewrites the owned provider catalog
 * entries to launch through `current`, and installs the schedule.
 */
export async function setup(
  base,
  args,
  releaseDir = resolve(dirname(fileURLToPath(import.meta.url)), ".."),
) {
  const id = releaseIdentity(releaseDir);
  const config = setupConfig(args);
  mkdirSync(base, { recursive: true });
  const health = await healthCheck(launcher(config, releaseDir));
  switchCurrent(base, releaseDir);
  writeJson(join(base, "update.json"), config);
  const state = loadState(base);
  state.previous =
    state.current?.name && state.current.name !== basename(releaseDir)
      ? state.current
      : (state.previous ?? null);
  state.current = { name: basename(releaseDir), version: id.version, source: id.source };
  state.installed = [...new Set([...(state.installed ?? []), basename(releaseDir)])];
  writeJson(join(base, "update-state.json"), state);
  const result = { result: "configured", version: id.version, health };
  if (!args.includes("--no-catalogs")) {
    const { installAgentTools } = await import(
      pathToFileURL(join(releaseDir, "scripts", "install-agent-tools.mjs")).href
    );
    const stable = launcher(config, join(base, "current"));
    const major = option(args, "--opencode-major");
    const legacy = option(args, "--legacy-opencode-manifest");
    result.catalogs = installAgentTools({
      home: homedir(),
      host,
      releasePath: join(base, "current"),
      nodePath: config.node,
      command: stable.command,
      args: stable.args,
      ...(major ? { opencodeMajor: Number(major) } : {}),
      ...(legacy ? { legacyOpenCodeManifest: legacy } : {}),
    });
  }
  if (!args.includes("--no-schedule")) result.schedule = installSchedule(base, config);
  return result;
}
export function installSchedule(base, config) {
  const script = join(base, "current", "scripts", "fleet-update.mjs");
  if (isWindows) {
    const xmlEscape = (s) =>
      s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
    const conhost = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "conhost.exe");
    const xml = `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Kadenco fleet update (docs/fleet-update.md)</Description></RegistrationInfo>
  <Triggers><TimeTrigger><StartBoundary>2026-01-01T00:17:00</StartBoundary><Repetition><Interval>PT1H</Interval></Repetition><RandomDelay>PT10M</RandomDelay></TimeTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><StartWhenAvailable>true</StartWhenAvailable><ExecutionTimeLimit>PT40M</ExecutionTimeLimit><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><Hidden>true</Hidden></Settings>
  <Actions Context="Author"><Exec><Command>${xmlEscape(conhost)}</Command><Arguments>${xmlEscape(`--headless "${config.node}" "${script}" run`)}</Arguments></Exec></Actions>
</Task>
`;
    const file = join(base, "kadenco-fleet-update.task.xml");
    writeFileSync(file, "\uFEFF" + xml, { encoding: "utf16le" });
    runChecked("schtasks.exe", ["/Create", "/TN", "kadenco-fleet-update", "/XML", file, "/F"]);
    rmSync(file);
    return { task: "kadenco-fleet-update", interval: "1h" };
  }
  const units = join(homedir(), ".config", "systemd", "user");
  mkdirSync(units, { recursive: true });
  const q = (s) => `"${s.replace(/["\\]/g, (c) => "\\" + c)}"`;
  writeFileSync(
    join(units, "kadenco-update.service"),
    `[Unit]\nDescription=Kadenco fleet update (docs/fleet-update.md)\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=${q(config.node)} ${q(script)} run\nTimeoutStartSec=40min\nNice=10\n`,
  );
  writeFileSync(
    join(units, "kadenco-update.timer"),
    `[Unit]\nDescription=Hourly Kadenco fleet update\n\n[Timer]\nOnBootSec=10min\nOnUnitActiveSec=1h\nRandomizedDelaySec=10min\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n`,
  );
  runChecked("systemctl", ["--user", "daemon-reload"]);
  runChecked("systemctl", ["--user", "enable", "--now", "kadenco-update.timer"]);
  return { timer: "kadenco-update.timer", interval: "1h" };
}

async function main(argv) {
  const [command, ...args] = argv;
  const base = resolve(option(args, "--base") ?? defaultBase());
  if (command === "self-test") {
    await import("sigstore");
    return { result: "ok" };
  }
  if (command === "run") return runUpdate(base);
  if (command === "rollback") return rollback(base);
  if (command === "setup") return setup(base, args);
  if (command === "install") return installVersion(base, args[0], args.slice(1));
  if (command === "status")
    return {
      state: loadState(base),
      held: existsSync(join(base, "update.hold")),
      current: currentTarget(base),
    };
  throw Error("update_usage");
}
const invokedDirectly = () => {
  try {
    // Launched through base/current: Node reports the module by its real path.
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
};
if (process.argv[1] && invokedDirectly()) {
  const base = resolve(option(process.argv, "--base") ?? defaultBase());
  try {
    const result = await main(process.argv.slice(2));
    if (process.argv[2] === "run") log(base, result);
    console.log(JSON.stringify(result));
  } catch (error) {
    const reason = /^update_[a-z_]+(:[A-Za-z0-9_.,-]+)?$/.test(error?.message ?? "")
      ? error.message
      : "update_failed";
    if (process.argv[2] === "run") log(base, { result: "failed", reason });
    console.error(JSON.stringify({ result: "failed", reason }));
    process.exitCode = 1;
  }
}
