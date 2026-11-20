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
  closeSync,
  existsSync,
  fstatSync,
  openSync,
  writeSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createServer } from "node:net";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
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
/** sigstore-js matches identities as regular expressions: escape and anchor. */
export const identityPattern = (signer) =>
  "^" + signer.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&") + "$";
/**
 * Accepts the package when at least one attestation bundle verifies (signature,
 * certificate chain, transparency log) with a certificate issued exactly to the
 * release workflow on main by GitHub's OIDC issuer, and its statement names
 * this package digest and source commit. `verify(bundle)` returns the signer.
 */
export async function verifyProvenance(
  bundles,
  { digest, source, verify, signer = SIGNER, repository },
) {
  for (const bundle of bundles) {
    try {
      if (bundle?.dsseEnvelope?.payloadType !== "application/vnd.in-toto+json") continue;
      const who = (await verify(bundle))?.identity;
      if (who?.subjectAlternativeName !== signer || who?.extensions?.issuer !== ISSUER) continue;
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
} /** Snappy block decoding (GitHub serves attestation bundles snappy-compressed). */
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
  // Count while streaming, so an undeclared oversized body is cut off early.
  const chunks = [];
  let size = 0;
  const reader = r.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > cap) {
      await reader.cancel().catch(() => {});
      throw Error("update_fetch_too_large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks);
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
    const fd = openSync(path, "a", 0o600);
    let full;
    try {
      writeSync(fd, JSON.stringify({ at: new Date().toISOString(), ...entry }) + "\n");
      full = fstatSync(fd).size > 1 << 20;
    } finally {
      closeSync(fd);
    }
    if (full) renameSync(path, path + ".1");
  } catch {
    // Logging never blocks an update decision.
  }
}
/**
 * The real path of an existing directory, as stored on disk. Every command
 * works from this form of its base, so all derived paths agree.
 */
export const canonicalPath = (path) => realpathSync.native(path);
/** Identity for comparison: real path, case-folded on Windows (case-insensitive). */
const pathKey = (path) => {
  const real = realpathSync.native(path);
  return isWindows ? real.toLowerCase() : real;
};
function samePath(a, b) {
  try {
    return pathKey(a) === pathKey(b);
  } catch {
    return false;
  }
}
/** Lock name for this user and base: an abstract Unix socket or a named pipe. */
export function lockName(base) {
  // One name per directory, however it is spelled: resolve links, and fold
  // case on Windows, whose paths are case-insensitive.
  const id = createHash("sha256").update(pathKey(base)).digest("hex").slice(0, 24);
  return isWindows
    ? `\\\\.\\pipe\\kadenco-fleet-update-${id}`
    : `\0kadenco-fleet-update-${process.getuid?.() ?? 0}-${id}`;
}
/**
 * Process-lifetime lock. Listening on the name succeeds for exactly one
 * process; the operating system releases it when that process exits, however
 * it exits, so there is no stale lock to detect or retire.
 */
export function lock(base) {
  return new Promise((ok, fail) => {
    const server = createServer((socket) => socket.destroy());
    server.once("error", (error) =>
      fail(error.code === "EADDRINUSE" ? Error("update_locked") : error),
    );
    server.listen(lockName(base), () => {
      server.unref();
      ok(() => new Promise((done) => server.close(() => done())));
    });
  });
}
function isLink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}
function linkTarget(path, base) {
  if (!isLink(path)) return null;
  const target = readlinkSync(path);
  return resolve(isAbsolute(target) ? target : join(base, target));
}
export const currentTarget = (base) => linkTarget(join(base, "current"), base);
function checkReleaseDir(base, releaseDir) {
  const name = basename(releaseDir);
  if (
    !name ||
    name === "." ||
    name === ".." ||
    !samePath(dirname(releaseDir), join(base, "releases"))
  )
    throw Error("update_release_outside_base");
  return join(base, "releases", name);
} /**
 * Points base/current at a release under base/releases. Linux replaces the
 * symlink atomically. Windows cannot replace a junction atomically: it creates
 * current.next, removes current, then renames; an interruption leaves
 * current.next, which reconcile() completes. The scheduled entry point never
 * launches through current, so an interrupted switch cannot stop updates.
 */
export function switchCurrent(base, releaseDir) {
  releaseDir = checkReleaseDir(base, releaseDir);
  const current = join(base, "current"),
    next = join(base, "current.next");
  if ((existsSync(current) || isLink(current)) && !isLink(current))
    throw Error("update_current_not_link");
  if (!isWindows) {
    const temp = join(base, `.current-${randomBytes(6).toString("hex")}`);
    symlinkSync(join("releases", basename(releaseDir)), temp);
    renameSync(temp, current);
    return;
  }
  if (isLink(next)) unlinkSync(next);
  symlinkSync(releaseDir, next, "junction");
  if (isLink(current)) unlinkSync(current);
  renameSync(next, current);
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
/**
 * npm from the same Node installation the updater runs on (the configured
 * node), never whatever `npm` a scheduler's PATH happens to resolve.
 */
function npmCommand() {
  const bin = dirname(realpathSync(process.execPath));
  const candidates = isWindows
    ? [join(bin, "node_modules", "npm", "bin", "npm-cli.js")]
    : [
        join(bin, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
        "/usr/share/nodejs/npm/bin/npm-cli.js",
      ];
  const cli = candidates.find((p) => existsSync(p));
  if (!cli) throw Error("update_npm_unavailable");
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
 * full tool surface and the live server's authenticated binding to this host.
 * It settles only once `close` confirms every process holding the caller's
 * output has exited; an unconfirmed shutdown fails the check. Windows kills the
 * tree while the PowerShell wrapper still parents the caller.
 */
export function healthCheck(
  { command, args },
  expectedHost,
  timeoutMs = 90000,
  { graceMs = 5000, killWaitMs = 20000 } = {},
) {
  return new Promise((resolvePromise, reject) => {
    // POSIX: its own process group, so cleanup reaches every descendant.
    const child = spawn(command, args, {
      stdio: ["pipe", "pipe", "ignore"],
      windowsHide: true,
      detached: !isWindows,
    });
    const closed = new Promise((done) => child.once("close", () => done(true)));
    const within = (ms) => Promise.race([closed, delay(ms).then(() => false)]);
    const pending = new Map();
    let buffer = "",
      settled = false;
    const finish = async (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      let stopped;
      if (isWindows) {
        if (child.exitCode === null && child.signalCode === null && child.pid)
          spawnSync("taskkill.exe", ["/PID", String(child.pid), "/T", "/F"], {
            windowsHide: true,
            timeout: 15000,
          });
        stopped = await within(killWaitMs);
      } else {
        child.stdin.end();
        stopped = await within(graceMs);
        if (!stopped) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            // Group already gone.
          }
          stopped = await within(killWaitMs);
        }
      }
      if (!stopped) reject(Error("update_health_cleanup"));
      else if (error) reject(error);
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
      if (parsed.host !== expectedHost) throw Error("update_health_host");
      return { tools: names.length, host: parsed.host, backend: parsed.backend_version };
    })().then(
      (v) => finish(null, v),
      (e) => finish(e),
    );
  });
}
const delay = (ms) => new Promise((done) => setTimeout(done, ms).unref());

// ----------------------------------------------------------------- install --
const MARKER = ".fleet-update.json";
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
export const releaseName = (version, digest) => `kadenco-${version}-${digest.slice(0, 16)}`;
/**
 * A release this updater installed: its marker binds the directory name to the
 * exact package digest that passed verification.
 */
export function managedRelease(base, name) {
  if (typeof name !== "string" || !/^kadenco-[0-9A-Za-z.-]+-[a-f0-9]{16}$/.test(name)) return null;
  const dir = join(base, "releases", name);
  try {
    const marker = readJson(join(dir, MARKER)),
      id = releaseIdentity(dir);
    if (
      !/^[a-f0-9]{64}$/.test(marker.digest ?? "") ||
      releaseName(marker.version, marker.digest) !== name ||
      marker.version !== id.version ||
      marker.source !== id.source
    )
      return null;
    return { name, dir, version: id.version, source: id.source, digest: marker.digest };
  } catch {
    return null;
  }
}
const record = (r) => ({ name: r.name, version: r.version, source: r.source, digest: r.digest });

/**
 * Failures of the infrastructure rather than of one release: they end the run
 * without marking any release, and the next run retries. npm ci counts here
 * because an attested package's shrinkwrap already installed in the release
 * workflow's smoke test, so a failure points at the registry or network.
 */
export function isTransient(error) {
  const m = error?.message ?? "";
  return (
    m === "fetch failed" ||
    error?.name === "TimeoutError" ||
    error?.name === "AbortError" ||
    /^update_fetch_status:(403|408|429|5\d\d)$/.test(m) ||
    m === "update_npm_failed" ||
    m === "update_trust_root_unavailable" ||
    m === "update_npm_unavailable"
  );
}
async function installRelease(base, config, candidate) {
  const { version, release } = candidate;
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
  if (candidate.expectDigest && candidate.expectDigest !== digest)
    throw Error("update_checksum_unexpected");
  const bundles = await attestationBundles(digest);
  // Trust material (Sigstore TUF) is fetched once, outside the per-bundle
  // checks: its unavailability is an infrastructure failure, not a bad release.
  let verifier;
  try {
    const { createVerifier } = await import("sigstore");
    verifier = await createVerifier({
      certificateIdentityURI: identityPattern(SIGNER),
      certificateIssuer: ISSUER,
      tufCachePath: join(base, "sigstore-cache"),
    });
  } catch {
    throw Error("update_trust_root_unavailable");
  }
  await verifyProvenance(bundles, {
    digest,
    source: build.source,
    verify: (bundle) => verifier.verify(bundle),
  });

  const releases = join(base, "releases"),
    name = releaseName(version, digest),
    finalDir = join(releases, name);
  mkdirSync(releases, { recursive: true });
  if (existsSync(finalDir)) {
    // Installed earlier from these exact verified bytes (for example before a
    // failed health check); the marker binds the directory to the digest.
    const existing = managedRelease(base, name);
    if (!existing || existing.digest !== digest || existing.source !== build.source)
      throw Error("update_release_collision");
    return existing;
  }
  const stage = join(releases, `.stage-${randomBytes(6).toString("hex")}`);
  mkdirSync(stage);
  try {
    // tar reads exactly the bytes we hashed and verified, from memory.
    const names = runChecked("tar", ["-tzf", "-"], { cwd: stage, input: tgz })
      .split(/\r?\n/)
      .filter(Boolean);
    const details = runChecked("tar", ["-tvzf", "-"], { cwd: stage, input: tgz })
      .split(/\r?\n/)
      .filter(Boolean);
    checkArchiveListing(names, details);
    runChecked("tar", ["-xzf", "-", ...(isWindows ? [] : ["--no-same-owner"])], {
      cwd: stage,
      input: tgz,
    });
    const pkgDir = join(stage, "package");
    const id = releaseIdentity(pkgDir);
    if (id.version !== version || id.source !== build.source)
      throw Error("update_release_identity");
    const [npm, prefix] = npmCommand();
    try {
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
        { cwd: pkgDir, timeout: 15 * 60 * 1000 },
      );
    } catch {
      throw Error("update_npm_failed");
    }
    // The next run uses this release's updater: it must load before we switch.
    try {
      runChecked(config.node, [join(pkgDir, "scripts", "fleet-update.mjs"), "self-test"], {
        cwd: pkgDir,
        timeout: 60000,
      });
    } catch {
      throw Error("update_self_test_failed");
    }
    // Ownership travels with the directory, so a crash after the rename still
    // leaves a release later runs recognize and reuse.
    writeFileSync(
      join(pkgDir, MARKER),
      JSON.stringify({
        version,
        source: build.source,
        digest,
        installed_at: new Date().toISOString(),
      }) + "\n",
      { flag: "wx" },
    );
    renameSync(pkgDir, finalDir);
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
  const installed = managedRelease(base, name);
  if (!installed) throw Error("update_release_identity");
  return installed;
}
function prune(base, state, keep = 3) {
  const releases = join(base, "releases");
  const protectedNames = new Set([state.current?.name, state.previous?.name].filter(Boolean));
  const owned = readdirSync(releases)
    .map((n) => managedRelease(base, n))
    .filter(Boolean)
    .sort((a, b) => compareVersions(b.version, a.version));
  for (const r of owned.slice(keep)) {
    if (protectedNames.has(r.name)) continue;
    try {
      rmSync(r.dir, { recursive: true, force: true });
    } catch {
      // In use (Windows); retried on a later run.
    }
  }
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
const statePath = (base) => join(base, "update-state.json");
const loadState = (base) => (existsSync(statePath(base)) ? readJson(statePath(base)) : {});
/**
 * Under the lock: makes state agree with the filesystem after any crash. The
 * active link is the truth when it names a managed release; an interrupted
 * Windows switch is completed; a missing link is restored from state.
 */
export function reconcile(base, state) {
  const current = join(base, "current"),
    next = join(base, "current.next");
  // A link counts only if it resolves to the managed release directory itself.
  const managedAt = (target) => {
    const m = target ? managedRelease(base, basename(target)) : null;
    return m && samePath(target, m.dir) ? m : null;
  };
  if (isLink(next)) {
    const pending = managedAt(linkTarget(next, base));
    if (!isLink(current) && pending) renameSync(next, current);
    else unlinkSync(next);
  }
  const active = managedAt(currentTarget(base));
  if (active) {
    if (active.name !== state.current?.name) {
      if (managedRelease(base, state.current?.name)) state.previous = state.current;
      state.current = record(active);
    }
  } else {
    const recorded = managedRelease(base, state.current?.name);
    if (!recorded) throw Error("update_not_configured");
    switchCurrent(base, recorded.dir);
  }
  if (state.previous && !managedRelease(base, state.previous.name)) state.previous = null;
  return state;
}
const MAX_PAGES = 10;
async function listReleases() {
  const all = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const batch = await fetchJson(
      `${API}/repos/${REPOSITORY}/releases?per_page=100&page=${page}`,
      16 << 20,
    );
    if (!Array.isArray(batch)) throw Error("update_releases_unreadable");
    all.push(...batch);
    if (batch.length < 100) break;
  }
  return all;
}
const MAX_ATTEMPTS = 5,
  REJECT_MS = 24 * 60 * 60 * 1000,
  DEFER_MS = 2 * 60 * 60 * 1000;

export async function runUpdate(base, { health = healthCheck, install = installRelease } = {}) {
  base = canonicalPath(base);
  const config = loadConfig(base);
  const unlock = await lock(base);
  try {
    // Reconcile first, so a rollback or switch interrupted by a crash is
    // settled before the hold is honored or anything is installed.
    const state = reconcile(base, loadState(base));
    writeJson(statePath(base), state);
    if (existsSync(join(base, "update.hold")))
      return { result: "held", version: state.current.version };
    const now = Date.now();
    state.rejected = Object.fromEntries(
      Object.entries(state.rejected ?? {}).filter(([, r]) => Date.parse(r.retry_after) > now),
    );
    const candidates = newerReleases(await listReleases(), state.current.version).filter(
      (c) => !state.rejected[c.release.tag_name],
    );
    state.checked_at = new Date().toISOString();
    const skipped = [];
    // Fallback covers only installing and checking a candidate. Activation is
    // outside it: once `current` may have moved, any failure ends the run and
    // the next run's reconcile settles the switch; it never falls back further.
    let chosen = null;
    for (const candidate of candidates.slice(0, MAX_ATTEMPTS)) {
      try {
        const installed = await install(base, config, candidate);
        chosen = { installed, health: await health(launcher(config, installed.dir), config.host) };
        break;
      } catch (error) {
        // Infrastructure failures, and a caller whose exit could not be
        // confirmed (it may still be running), end the run unmarked.
        if (isTransient(error) || error?.message === "update_health_cleanup") {
          writeJson(statePath(base), state);
          throw error;
        }
        // Anything else is about this release. A failed health check may be the
        // server rather than the release, so it is deferred briefly; the rest
        // is rejected for a day. Later runs reach older candidates either way.
        const reason = safeReason(error),
          wait = reason.startsWith("update_health_") ? DEFER_MS : REJECT_MS;
        state.rejected[candidate.release.tag_name] = {
          at: new Date().toISOString(),
          reason,
          retry_after: new Date(Date.now() + wait).toISOString(),
        };
        skipped.push({ version: candidate.version, reason });
      }
    }
    writeJson(statePath(base), state);
    if (!chosen) return { result: "current", version: state.current.version, skipped };
    const { installed } = chosen;
    // An operator may have paused while we verified: the installed copy stays
    // for reuse once the hold is removed.
    if (existsSync(join(base, "update.hold")))
      return { result: "held", version: state.current.version, ready: installed.version };
    switchCurrent(base, installed.dir);
    state.previous = state.current;
    state.current = record(installed);
    state.updated_at = new Date().toISOString();
    writeJson(statePath(base), state);
    writeEntry(base);
    prune(base, state);
    return {
      result: "updated",
      from: state.previous.version,
      to: installed.version,
      digest: installed.digest,
      health: chosen.health,
      skipped,
    };
  } finally {
    await unlock();
  }
}
/** All published releases newer than `installed`, newest first. */
export function newerReleases(releases, installed) {
  const seen = new Set();
  return releases
    .filter((r) => r && !r.draft)
    .map((r) => ({ release: r, version: /^v(.+)$/.exec(r.tag_name ?? "")?.[1] }))
    .filter(
      (c) => c.version && parseVersion(c.version) && !seen.has(c.version) && seen.add(c.version),
    )
    .filter((c) => !installed || compareVersions(c.version, installed) > 0)
    .sort((a, b) => compareVersions(b.version, a.version));
}
export async function rollback(base) {
  base = canonicalPath(base);
  const unlock = await lock(base);
  try {
    const state = reconcile(base, loadState(base));
    if (!state.previous?.name) throw Error("update_no_previous");
    const target = managedRelease(base, state.previous.name);
    if (!target) throw Error("update_no_previous");
    // The hold is written first: if we crash after switching, the next run
    // reconciles to the rolled-back release and still does not update.
    writeFileSync(join(base, "update.hold"), "rollback " + new Date().toISOString() + "\n");
    switchCurrent(base, target.dir);
    [state.current, state.previous] = [record(target), state.current];
    writeJson(statePath(base), state);
    return { result: "rolled_back", to: state.current.version, held: true };
  } finally {
    await unlock();
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
 * Bootstrap. Run from a package whose tarball the operator verified with an
 * independent verifier (docs/fleet-update.md); --expect-digest binds this run
 * to those bytes. Installs the release through the update path, then adopts it
 * under the same lock.
 */
export async function installVersion(base, version, args, deps = {}) {
  const expectDigest = option(args, "--expect-digest");
  if (!parseVersion(version) || !/^[a-f0-9]{64}$/.test(expectDigest ?? ""))
    throw Error("update_setup_usage");
  const config = setupConfig(args);
  mkdirSync(base, { recursive: true });
  base = canonicalPath(base);
  const unlock = await lock(base);
  try {
    const release = await fetchJson(`${API}/repos/${REPOSITORY}/releases/tags/v${version}`);
    if (release.draft || release.tag_name !== `v${version}`) throw Error("update_release_missing");
    const installed = await installRelease(base, config, { version, release, expectDigest });
    return await adopt(base, config, installed, args, deps);
  } finally {
    await unlock();
  }
}
/**
 * Adoption of an installed release (lock held): health check, `current`,
 * configuration and state, the stable entry point, owned provider catalog
 * entries launching through `current`, and the schedule.
 */
export async function adopt(base, config, installed, args, deps = {}) {
  const health = deps.health ?? healthCheck,
    home = deps.home ?? homedir();
  const result = {
    result: "configured",
    version: installed.version,
    health: await health(launcher(config, installed.dir), config.host),
  };
  switchCurrent(base, installed.dir);
  writeJson(join(base, "update.json"), config);
  const state = loadState(base);
  if (
    state.current?.name &&
    state.current.name !== installed.name &&
    managedRelease(base, state.current.name)
  )
    state.previous = state.current;
  state.current = record(installed);
  writeJson(statePath(base), state);
  writeEntry(base);
  if (!args.includes("--no-catalogs")) {
    const { installAgentTools } = await import(
      pathToFileURL(join(installed.dir, "scripts", "install-agent-tools.mjs")).href
    );
    const stable = launcher(config, join(base, "current"));
    const major = option(args, "--opencode-major");
    const legacy = option(args, "--legacy-opencode-manifest");
    result.catalogs = installAgentTools({
      home,
      host: config.host,
      releasePath: join(base, "current"),
      nodePath: config.node,
      command: stable.command,
      args: stable.args,
      ...(major ? { opencodeMajor: Number(major) } : {}),
      ...(legacy ? { legacyOpenCodeManifest: legacy } : {}),
    });
  }
  if (!args.includes("--no-schedule"))
    result.schedule = (deps.schedule ?? installSchedule)(base, config, home);
  return result;
}
/**
 * The scheduler's stable entry point. It resolves the active release from
 * update-state.json (not through `current`), so an interrupted switch cannot
 * disable updates; the release's updater then reconciles the link.
 */
export function entrySource() {
  return `// Generated by kadenco scripts/fleet-update.mjs; see docs/fleet-update.md.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const base = dirname(fileURLToPath(import.meta.url));
const state = JSON.parse(readFileSync(join(base, "update-state.json"), "utf8"));
const name = state.current?.name;
if (typeof name !== "string" || !/^kadenco-[0-9A-Za-z.-]+-[a-f0-9]{16}$/.test(name)) {
  console.error(JSON.stringify({ result: "failed", reason: "update_state_invalid" }));
  process.exit(1);
}
const { cli } = await import(pathToFileURL(join(base, "releases", name, "scripts", "fleet-update.mjs")).href);
await cli([...process.argv.slice(2), "--base", base]);
`;
}
function writeEntry(base) {
  const path = join(base, "fleet-update-entry.mjs"),
    temp = `${path}.${randomBytes(4).toString("hex")}`;
  writeFileSync(temp, entrySource(), { mode: 0o644, flag: "wx" });
  renameSync(temp, path);
}
export function installSchedule(base, config, home = homedir()) {
  const script = join(base, "fleet-update-entry.mjs");
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
    try {
      runChecked("schtasks.exe", ["/Create", "/TN", "kadenco-fleet-update", "/XML", file, "/F"]);
    } finally {
      rmSync(file, { force: true });
    }
    return { task: "kadenco-fleet-update", interval: "1h" };
  }
  const units = join(home, ".config", "systemd", "user");
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

const safeReason = (error) =>
  /^update_[a-z_]+(:[A-Za-z0-9_.,-]+)?$/.test(error?.message ?? "")
    ? error.message
    : "update_failed";
async function main(command, args, base) {
  if (command === "self-test") {
    await import("sigstore");
    return { result: "ok" };
  }
  if (command === "run") return runUpdate(base);
  if (command === "rollback") return rollback(base);
  if (command === "install") return installVersion(base, args[0], args.slice(1));
  if (command === "status")
    return {
      state: loadState(base),
      held: existsSync(join(base, "update.hold")),
      current: currentTarget(base),
    };
  throw Error("update_usage");
}
/** Command-line entry (direct invocation or the stable entry point). */
export async function cli(argv) {
  const [command, ...args] = argv;
  const base = resolve(option(args, "--base") ?? defaultBase());
  try {
    const result = await main(command, args, base);
    if (command === "run") log(base, result);
    console.log(JSON.stringify(result));
  } catch (error) {
    const reason = safeReason(error);
    if (command === "run") log(base, { result: "failed", reason });
    console.error(JSON.stringify({ result: "failed", reason }));
    process.exitCode = 1;
  }
}
const invokedDirectly = () => {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
};
if (process.argv[1] && invokedDirectly()) await cli(process.argv.slice(2));
