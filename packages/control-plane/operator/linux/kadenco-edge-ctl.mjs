#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Kadenco Linux edge host control. Runs as root, invoked by the operator (for
// example over `pct exec`). Prints one JSON object and exits nonzero on refusal.
// Never prints secrets.
//   status | stop | start | manifest DIR | get config|supervisor|edge
//   install-release TGZ NAME MANIFEST | set-release NAME
//   install-file SRC config|supervisor | set-executor-expiry MS
//
// The runtime directory is writable by the service account, so every root
// access to it refuses symbolic links and writes only to files root created
// exclusively; backups go to a root-only directory.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import {
  openSync,
  closeSync,
  readSync,
  writeSync,
  fstatSync,
  fchownSync,
  fchmodSync,
  fsyncSync,
  renameSync,
  existsSync,
  readdirSync,
  lstatSync,
  rmSync,
  mkdirSync,
  mkdtempSync,
  constants,
  readFileSync,
  writeFileSync,
} from "node:fs";
import { join, basename, dirname } from "node:path";

// KADENCO_CTL_ROOT relocates every path (tests only); production uses "/".
const ROOT = process.env.KADENCO_CTL_ROOT ?? "";
const P = (p) => ROOT + p;
const EDGE = P("/etc/kadenco/edge.json");
const RUNTIME = P("/var/lib/kadenco/eddie-t3");
const RELEASES = P("/opt/kadenco/releases");
const BACKUPS = P("/var/backups/kadenco");
const XFER = P("/root/kadenco-xfer");
const LOCK = P("/run/kadenco-edge-ctl.lock");
const UNIT = "kadenco-edge";
// The edge never releases its central lease on exit (120 s TTL): a successor
// started sooner spins in its claim window. Start only after the lease lapsed.
const STOPPED_AT = P("/run/kadenco-edge-stopped-at");
const LEASE_WAIT_MS = Number(process.env.KADENCO_CTL_LEASE_WAIT_MS ?? 130000);
const FILES = {
  // Operator-managed files live in the root-owned /etc/kadenco chain (the edge
  // only reads them), so the service account cannot redirect root's writes by
  // replacing a parent directory.
  config: P("/etc/kadenco/config.json"),
  supervisor: P("/etc/kadenco/central-supervisor.json"),
  edge: EDGE,
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const out = (v) => console.log(JSON.stringify(v));
const fail = (reason) => {
  out({ ok: false, reason });
  process.exit(1);
};
const stamp = () => new Date().toISOString().replace(/[-:]/g, "").replace(/\..*/, "");
const validName = (n) => /^kadenco-0\.1\.0-(alpha|beta)\.[0-9]+-[a-f0-9]{7}$/.test(n ?? "");
const isRoot = process.getuid?.() === 0;
let account;
const serviceAccount = () =>
  (account ??= ROOT
    ? [process.getuid(), process.getgid()]
    : ["-u", "-g"].map((f) =>
        Number(execFileSync("id", [f, "kadenco"], { encoding: "utf8" }).trim()),
      ));

/** Reads a regular file without following a symbolic link at its final component. */
function readSafe(path) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const s = fstatSync(fd);
    if (!s.isFile()) throw Error("not_regular_file");
    const buf = Buffer.alloc(s.size);
    let n = 0;
    while (n < s.size) {
      const r = readSync(fd, buf, n, s.size - n, n);
      if (!r) break;
      n += r;
    }
    return buf.subarray(0, n).toString("utf8");
  } finally {
    closeSync(fd);
  }
}
const readJson = (p) => JSON.parse(readSafe(p));

/** Writes a new file exclusively (never through an existing name), sets its
 * owner and mode on the open descriptor, then renames it over the target. */
function atomicWrite(path, text, owner, mode) {
  const tmp = join(dirname(path), `.${basename(path)}.${randomBytes(8).toString("hex")}`);
  const fd = openSync(
    tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
    mode,
  );
  try {
    writeSync(fd, text);
    if (isRoot) fchownSync(fd, owner[0], owner[1]);
    fchmodSync(fd, mode);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}
/** Copies the current file into the root-only backup directory. */
function backup(path) {
  mkdirSync(BACKUPS, { recursive: true, mode: 0o700 });
  const target = join(BACKUPS, `${basename(path)}.${stamp()}.${randomBytes(3).toString("hex")}`);
  atomicWrite(target, readSafe(path), [0, 0], 0o600);
  return target;
}
/** A transfer file: a fixed-pattern name directly in the root-only directory. */
function transferPath(p) {
  if (dirname(p ?? "") !== XFER || !/^kadenco-[a-f0-9]{32}$/.test(basename(p)))
    fail("invalid_transfer_path");
  const s = lstatSync(p);
  if (!s.isFile()) fail("invalid_transfer_path");
  process.on("exit", () => rmSync(p, { force: true }));
  return p;
}

function lock() {
  try {
    mkdirSync(LOCK);
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
    if (Date.now() - lstatSync(LOCK).mtimeMs < 20 * 60000) fail("operation_in_progress");
    rmSync(LOCK, { recursive: true, force: true });
    mkdirSync(LOCK);
  }
  process.on("exit", () => rmSync(LOCK, { recursive: true, force: true }));
}

function manifest(dir) {
  if (!lstatSync(dir).isDirectory()) fail("release_not_directory");
  const lines = [];
  const walk = (d, rel) => {
    for (const name of readdirSync(d).sort()) {
      const p = join(d, name),
        r = rel ? rel + "/" + name : name,
        s = lstatSync(p);
      if (s.isSymbolicLink()) fail("release_symlink");
      if (s.isDirectory()) walk(p, r);
      else if (s.isFile())
        lines.push(r + "\0" + createHash("sha256").update(readFileSync(p)).digest("hex"));
      else fail("release_special_file");
    }
  };
  walk(dir, "");
  return {
    files: lines.length,
    sha256: createHash("sha256").update(lines.join("\n")).digest("hex"),
  };
}
// Releases are qualified on another platform: refuse anything platform-specific.
function nativeFiles(dir) {
  const found = [];
  const walk = (d) => {
    for (const name of readdirSync(d)) {
      const p = join(d, name),
        s = lstatSync(p);
      if (s.isDirectory()) walk(p);
      else if (/\.(node|exe|dll|so|dylib)$/i.test(name)) found.push(p.slice(dir.length + 1));
    }
  };
  walk(dir);
  return found;
}
/** Only regular files and directories, all under NAME/, no absolute or parent paths. */
function vetArchive(tgz, name) {
  const listing = execFileSync("tar", ["-tvzf", tgz, "--numeric-owner"], {
    encoding: "utf8",
    maxBuffer: 64 << 20,
  });
  const names = execFileSync("tar", ["-tzf", tgz], { encoding: "utf8", maxBuffer: 64 << 20 })
    .split("\n")
    .filter(Boolean);
  const types = listing
    .split("\n")
    .filter(Boolean)
    .map((l) => l[0]);
  if (!names.length || types.length !== names.length) fail("release_archive_unreadable");
  if (types.some((t) => t !== "-" && t !== "d")) fail("release_archive_member_type");
  for (const n of names) {
    const clean = n.replace(/\/$/, "");
    if (clean !== name && !clean.startsWith(name + "/")) fail("release_archive_layout");
    if (clean.split("/").some((seg) => seg === ".." || seg === "." || seg === ""))
      fail("release_archive_path");
  }
}

function edgePort() {
  const port = readJson(FILES.config).port ?? 41880;
  if (!Number.isInteger(port) || port < 1024 || port > 65535) fail("invalid_edge_port");
  return port;
}
async function health(port) {
  const get = async (url) => {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(3000), redirect: "error" });
      return { code: r.status, body: (await r.text()).slice(0, 200).trim() };
    } catch {
      return { code: 0, body: "" };
    }
  };
  const h = await get(`http://127.0.0.1:${port}/healthz`);
  let edge = null;
  try {
    if (h.code === 200) edge = JSON.parse(h.body).status ?? null;
  } catch {}
  const t = await get("http://127.0.0.1:41881/readyz");
  return { edge, tunnel: t.code === 200 && t.body === "ready" ? "ready" : "not_ready" };
}
function unit() {
  const r = spawnSync("systemctl", ["show", UNIT, "-p", "ActiveState", "-p", "MainPID"], {
    encoding: "utf8",
  });
  if (r.status !== 0) fail("unit_probe_failed");
  const v = Object.fromEntries(
    r.stdout
      .trim()
      .split("\n")
      .map((l) => l.split("=")),
  );
  return { state: v.ActiveState ?? "unknown", mainPid: Number(v.MainPID ?? 0) };
}
function listening(ports) {
  const r = spawnSync("ss", ["-ltnH"], { encoding: "utf8" });
  if (r.status !== 0) fail("listener_probe_failed");
  return ports.filter((p) => r.stdout.split("\n").some((l) => new RegExp(`:${p}\\s`).test(l)));
}
async function status() {
  const edge = readJson(EDGE);
  let build = null;
  try {
    const b = readJson(join(edge.releasePath, "BUILD.json"));
    build = { source: b.source, version: b.version };
  } catch {}
  const u = unit();
  let supervisor = null;
  try {
    const s = readJson(join(RUNTIME, "service-status.json"));
    supervisor = {
      // A ready record only counts for the unit's current main process.
      state: s.supervisorPid === u.mainPid ? s.state : "stale",
      at: s.at,
      forwards: (s.callerForwards ?? []).map((f) => `${f.host}:${f.running ? "up" : "down"}`),
    };
  } catch {}
  const sup = readJson(FILES.supervisor);
  return {
    ok: true,
    service: u.state,
    release: basename(edge.releasePath),
    build,
    executorStartupGate: edge.executorExpiresAt,
    serviceExpiresAt: sup.bootstrap?.serviceExpiresAt,
    supervisor,
    mainPid: u.mainPid,
    ...(await health(edgePort())),
  };
}
// Ready only if, after the probes, the unit is still active under the same main
// process whose ready record was read.
const ready = (s) => {
  if (
    !(
      s?.service === "active" &&
      s?.supervisor?.state === "ready" &&
      s?.edge === "up" &&
      s?.tunnel === "ready"
    )
  )
    return false;
  const now = unit();
  return now.state === "active" && now.mainPid === s.mainPid;
};
const kadencoProcesses = () => {
  const r = spawnSync("pgrep", ["-u", "kadenco"], { encoding: "utf8" });
  if (r.status === 1) return false; // no match
  if (r.status !== 0) fail("process_probe_failed");
  return true;
};

const [cmd, ...args] = process.argv.slice(2);
try {
  if (!["status", "manifest", "get"].includes(cmd)) lock();
  if (cmd === "status") out(await status());
  else if (cmd === "stop") {
    const r = spawnSync("systemctl", ["stop", UNIT], { stdio: "ignore" });
    if (r.status !== 0) fail("edge_stop_failed");
    const ports = [edgePort(), 41881];
    const deadline = Date.now() + 60000;
    const busy = () =>
      unit().state === "active" || kadencoProcesses() || listening(ports).length > 0;
    while (Date.now() < deadline && busy()) await sleep(500);
    if (busy()) fail("edge_stop_unverified");
    writeFileSync(STOPPED_AT, String(Date.now()));
    out({ ok: true, stopped: true });
  } else if (cmd === "start") {
    let stoppedAt = 0;
    try {
      stoppedAt = Number(readFileSync(STOPPED_AT, "utf8"));
    } catch {}
    const wait = stoppedAt + LEASE_WAIT_MS - Date.now();
    if (wait > 0) await sleep(Math.min(wait, LEASE_WAIT_MS));
    if (spawnSync("systemctl", ["start", UNIT], { stdio: "ignore" }).status !== 0)
      fail("edge_start_failed");
    const deadline = Date.now() + 360000;
    let s;
    while (Date.now() < deadline) {
      await sleep(3000);
      s = await status();
      if (ready(s) || !["active", "activating"].includes(s.service)) break;
    }
    const ok = ready(s);
    out({ ...s, ok });
    if (!ok) process.exitCode = 1;
  } else if (cmd === "manifest") out({ ok: true, ...manifest(args[0]) });
  else if (cmd === "get") {
    if (!FILES[args[0]]) fail("unknown_file");
    process.stdout.write(readSafe(FILES[args[0]]));
  } else if (cmd === "install-release") {
    const tgz = transferPath(args[0]);
    const [, name, expected] = args;
    if (!validName(name) || !/^[a-f0-9]{64}$/.test(expected ?? "")) fail("invalid_release_request");
    const final = join(RELEASES, name);
    if (existsSync(final)) {
      const m = manifest(final);
      if (m.sha256 !== expected) fail("release_exists_with_different_content");
      out({ ok: true, installed: name, existing: true, ...m });
    } else {
      vetArchive(tgz, name);
      mkdirSync(RELEASES, { recursive: true });
      const staging = mkdtempSync(join(RELEASES, ".staging-"));
      // fail() exits the process, which skips finally blocks: clean up on exit.
      process.on("exit", () => rmSync(staging, { recursive: true, force: true }));
      try {
        execFileSync("tar", [
          "-xzf",
          tgz,
          "-C",
          staging,
          "--no-same-owner",
          "--no-same-permissions",
        ]);
        const inner = join(staging, name);
        if (readdirSync(staging).length !== 1) fail("release_archive_layout");
        const m = manifest(inner);
        if (m.sha256 !== expected) fail("release_manifest_mismatch");
        const native = nativeFiles(inner);
        if (native.length) fail("release_contains_native_binaries:" + native.slice(0, 3).join(","));
        if (isRoot) execFileSync("chown", ["-R", "root:root", inner]);
        execFileSync("chmod", ["-R", "u=rwX,go=rX", inner]);
        renameSync(inner, final);
        out({ ok: true, installed: name, existing: false, ...m });
      } finally {
        rmSync(staging, { recursive: true, force: true });
      }
    }
  } else if (cmd === "set-release") {
    const [name] = args;
    if (
      !validName(name) ||
      !lstatSync(join(RELEASES, name)).isDirectory() ||
      !existsSync(join(RELEASES, name, "BUILD.json"))
    )
      fail("release_not_installed");
    const edge = readJson(EDGE);
    const previous = basename(edge.releasePath);
    const saved = backup(EDGE);
    edge.releasePath = join(RELEASES, name);
    atomicWrite(EDGE, JSON.stringify(edge, null, 2) + "\n", [0, serviceAccount()[1]], 0o640);
    out({ ok: true, release: name, previous, backup: saved });
  } else if (cmd === "install-file") {
    const src = transferPath(args[0]);
    const kind = args[1];
    if (!["config", "supervisor"].includes(kind)) fail("unknown_file");
    const text = readSafe(src);
    JSON.parse(text);
    const saved = backup(FILES[kind]);
    atomicWrite(FILES[kind], text, [0, serviceAccount()[1]], 0o640);
    out({
      ok: true,
      installed: kind,
      sha256: createHash("sha256").update(text).digest("hex"),
      backup: saved,
    });
  } else if (cmd === "set-executor-expiry") {
    // A startup gate: the supervisor refuses to start the edge after it. The
    // running edge's executor expiry is central-supervisor.json's serviceExpiresAt.
    const ms = Number(args[0]);
    if (!Number.isSafeInteger(ms) || ms <= Date.now()) fail("invalid_expiry");
    const edge = readJson(EDGE);
    const previous = edge.executorExpiresAt;
    const saved = backup(EDGE);
    edge.executorExpiresAt = ms;
    atomicWrite(EDGE, JSON.stringify(edge, null, 2) + "\n", [0, serviceAccount()[1]], 0o640);
    out({ ok: true, executorStartupGate: ms, previous, backup: saved });
  } else fail("usage");
} catch (e) {
  fail(/^[a-z_:.,0-9-]+$/i.test(e?.message ?? "") ? e.message : (e?.code ?? "failed"));
}
