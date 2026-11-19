#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Kadenco Linux edge host control. Runs as root, invoked by the
// operator over `pct exec`. Prints one JSON object; never prints secrets.
//   status | stop | start | manifest DIR | get config|supervisor|edge
//   install-release TGZ NAME MANIFEST | set-release NAME
//   install-file SRC config|supervisor | set-executor-expiry MS
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  readFileSync,
  writeFileSync,
  renameSync,
  existsSync,
  readdirSync,
  lstatSync,
  copyFileSync,
  chownSync,
  chmodSync,
  rmSync,
  mkdirSync,
} from "node:fs";
import { join, basename } from "node:path";

const EDGE = "/etc/kadenco/edge.json";
const RUNTIME = "/var/lib/kadenco/eddie-t3";
const RELEASES = "/opt/kadenco/releases";
const UNIT = "kadenco-edge";
// The edge never releases its central lease on exit (120 s TTL): a successor
// started sooner spins in its claim window. Start only after the lease lapsed.
const STOPPED_AT = "/run/kadenco-edge-stopped-at";
const LEASE_WAIT_MS = 130000;
const FILES = {
  config: join(RUNTIME, "config.json"),
  supervisor: join(RUNTIME, "central-supervisor.json"),
  edge: EDGE,
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const out = (v) => console.log(JSON.stringify(v));
const fail = (reason) => {
  out({ ok: false, reason });
  process.exit(1);
};
const readJson = (p) => JSON.parse(readFileSync(p, "utf8"));
const uid = Number(execFileSync("id", ["-u", "kadenco"], { encoding: "utf8" }).trim());
const gid = Number(execFileSync("id", ["-g", "kadenco"], { encoding: "utf8" }).trim());
const stamp = () => new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
const validName = (n) => /^kadenco-0\.1\.0-(alpha|beta)\.[0-9]+-[a-f0-9]{7}$/.test(n);

function manifest(dir) {
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
// Releases are copied from a Windows-qualified installation: refuse anything
// platform-specific instead of discovering it at startup.
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
async function health() {
  const get = async (url) => {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
      return { code: r.status, body: (await r.text()).slice(0, 200).trim() };
    } catch {
      return { code: 0, body: "" };
    }
  };
  const h = await get("http://127.0.0.1:41880/healthz");
  let edge = null;
  try {
    edge = JSON.parse(h.body).status;
  } catch {}
  const t = await get("http://127.0.0.1:41881/readyz");
  return { edge, tunnel: t.code === 200 && t.body === "ready" ? "ready" : "not_ready" };
}
function serviceState() {
  const r = spawnSync("systemctl", ["is-active", UNIT], { encoding: "utf8" });
  return r.stdout.trim();
}
async function status() {
  const edge = readJson(EDGE);
  let build = null;
  try {
    const b = readJson(join(edge.releasePath, "BUILD.json"));
    build = { source: b.source, version: b.version };
  } catch {}
  let supervisor = null;
  try {
    const s = readJson(join(RUNTIME, "service-status.json"));
    supervisor = {
      state: s.state,
      at: s.at,
      forwards: (s.callerForwards ?? []).map((f) => `${f.host}:${f.running ? "up" : "down"}`),
    };
  } catch {}
  const sup = readJson(FILES.supervisor);
  return {
    ok: true,
    service: serviceState(),
    release: basename(edge.releasePath),
    build,
    executorExpiresAt: edge.executorExpiresAt,
    serviceExpiresAt: sup.bootstrap?.serviceExpiresAt,
    supervisor,
    ...(await health()),
  };
}
function processes() {
  const r = spawnSync("pgrep", ["-u", "kadenco", "-l"], { encoding: "utf8" });
  return r.stdout.trim().split("\n").filter(Boolean);
}
function atomicWrite(path, text, owner, mode) {
  const tmp = path + ".next";
  writeFileSync(tmp, text, { mode });
  chownSync(tmp, owner[0], owner[1]);
  chmodSync(tmp, mode);
  renameSync(tmp, path);
}
function backup(path) {
  const b = `${path}.bak-${stamp()}`;
  copyFileSync(path, b);
  return b;
}

const [cmd, ...args] = process.argv.slice(2);
try {
  if (cmd === "status") out(await status());
  else if (cmd === "stop") {
    spawnSync("systemctl", ["stop", UNIT], { stdio: "ignore" });
    const deadline = Date.now() + 60000;
    while (Date.now() < deadline && (serviceState() === "active" || processes().length))
      await sleep(500);
    const left = processes();
    const h = await health();
    if (serviceState() === "active" || left.length || h.edge) fail("edge_stop_unverified");
    writeFileSync(STOPPED_AT, String(Date.now()));
    out({ ok: true, stopped: true });
  } else if (cmd === "start") {
    let stoppedAt = 0;
    try {
      stoppedAt = Number(readFileSync(STOPPED_AT, "utf8"));
    } catch {}
    const wait = stoppedAt + LEASE_WAIT_MS - Date.now();
    if (wait > 0) await sleep(Math.min(wait, LEASE_WAIT_MS));
    const r = spawnSync("systemctl", ["start", UNIT], { encoding: "utf8" });
    if (r.status !== 0) fail("edge_start_failed");
    const deadline = Date.now() + 360000;
    let s;
    while (Date.now() < deadline) {
      await sleep(3000);
      s = await status();
      if (s.supervisor?.state === "ready" && s.edge === "up" && s.tunnel === "ready") break;
      if (s.service !== "active" && s.service !== "activating") break;
    }
    out({
      ...s,
      ok: s?.supervisor?.state === "ready" && s?.edge === "up" && s?.tunnel === "ready",
    });
  } else if (cmd === "manifest") out({ ok: true, ...manifest(args[0]) });
  else if (cmd === "get") {
    if (!FILES[args[0]]) fail("unknown_file");
    process.stdout.write(readFileSync(FILES[args[0]], "utf8"));
  } else if (cmd === "install-release") {
    const [tgz, name, expected] = args;
    // The transfer copy is consumed on every outcome, including refusals.
    if (tgz?.startsWith("/root/kadenco-xfer/"))
      process.on("exit", () => rmSync(tgz, { force: true }));
    if (!validName(name) || !/^[a-f0-9]{64}$/.test(expected ?? "")) fail("invalid_release_request");
    const final = join(RELEASES, name);
    if (existsSync(final)) {
      const m = manifest(final);
      if (m.sha256 !== expected) fail("release_exists_with_different_content");
      rmSync(tgz, { force: true });
      out({ ok: true, installed: name, existing: true, ...m });
    } else {
      const staging = join(RELEASES, ".staging-" + name);
      rmSync(staging, { recursive: true, force: true });
      mkdirSync(staging, { recursive: true });
      execFileSync("tar", ["-xzf", tgz, "-C", staging, "--no-same-owner", "--no-same-permissions"]);
      rmSync(tgz, { force: true });
      const inner = join(staging, name);
      if (!existsSync(inner) || readdirSync(staging).length !== 1) fail("release_archive_layout");
      const m = manifest(inner);
      if (m.sha256 !== expected) fail("release_manifest_mismatch");
      const native = nativeFiles(inner);
      if (native.length) fail("release_contains_native_binaries:" + native.slice(0, 3).join(","));
      execFileSync("chown", ["-R", "root:root", inner]);
      execFileSync("chmod", ["-R", "u=rwX,go=rX", inner]);
      renameSync(inner, final);
      rmSync(staging, { recursive: true, force: true });
      out({ ok: true, installed: name, existing: false, ...m });
    }
  } else if (cmd === "set-release") {
    const [name] = args;
    if (!validName(name) || !existsSync(join(RELEASES, name, "BUILD.json")))
      fail("release_not_installed");
    const edge = readJson(EDGE);
    const previous = basename(edge.releasePath);
    const saved = backup(EDGE);
    edge.releasePath = join(RELEASES, name);
    atomicWrite(EDGE, JSON.stringify(edge, null, 2) + "\n", [0, gid], 0o640);
    out({ ok: true, release: name, previous, backup: saved });
  } else if (cmd === "install-file") {
    const [src, kind] = args;
    if (src?.startsWith("/root/kadenco-xfer/"))
      process.on("exit", () => rmSync(src, { force: true }));
    if (!["config", "supervisor"].includes(kind)) fail("unknown_file");
    const text = readFileSync(src, "utf8");
    JSON.parse(text);
    const saved = backup(FILES[kind]);
    atomicWrite(FILES[kind], text, [uid, gid], 0o600);
    rmSync(src, { force: true });
    out({
      ok: true,
      installed: kind,
      sha256: createHash("sha256").update(text).digest("hex"),
      backup: saved,
    });
  } else if (cmd === "set-executor-expiry") {
    const ms = Number(args[0]);
    if (!Number.isSafeInteger(ms) || ms <= Date.now()) fail("invalid_expiry");
    const edge = readJson(EDGE);
    const previous = edge.executorExpiresAt;
    const saved = backup(EDGE);
    edge.executorExpiresAt = ms;
    atomicWrite(EDGE, JSON.stringify(edge, null, 2) + "\n", [0, gid], 0o640);
    out({ ok: true, executorExpiresAt: ms, previous, backup: saved });
  } else fail("usage");
} catch (e) {
  fail(/^[a-z_:.,0-9-]+$/i.test(e?.message ?? "") ? e.message : "failed");
}
