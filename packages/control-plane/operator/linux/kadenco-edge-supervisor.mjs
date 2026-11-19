#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Kadenco central edge supervisor for a Linux edge host. Port of the Windows
// central-run-service.ps1: secrets come from a secret-store REST endpoint at
// start and reach run-edge.mjs once on private stdin; they are never written to
// disk, argv or logs. The tunnel client receives its own API key and the MCP
// authorization in its environment, as on Windows. systemd restarts the unit.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";
import { isIP } from "node:net";

const CONFIG = process.argv[2] ?? "/etc/kadenco/edge.json";
const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
// The edge policy is operator-managed and read-only to the service.
const policy = JSON.parse(readFileSync(cfg.configPath ?? join(cfg.runtime, "config.json"), "utf8"));
const port = policy.port ?? 41880;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (event, fields = {}) =>
  console.log(JSON.stringify({ at: new Date().toISOString(), event, ...fields }));
let stage = "start";
const children = { adapter: null, tunnel: null, forwards: [] };
let startupFailure = null;

function status(state) {
  const s = {
    state,
    at: new Date().toISOString(),
    supervisorPid: process.pid,
    release: cfg.releasePath,
    adapterPid: children.adapter?.pid,
    tunnelPid: children.tunnel?.pid,
    callerForwards: children.forwards.map((f) => ({
      host: f.route.host,
      pid: f.child?.pid,
      running: !exited(f.child),
    })),
    ...(startupFailure ? { startupFailure } : {}),
  };
  const tmp = join(cfg.runtime, "service-status.tmp");
  writeFileSync(tmp, JSON.stringify(s));
  renameSync(tmp, join(cfg.runtime, "service-status.json"));
}

// The API key travels only to an HTTPS origin, or over plain HTTP to a literal
// private or mesh address (for example an encrypted overlay network). Never
// follow a redirect with it.
function storeOrigin() {
  const u = new URL(cfg.keeper.origin);
  const privateHost =
    isIP(u.hostname) === 4 &&
    /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(
      u.hostname,
    );
  if (u.protocol !== "https:" && !(u.protocol === "http:" && privateHost))
    throw Error("vault_origin_refused");
  if (u.username || u.password || u.search || u.hash || (u.pathname !== "/" && u.pathname !== ""))
    throw Error("vault_origin_refused");
  return u.origin;
}
async function keeperRecord(uid) {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(uid ?? "")) throw Error("vault_record_invalid");
  const key = readFileSync(cfg.keeper.apiKeyFile, "utf8").trim();
  const response = await fetch(storeOrigin() + "/api/v1/executecommand", {
    method: "POST",
    headers: { "api-key": key, "content-type": "application/json" },
    body: JSON.stringify({ command: `get ${uid} --format json` }),
    redirect: "error",
    signal: AbortSignal.timeout(30000),
  });
  const body = await response.json();
  if (!response.ok || body.status !== "success") throw Error("vault_read_failed");
  return typeof body.data === "string" ? JSON.parse(body.data) : body.data;
}
function field(record, label) {
  const f = (record.custom ?? []).filter((c) => c.label === label);
  if (f.length !== 1 || f[0].value?.length !== 1) throw Error("vault_field_ambiguous");
  const v = String(f[0].value[0]).trim();
  if (v.length < 20 || /\s/.test(v)) throw Error("vault_field_invalid");
  return v;
}

const exited = (c) => !c || c.exitCode !== null || c.signalCode !== null || c.spawnfailed === true;
/** Spawns a tracked child whose spawn or stream errors never escape the supervisor. */
function child(command, args, options) {
  const c = spawn(command, args, options);
  c.on("error", (error) => {
    c.spawnfailed = true;
    log("child_error", { command: command.split("/").at(-1), code: error?.code ?? "unknown" });
  });
  c.stdin?.on("error", () => {});
  return c;
}
function forward(route) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(route.host)) throw Error("invalid_forward");
  if (
    !(Number.isInteger(route.remotePort) && route.remotePort >= 1024 && route.remotePort <= 65535)
  )
    throw Error("invalid_forward");
  if (!policy.nativeDelivery?.hosts?.some((h) => h.ssh === route.host))
    throw Error("unenrolled_forward");
  return child(
    "ssh",
    [
      "-N",
      "-T",
      "-n",
      "-o",
      "ConnectTimeout=8",
      "-o",
      "ConnectionAttempts=1",
      "-o",
      "BatchMode=yes",
      "-o",
      "StrictHostKeyChecking=yes",
      "-o",
      "ExitOnForwardFailure=yes",
      "-o",
      "ServerAliveInterval=15",
      "-o",
      "ServerAliveCountMax=3",
      "-R",
      `127.0.0.1:${route.remotePort}:127.0.0.1:${port}`,
      route.host,
    ],
    { stdio: "ignore" },
  );
}

/** Same rule as central-health.ps1: three consecutive edge_lease_unavailable
 * 503s mean this process lost its lease and must be restarted fresh. */
function fenceDecision(previous, code, reason) {
  const count = code === 503 && reason === "edge_lease_unavailable" ? Math.min(3, previous + 1) : 0;
  return { failures: count, restart: count >= 3 };
}
async function health() {
  try {
    const r = await fetch(`http://127.0.0.1:${port}/healthz`, {
      signal: AbortSignal.timeout(3000),
      redirect: "error",
    });
    const text = (await r.text()).slice(0, 1024);
    let body = {};
    try {
      body = JSON.parse(text);
    } catch {}
    return { code: r.status, status: body.status, reason: body.reason };
  } catch {
    return { code: 0 };
  }
}
async function tunnelReady() {
  try {
    const r = await fetch("http://127.0.0.1:41881/readyz", {
      signal: AbortSignal.timeout(3000),
      redirect: "error",
    });
    return r.status === 200 && (await r.text()).trim() === "ready";
  } catch {
    return false;
  }
}

// One shutdown for signals and failures: stops the forwards and the tunnel,
// lets run-edge drain, then kills anything left. Startup checks `stopping`
// after every await, so nothing is spawned or reported ready once it began.
let stopping = false;
let shutdown;
function stopAll() {
  stopping = true;
  return (shutdown ??= (async () => {
    for (const f of children.forwards) if (!exited(f.child)) f.child.kill("SIGTERM");
    if (!exited(children.tunnel)) children.tunnel.kill("SIGTERM");
    if (!exited(children.adapter)) children.adapter.kill("SIGTERM");
    const all = () => [children.adapter, children.tunnel, ...children.forwards.map((f) => f.child)];
    const deadline = Date.now() + 20000;
    while (Date.now() < deadline && all().some((c) => !exited(c))) await sleep(250);
    for (const c of all()) if (!exited(c)) c.kill("SIGKILL");
  })());
}
for (const sig of ["SIGTERM", "SIGINT"])
  process.once(
    sig,
    () =>
      void stopAll().then(() => {
        status("stopped");
        process.exit(0);
      }),
  );
const checkpoint = () => {
  if (stopping) throw Error("shutdown_requested");
};

try {
  stage = "vault_read";
  status(stage);
  const secrets = await keeperRecord(cfg.keeper.secretsRecord);
  checkpoint();
  const tunnelRecord = await keeperRecord(cfg.keeper.tunnelRecord);
  checkpoint();
  const tunnelKey = field(tunnelRecord, cfg.keeper.tunnelField);
  if (tunnelKey.startsWith("tunnel_")) throw Error("vault_field_invalid");
  const mcpBearer = field(secrets, "MCP Bearer");
  if (!(cfg.executorExpiresAt > Date.now())) throw Error("executor_expired");
  stage = "start_adapter";
  const bootstrap = JSON.stringify({
    stateKey: field(secrets, "State Key"),
    executorToken: field(secrets, "Executor Bearer"),
    ownerTokens: [["eddie", mcpBearer]],
  });
  children.adapter = child(
    process.execPath,
    [join(cfg.releasePath, "packages/control-plane/operator/run-edge.mjs"), cfg.supervisorConfig],
    { stdio: ["pipe", "ignore", "pipe"], cwd: cfg.runtime },
  );
  children.adapter.stdin.end(bootstrap);
  // run-edge prints only fixed-field JSON diagnostics on stderr; keep those.
  let pending = "";
  children.adapter.stderr.on("data", (chunk) => {
    pending = (pending + chunk).slice(-8192);
    let i;
    while ((i = pending.indexOf("\n")) >= 0) {
      const line = pending.slice(0, i).trim();
      pending = pending.slice(i + 1);
      try {
        const v = JSON.parse(line);
        if (v && typeof v === "object") {
          if (v.reason || v.stage) startupFailure = v;
          log("adapter", { diagnostic: v });
        }
      } catch {
        if (line.startsWith("Kadenco central edge ready")) log("adapter_ready");
      }
    }
  });
  stage = "adapter_health";
  status(stage);
  const deadline = Date.now() + 180000;
  let ready = false;
  while (Date.now() < deadline && !exited(children.adapter) && !stopping) {
    const h = await health();
    if (h.code === 200 && h.status === "up") {
      ready = true;
      break;
    }
    await sleep(250);
  }
  checkpoint();
  if (!ready) throw Error("adapter_startup_failed");
  stage = "start_children";
  for (const route of cfg.callerForwards ?? [])
    children.forwards.push({ route, child: forward(route), retryAt: Date.now() + 15000 });
  children.tunnel = child(
    cfg.tunnelClient,
    ["run", "--profile", "eddie-t3", "--profile-dir", join(cfg.runtime, "tunnel-profiles")],
    {
      stdio: "ignore",
      cwd: cfg.runtime,
      env: {
        ...process.env,
        CONTROL_PLANE_API_KEY: tunnelKey,
        EDDIE_T3_MCP_AUTH: "Bearer " + mcpBearer,
      },
    },
  );
  status("running");
  log("running", { adapterPid: children.adapter.pid, tunnelPid: children.tunnel.pid });
  let fenceFailures = 0;
  let lastHealth = 0;
  while (!stopping && !exited(children.adapter) && !exited(children.tunnel)) {
    for (const f of children.forwards)
      if (exited(f.child) && Date.now() >= f.retryAt && !stopping) {
        f.child = forward(f.route);
        f.retryAt = Date.now() + 15000;
      }
    if (Date.now() - lastHealth >= 15000) {
      lastHealth = Date.now();
      const h = await health();
      if (stopping) break;
      let state = "degraded";
      if (h.code === 200 && h.status === "up") {
        fenceFailures = 0;
        if ((await tunnelReady()) && children.forwards.every((f) => !exited(f.child)))
          state = "ready";
      } else {
        const d = fenceDecision(fenceFailures, h.code, h.reason);
        fenceFailures = d.failures;
        if (d.restart) {
          stage = "lease_recovery";
          status("edge_fenced");
          throw Error("edge_fenced");
        }
      }
      if (stopping) break;
      status(state);
    }
    await sleep(2000);
  }
  if (!stopping) {
    status("child_exited");
    log("child_exited", { adapter: children.adapter.exitCode, tunnel: children.tunnel?.exitCode });
    await stopAll();
    process.exit(1);
  }
} catch (error) {
  // A signal-driven shutdown finishes in its own handler.
  if (stopping && error?.message === "shutdown_requested") await new Promise(() => {});
  // Never print raw provider output, bodies or secret-bearing text.
  const reason =
    error instanceof Error && /^[a-z_]+$/.test(error.message) ? error.message : "failed";
  log("failed", { stage, reason });
  try {
    status(stage + "_failed");
  } catch {}
  await stopAll();
  process.exit(1);
}
