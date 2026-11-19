#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Kadenco central edge supervisor for a Linux edge host. Port of the
// Windows central-run-service.ps1: secrets come from the operator's Keeper REST
// service at start, reach run-edge.mjs once on private stdin, and are never
// written to disk, argv or logs. systemd restarts the whole process group.
import { spawn } from "node:child_process";
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { join } from "node:path";

const CONFIG = process.argv[2] ?? "/etc/kadenco/edge.json";
const cfg = JSON.parse(readFileSync(CONFIG, "utf8"));
const policy = JSON.parse(readFileSync(join(cfg.runtime, "config.json"), "utf8"));
const port = policy.port;
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
      running: f.child?.exitCode === null && !f.child?.killed,
    })),
    ...(startupFailure ? { startupFailure } : {}),
  };
  const tmp = join(cfg.runtime, "service-status.tmp");
  writeFileSync(tmp, JSON.stringify(s));
  renameSync(tmp, join(cfg.runtime, "service-status.json"));
}

async function keeperRecord(uid) {
  const key = readFileSync(cfg.keeper.apiKeyFile, "utf8").trim();
  const response = await fetch(cfg.keeper.origin + "/api/v1/executecommand", {
    method: "POST",
    headers: { "api-key": key, "content-type": "application/json" },
    body: JSON.stringify({ command: `get ${uid} --format json` }),
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

const exited = (c) => !c || c.exitCode !== null || c.signalCode !== null;
function forward(route) {
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(route.host)) throw Error("invalid_forward");
  if (
    !(Number.isInteger(route.remotePort) && route.remotePort >= 1024 && route.remotePort <= 65535)
  )
    throw Error("invalid_forward");
  if (!policy.nativeDelivery?.hosts?.some((h) => h.ssh === route.host))
    throw Error("unenrolled_forward");
  return spawn(
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
    const r = await fetch("http://127.0.0.1:41881/readyz", { signal: AbortSignal.timeout(3000) });
    return r.status === 200 && (await r.text()).trim() === "ready";
  } catch {
    return false;
  }
}

let stopping = false;
async function stopAll(signal = "SIGTERM") {
  stopping = true;
  for (const f of children.forwards) if (!exited(f.child)) f.child.kill("SIGTERM");
  if (!exited(children.tunnel)) children.tunnel.kill("SIGTERM");
  // run-edge drains on SIGTERM and exits; give it the lease-release window.
  if (!exited(children.adapter)) children.adapter.kill(signal);
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline && [children.adapter, children.tunnel].some((c) => !exited(c)))
    await sleep(250);
  for (const c of [children.adapter, children.tunnel, ...children.forwards.map((f) => f.child)])
    if (!exited(c)) c.kill("SIGKILL");
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

try {
  stage = "vault_read";
  status(stage);
  const secrets = await keeperRecord(cfg.keeper.secretsRecord);
  const tunnelRecord = await keeperRecord(cfg.keeper.tunnelRecord);
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
  children.adapter = spawn(
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
  while (Date.now() < deadline && !exited(children.adapter)) {
    const h = await health();
    if (h.code === 200 && h.status === "up") {
      ready = true;
      break;
    }
    await sleep(250);
  }
  if (!ready) throw Error("adapter_startup_failed");
  stage = "start_children";
  for (const route of cfg.callerForwards ?? [])
    children.forwards.push({ route, child: forward(route), retryAt: Date.now() + 15000 });
  children.tunnel = spawn(
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
      if (exited(f.child) && Date.now() >= f.retryAt) {
        f.child = forward(f.route);
        f.retryAt = Date.now() + 15000;
      }
    if (Date.now() - lastHealth >= 15000) {
      lastHealth = Date.now();
      const h = await health();
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
