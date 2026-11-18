#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// `npm audit` with narrow, owner-approved, dated exceptions (audit-exceptions.json).
// Fails on ANY advisory that is not listed, on ANY production vulnerability
// (exceptions are development-only), on an expired or malformed exception, and
// on unreadable reports. Run from the repository root it also fails on a stale
// exception (listed but reported by neither the root nor packages/control-plane),
// which forces its removal once a fix lands.
// Usage: node scripts/audit-gate.mjs [package-dir]   (default: current directory)
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const readable = (report) =>
  report !== null &&
  typeof report === "object" &&
  report.vulnerabilities !== null &&
  typeof report.vulnerabilities === "object" &&
  !Array.isArray(report.vulnerabilities);

/** Root advisories (by GHSA id) reachable from every reported vulnerability. */
export function advisories(report) {
  const out = new Map();
  for (const [name, v] of Object.entries(report?.vulnerabilities ?? {}))
    for (const via of v?.via ?? [])
      if (via && typeof via === "object" && typeof via.url === "string")
        out.set(via.url.split("/").pop(), { package: via.name ?? name, url: via.url });
  return out;
}

/** Strict YYYY-MM-DD calendar date as the start of that UTC day, else NaN. */
export function expiryTime(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return NaN;
  const t = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === value ? t : NaN;
}

/** Pure decision for one package directory: failure reasons (empty = pass). */
export function evaluate(full, production, exceptions, today = new Date()) {
  if (!readable(full)) return ["audit report unreadable"];
  if (!readable(production)) return ["production audit report unreadable"];
  const failures = [];
  const allowed = new Map(exceptions.map((e) => [e.advisory, e]));
  for (const [id, a] of advisories(full)) {
    const e = allowed.get(id);
    const expires = expiryTime(e?.expires);
    if (!e) failures.push(`unapproved advisory ${id} (${a.package})`);
    else if (e.package !== a.package)
      failures.push(`exception ${id} names ${e.package}, found ${a.package}`);
    else if (!Number.isFinite(expires))
      failures.push(`exception ${id} has an invalid expiry date ${JSON.stringify(e.expires)}`);
    else if (!(expires > today.getTime()))
      failures.push(`exception ${id} expired on ${e.expires}; re-approve or fix`);
  }
  // Exceptions cover development tooling only: any production finding fails,
  // even one whose advisory id cannot be extracted from the report.
  const prodIds = [...advisories(production).keys()];
  const prodPackages = Object.keys(production.vulnerabilities);
  if (prodPackages.length)
    failures.push(
      `production dependencies are vulnerable (${prodIds.join(", ") || prodPackages.join(", ")})`,
    );
  return failures;
}

/** Exceptions no longer reported by any audited package. Every report must be readable. */
export function stale(exceptions, reports) {
  if (!reports.every(readable))
    return ["cannot check exception staleness: audit report unreadable"];
  const seen = new Set(reports.flatMap((r) => [...advisories(r).keys()]));
  return exceptions
    .filter((e) => !seen.has(e.advisory))
    .map((e) => `stale exception ${e.advisory}: no longer reported, remove it`);
}

function audit(dir, scope) {
  // Each scan pins its own dependency scope and forces a registry lookup, so
  // NODE_ENV, npm include/omit settings or offline mode cannot change it.
  const env = { ...process.env };
  delete env.NODE_ENV;
  for (const key of Object.keys(env))
    if (/^npm_config_(include|omit|offline|prefer_offline|production|only|dev)$/i.test(key))
      delete env[key];
  const args = [
    "audit",
    "--json",
    "--offline=false",
    "--prefer-offline=false",
    ...(scope === "production" ? ["--omit=dev"] : ["--include=dev", "--include=prod"]),
  ];
  const options = { cwd: dir, env, encoding: "utf8", windowsHide: true, maxBuffer: 64 << 20 };
  // Fixed, constant arguments. Windows needs a shell for npm.cmd; pass one string.
  const r =
    process.platform === "win32"
      ? spawnSync(["npm", ...args].join(" "), { ...options, shell: true })
      : spawnSync("npm", args, options);
  try {
    return JSON.parse(r.stdout);
  } catch {
    return undefined;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = resolve(fileURLToPath(new URL("../", import.meta.url)));
  const dir = resolve(process.argv[2] ?? ".");
  const exceptions = JSON.parse(readFileSync(resolve(root, "audit-exceptions.json"), "utf8"));
  const full = audit(dir, "full");
  const failures = evaluate(full, audit(dir, "production"), exceptions);
  if (dir === root)
    failures.push(
      ...stale(exceptions, [full, audit(resolve(root, "packages/control-plane"), "full")]),
    );
  if (failures.length) {
    for (const f of failures) console.error(`audit-gate: FAIL ${f}`);
    process.exit(1);
  }
  for (const id of advisories(full).keys()) {
    const e = exceptions.find((x) => x.advisory === id);
    console.error(
      `audit-gate: accepted ${id} (${e.package}, dev-only) until ${e.expires}; ${e.tracking}`,
    );
  }
  console.error(`audit-gate: OK ${dir}`);
}
