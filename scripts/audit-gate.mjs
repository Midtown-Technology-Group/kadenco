#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// `npm audit` with narrow, owner-approved, dated exceptions (audit-exceptions.json).
// Fails on ANY advisory that is not listed, on a listed advisory that reaches
// production dependencies, and on an expired exception. Run from the repository
// root it also fails on a stale exception (listed but reported by neither the
// root nor packages/control-plane), which forces its removal once a fix lands.
// Usage: node scripts/audit-gate.mjs [package-dir]   (default: current directory)
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

/** Root advisories (by GHSA id) reachable from every reported vulnerability. */
export function advisories(report) {
  const out = new Map();
  for (const [name, v] of Object.entries(report?.vulnerabilities ?? {}))
    for (const via of v.via ?? [])
      if (via && typeof via === "object" && typeof via.url === "string")
        out.set(via.url.split("/").pop(), { package: via.name ?? name, url: via.url });
  return out;
}

/** Pure decision for one package directory: failure reasons (empty = pass). */
export function evaluate(full, production, exceptions, today = new Date()) {
  if (!full || typeof full.vulnerabilities !== "object") return ["audit report unreadable"];
  if (!production || typeof production.vulnerabilities !== "object")
    return ["production audit report unreadable"];
  const failures = [];
  const allowed = new Map(exceptions.map((e) => [e.advisory, e]));
  for (const [id, a] of advisories(full)) {
    const e = allowed.get(id);
    if (!e) failures.push(`unapproved advisory ${id} (${a.package})`);
    else if (e.package !== a.package)
      failures.push(`exception ${id} names ${e.package}, found ${a.package}`);
    else if (!(Date.parse(e.expires) > today.getTime()))
      failures.push(`exception ${id} expired on ${e.expires}; re-approve or fix`);
  }
  // Exceptions cover development tooling only.
  for (const id of advisories(production).keys())
    failures.push(`advisory ${id} reaches production dependencies`);
  return failures;
}

/** Exceptions no longer reported by any audited package. */
export function stale(exceptions, reports) {
  const seen = new Set(reports.flatMap((r) => [...advisories(r).keys()]));
  return exceptions
    .filter((e) => !seen.has(e.advisory))
    .map((e) => `stale exception ${e.advisory}: no longer reported, remove it`);
}

function audit(dir, args = []) {
  const options = {
    cwd: dir,
    encoding: "utf8",
    windowsHide: true,
    maxBuffer: 64 * 1024 * 1024,
  };
  // Fixed, constant arguments. Windows needs a shell for npm.cmd; pass one string.
  const r =
    process.platform === "win32"
      ? spawnSync(["npm", "audit", "--json", ...args].join(" "), { ...options, shell: true })
      : spawnSync("npm", ["audit", "--json", ...args], options);
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
  const full = audit(dir);
  const failures = evaluate(full, audit(dir, ["--omit=dev"]), exceptions);
  if (dir === root)
    failures.push(...stale(exceptions, [full, audit(resolve(root, "packages/control-plane"))]));
  for (const id of advisories(full).keys()) {
    const e = exceptions.find((x) => x.advisory === id);
    if (e)
      console.error(
        `audit-gate: accepting ${id} (${e.package}, dev-only) until ${e.expires}; ${e.tracking}`,
      );
  }
  if (failures.length) {
    for (const f of failures) console.error(`audit-gate: FAIL ${f}`);
    process.exit(1);
  }
  console.error(`audit-gate: OK ${dir}`);
}
