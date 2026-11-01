// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync, realpathSync } from "node:fs";
import { dirname, delimiter, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { routeWrangler } from "./cloudflare-route.mjs";

/** Resolve an already installed npm CLI; never install, invoke a shell shim or read auth. */
export function resolveTool(tool, cwd = process.cwd(), path = process.env.PATH ?? "") {
  if (!["cf", "wrangler"].includes(tool)) throw Error("unsupported_tool");
  const roots = [];
  for (let dir = resolve(cwd); ; dir = dirname(dir)) {
    roots.push(join(dir, "node_modules", tool));
    if (dirname(dir) === dir) break;
  }
  for (const dir of path.split(delimiter).filter(Boolean)) {
    roots.push(join(dir, "node_modules", tool), resolve(dir, "../lib/node_modules", tool));
  }
  for (const root of roots) {
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
    } catch (error) {
      if (error.code === "ENOENT" || error.code === "ENOTDIR") continue;
      throw Error("installed_cli_metadata_invalid");
    }
    const bin = typeof pkg.bin === "string" ? pkg.bin : pkg.bin?.[tool];
    if (pkg.name !== tool || typeof bin !== "string") throw Error("installed_cli_metadata_invalid");
    const entry = resolve(root, bin),
      rel = relative(root, entry);
    if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw Error("installed_cli_entry_invalid");
    return entry;
  }
  throw Error(
    `existing_${tool}_installation_required: no login, install or alternate caller attempted`,
  );
}

/** Execute only the reviewed read/local argv plan, once; propagate denials without fallback. */
export function runAgentWrangler(argv, ports = {}) {
  const report = ports.report ?? ((s) => process.stderr.write(s + "\n"));
  const plan = routeWrangler(argv);
  if (!plan.allowed) {
    report(JSON.stringify(plan));
    return 2;
  }
  if (plan.kind === "local-dev-review-bindings") {
    report(
      "manual_local_dev_review_required: inspect remote bindings before direct local Wrangler dev; no command executed",
    );
    return 2;
  }
  try {
    const entry = (ports.resolveTool ?? resolveTool)(plan.executable);
    const result = (ports.spawnSync ?? spawnSync)(process.execPath, [entry, ...plan.argv], {
      stdio: "inherit",
      shell: false,
      windowsHide: true,
    });
    if (result.error) throw Error("cli_start_failed: no retry or fallback attempted");
    return result.status ?? 1;
  } catch (error) {
    report(error.message);
    return 1;
  }
}

if (
  process.argv[1] &&
  realpathSync(fileURLToPath(import.meta.url)) === realpathSync(process.argv[1])
)
  process.exitCode = runAgentWrangler(process.argv.slice(2));
