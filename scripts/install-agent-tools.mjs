// SPDX-License-Identifier: AGPL-3.0-or-later
// Operator-only, additive integration into supported user-level tool catalogs.
// Plan contains paths/launch metadata only. Credential contents are never read.
import {
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  lstatSync,
  chmodSync,
  renameSync,
  unlinkSync,
} from "node:fs";
import { resolve, join, dirname, relative, isAbsolute } from "node:path";
import { pathToFileURL } from "node:url";
import { parse, modify, applyEdits } from "jsonc-parser";
const marker = "# >>> Eddie T3 managed MCP >>>",
  end = "# <<< Eddie T3 managed MCP <<<";
const psQuote = (s) => "'" + s.replaceAll("'", "''") + "'";
const quote = (s) => "'" + s.replaceAll("'", "'\"'\"'") + "'";
function read(path) {
  let fd;
  try {
    // POSIX: O_NOFOLLOW refuses a final symlink and the checks below apply to
    // the very file read. Windows has no such flag; check the link first.
    if (constants.O_NOFOLLOW === undefined && lstatSync(path).isSymbolicLink())
      throw Error("unowned_or_unsafe_path");
    fd = openSync(
      path,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
  } catch (error) {
    if (error.code === "ENOENT") return null;
    if (error.code === "ELOOP" || error.code === "EISDIR") throw Error("unowned_or_unsafe_path");
    throw error;
  }
  try {
    if (!fstatSync(fd).isFile()) throw Error("unowned_or_unsafe_path");
    return readFileSync(fd, "utf8");
  } finally {
    closeSync(fd);
  }
}
function json(text) {
  const errors = [],
    p = parse(text ?? "{}", errors, { allowTrailingComma: true });
  if (errors.length || !p || typeof p !== "object" || Array.isArray(p))
    throw Error("invalid_configuration");
  return p;
}
function removeLegacyOpenCode(home, manifest, path, before, legacyManifestPath) {
  const legacy = json(before).mcp?.ask_eddie;
  if (legacy === undefined) return before;
  const owns = (m) =>
    m.resources?.[path] !== undefined &&
    JSON.stringify(m.resources[path]) === JSON.stringify(legacy);
  if (!owns(manifest)) {
    if (!legacyManifestPath || !isAbsolute(legacyManifestPath))
      throw Error("unowned_legacy_mcp_entry");
    const source = resolve(legacyManifestPath),
      root = join(home, ".config", "eddie-t3"),
      rel = relative(root, source);
    if (rel.startsWith("..") || isAbsolute(rel)) throw Error("outside_ownership_directory");
    let parent = source;
    while (parent !== home) {
      if (existsSync(parent) && lstatSync(parent).isSymbolicLink()) throw Error("unsafe_symlink");
      parent = dirname(parent);
    }
    if (!owns(json(read(source)))) throw Error("unowned_legacy_mcp_entry");
  }
  return applyEdits(
    before,
    modify(before, ["mcp", "ask_eddie"], undefined, {
      formattingOptions: { insertSpaces: true, tabSize: 2 },
    }),
  );
}
// Requires an operator-established exclusive-writer window and trusted directories.
// Byte rechecks followed by rename are NOT atomic compare-and-swap.
// Narrow repair for already-migrated v2 catalogs: preserve the currently owned
// nested server, credentials, connection metadata and every other provider file.
export function repairOwnedOpenCode2(plan) {
  if (plan.exclusiveWriter !== true) throw Error("exclusive_writer_window_required");
  if (!isAbsolute(plan.home)) throw Error("outside_home");
  const home = resolve(plan.home),
    root = join(home, ".config", "eddie-t3");
  for (let ancestor = home; ; ancestor = dirname(ancestor)) {
    if (existsSync(ancestor) && lstatSync(ancestor).isSymbolicLink()) throw Error("unsafe_symlink");
    if (dirname(ancestor) === ancestor) break;
  }
  const path = existsSync(join(home, ".config", "opencode", "opencode.jsonc"))
    ? join(home, ".config", "opencode", "opencode.jsonc")
    : join(home, ".config", "opencode", "opencode.json");
  for (const file of [path, join(root, "installation.json")]) {
    let parent = file;
    while (parent !== home) {
      if (existsSync(parent) && lstatSync(parent).isSymbolicLink()) throw Error("unsafe_symlink");
      parent = dirname(parent);
    }
  }
  const manifestPath = join(root, "installation.json"),
    manifestText = read(manifestPath),
    manifest = json(manifestText),
    before = read(path),
    data = json(before);
  if (
    !data.mcp?.servers?.ask_eddie ||
    JSON.stringify(data.mcp.servers.ask_eddie) !== JSON.stringify(manifest.resources?.[path])
  )
    throw Error("owned_entry_drift");
  const after = removeLegacyOpenCode(home, manifest, path, before, plan.legacyOpenCodeManifest);
  if (after === before) return { changed: false, host: manifest.host };
  const stamp = Date.now() + "-" + process.pid,
    backup = join(root, "opencode2-repair-" + stamp);
  writeFileSync(backup + ".config", before, { mode: 0o600, flag: "wx" });
  writeFileSync(backup + ".manifest", manifestText, { mode: 0o600, flag: "wx" });
  const temp = path + ".eddie-repair-" + stamp;
  writeFileSync(temp, after, { mode: 0o600, flag: "wx" });
  if (read(path) !== before || read(manifestPath) !== manifestText) {
    unlinkSync(temp);
    throw Error("concurrent_configuration_change");
  }
  renameSync(temp, path);
  return {
    changed: true,
    host: manifest.host,
    backup,
    refresh:
      "Use supported MCP refresh or the next provider session; no agents or services restarted.",
  };
}
export function installAgentTools(plan) {
  const home = resolve(plan.home),
    root = join(home, ".config", "eddie-t3"),
    manifestPath = join(root, "installation.json");
  if (
    !isAbsolute(plan.home) ||
    typeof plan.command !== "string" ||
    !Array.isArray(plan.args) ||
    plan.args.some((x) => typeof x !== "string") ||
    typeof plan.host !== "string" ||
    !isAbsolute(plan.releasePath) ||
    !isAbsolute(plan.nodePath)
  )
    throw Error("invalid_install_plan");
  const prior = read(manifestPath),
    manifest = prior ? json(prior) : { resources: {} };
  const changes = [],
    resources = {};
  const checkPath = (path) => {
    const rel = relative(home, path);
    if (rel.startsWith("..") || isAbsolute(rel)) throw Error("outside_home");
    let parent = path;
    while (parent !== home) {
      if (existsSync(parent) && lstatSync(parent).isSymbolicLink()) throw Error("unsafe_symlink");
      parent = dirname(parent);
    }
  };
  // `before` is the snapshot `after` was computed from: the commit refuses to
  // replace a file that changed since, so concurrent edits are never lost.
  const stage = (path, before, after, managed) => {
    checkPath(path);
    changes.push({ path, before, after });
    resources[path] = managed;
  };
  const owned = (path, current) => {
    const old = manifest.resources[path];
    return old && JSON.stringify(old) === JSON.stringify(current);
  };
  const entry = { command: plan.command, args: plan.args };
  // Codex reads a TOML table. Only this exact owned marker block is replaced;
  // unrelated tables/comments remain byte-for-byte unchanged.
  const codex = join(home, ".codex", "config.toml"),
    rawCodex = read(codex),
    beforeCodex = rawCodex ?? "";
  const begin = beforeCodex.indexOf(marker),
    finish = beforeCodex.indexOf(end);
  let block = null;
  if (begin >= 0 || finish >= 0) {
    if (begin < 0 || finish < begin) throw Error("invalid_managed_block");
    block = beforeCodex.slice(begin, finish + end.length);
    if (!owned(codex, block)) throw Error("owned_entry_drift");
  } else if (/ask_eddie/.test(beforeCodex)) throw Error("unowned_mcp_entry");
  const nextBlock =
    marker +
    "\n[mcp_servers.ask_eddie]\ncommand = " +
    JSON.stringify(plan.command) +
    "\nargs = " +
    JSON.stringify(plan.args) +
    "\nstartup_timeout_sec = 45\n" +
    end;
  stage(
    codex,
    rawCodex,
    block ? beforeCodex.replace(block, nextBlock) : beforeCodex + "\n" + nextBlock + "\n",
    nextBlock,
  );
  const opendir = join(home, ".config", "opencode"),
    open = existsSync(join(opendir, "opencode.jsonc"))
      ? join(opendir, "opencode.jsonc")
      : join(opendir, "opencode.json");
  const openMajor = plan.opencodeMajor ?? 1;
  if (![1, 2].includes(openMajor)) throw Error("invalid_opencode_major");
  const openKeys = openMajor === 2 ? ["mcp", "servers", "ask_eddie"] : ["mcp", "ask_eddie"];
  const openValue =
    openMajor === 2
      ? { type: "local", command: [plan.command, ...plan.args] }
      : { type: "local", command: [plan.command, ...plan.args], enabled: true, timeout: 45000 };
  for (const [path, keys, value] of [
    [open, openKeys, openValue],
    [join(home, ".cursor", "mcp.json"), ["mcpServers", "ask_eddie"], entry],
    [join(home, ".jcode", "mcp.json"), ["mcpServers", "ask_eddie"], entry],
    [join(home, ".claude.json"), ["mcpServers", "ask_eddie"], { type: "stdio", ...entry }],
  ]) {
    const raw = read(path),
      before = raw ?? "{}",
      data = json(before);
    let parent = data;
    for (const key of keys.slice(0, -1)) {
      if (
        parent?.[key] !== undefined &&
        (!parent[key] || typeof parent[key] !== "object" || Array.isArray(parent[key]))
      )
        throw Error("invalid_configuration");
      parent = parent?.[key];
    }
    const current = parent?.[keys.at(-1)];
    if (current !== undefined && !owned(path, current)) throw Error("unowned_mcp_entry");
    const base =
      path === open && openMajor === 2
        ? removeLegacyOpenCode(home, manifest, path, before, plan.legacyOpenCodeManifest)
        : before;
    stage(
      path,
      raw,
      applyEdits(
        base,
        modify(base, keys, value, { formattingOptions: { insertSpaces: true, tabSize: 2 } }),
      ),
      value,
    );
  }
  const extension = join(home, ".pi", "agent", "extensions", "eddie-t3.ts");
  const source =
    '// Managed Eddie T3 passive tools; no execution grant.\nimport {Type} from "@sinclair/typebox";\nimport {registerPiEddie} from ' +
    JSON.stringify(pathToFileURL(join(plan.releasePath, "scripts", "pi-eddie.mjs")).href) +
    ";\nexport default function(pi){registerPiEddie(pi,Type," +
    JSON.stringify(join(root, "connection.json")) +
    ");}\n";
  const beforeExtension = read(extension);
  if (beforeExtension !== null && !owned(extension, beforeExtension))
    throw Error("owned_entry_drift");
  stage(extension, beforeExtension, source, source);
  const connection = join(root, "connection.json");
  const beforeConnection = read(connection);
  if (beforeConnection !== null && !owned(connection, beforeConnection))
    throw Error("owned_entry_drift");
  const connectionText = JSON.stringify({ host: plan.host, ...entry }, null, 2) + "\n";
  stage(connection, beforeConnection, connectionText, connectionText);
  const cli = join(
    home,
    ".local",
    "bin",
    process.platform === "win32" ? "ask-eddie.ps1" : "ask-eddie",
  );
  const cliText =
    process.platform === "win32"
      ? 'param([Parameter(Mandatory)][ValidateSet("ask","get","conversation","capabilities","ack_reply","ack_delivery")][string]$Mode,[Parameter(Mandatory)][string]$RequestFile)\n& ' +
        psQuote(plan.nodePath) +
        " " +
        psQuote(join(plan.releasePath, "scripts", "agent-tool.mjs")) +
        " " +
        psQuote(connection) +
        " $Mode $RequestFile\nexit $LASTEXITCODE\n"
      : "#!/bin/sh\nexec " +
        quote(plan.nodePath) +
        " " +
        quote(join(plan.releasePath, "scripts", "agent-tool.mjs")) +
        " " +
        quote(connection) +
        ' "$@"\n';
  const beforeCli = read(cli);
  if (beforeCli !== null && !owned(cli, beforeCli)) throw Error("owned_entry_drift");
  stage(cli, beforeCli, cliText, cliText);
  // All collisions were checked before the first write. Full-file backups remain
  // private because user configurations may contain unrelated credentials.
  mkdirSync(root, { recursive: true, mode: 0o700 });
  if (process.platform !== "win32") chmodSync(root, 0o700);
  const stamp = Date.now() + "-" + process.pid;
  const applied = [],
    manifestTemp = manifestPath + ".eddie-" + stamp;
  try {
    // Writing the backup and temp file first leaves only the recheck and the
    // rename between a concurrent save and our replacement. That window cannot
    // be closed with file APIs alone: run with providers idle (an exclusive
    // writer window) to guarantee no concurrent edit is replaced.
    for (let i = 0; i < changes.length; i++) {
      const c = changes[i];
      if (c.before === c.after) {
        if (read(c.path) !== c.before) throw Error("concurrent_configuration_change");
        continue;
      }
      if (c.before !== null)
        writeFileSync(join(root, "backup-" + stamp + "-" + i), c.before, {
          mode: 0o600,
          flag: "wx",
        });
      mkdirSync(dirname(c.path), { recursive: true, mode: 0o700 });
      const temp = c.path + ".eddie-" + stamp;
      writeFileSync(temp, c.after, { mode: c.path === cli ? 0o700 : 0o600, flag: "wx" });
      if (read(c.path) !== c.before) {
        unlinkSync(temp);
        throw Error("concurrent_configuration_change");
      }
      renameSync(temp, c.path);
      applied.push(c);
    } // The ownership manifest commits last, atomically, inside the transaction:
    // if it cannot be written, the catalog changes above are rolled back.
    writeFileSync(
      manifestTemp,
      JSON.stringify({ version: "0.10.5", host: plan.host, resources }, null, 2),
      { mode: 0o600, flag: "wx" },
    );
    renameSync(manifestTemp, manifestPath);
  } catch (error) {
    try {
      unlinkSync(manifestTemp);
    } catch {
      // Not written.
    }
    for (const c of applied.reverse()) {
      if (read(c.path) !== c.after) throw Error("rollback_configuration_drift");
      if (c.before === null) unlinkSync(c.path);
      else writeFileSync(c.path, c.before, { mode: 0o600 });
    }
    throw error;
  }
  return {
    installed: true,
    host: plan.host,
    catalogs: ["codex", "opencode", "cursor", "claude", "pi", "jcode"],
    cli,
    refresh:
      "Existing provider sessions may need their supported MCP refresh or next session. No agents were restarted.",
  };
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try {
    const repair = process.argv[2] === "--repair-opencode2",
      plan = JSON.parse(readFileSync(process.argv[repair ? 3 : 2], "utf8").replace(/^\uFEFF/, ""));
    console.log(JSON.stringify(repair ? repairOwnedOpenCode2(plan) : installAgentTools(plan)));
  } catch {
    console.error(
      "Eddie tool installation refused; inspect catalog ownership, plan and private backups.",
    );
    process.exitCode = 1;
  }
}
