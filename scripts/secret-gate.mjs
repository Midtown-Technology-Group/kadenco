import { spawnSync } from "node:child_process";
import { accessSync, constants, lstatSync, realpathSync, statSync } from "node:fs";
import { delimiter, dirname, isAbsolute, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

// Resolve from explicit approved configuration or absolute PATH entries only.
// Passing an absolute executable avoids Windows' implicit current-directory lookup.
const roots = [
  realpathSync(fileURLToPath(new URL("../", import.meta.url))),
  realpathSync(process.cwd()),
];
const external = (path) =>
  roots.every((root) => {
    const part = relative(root, path);
    return isAbsolute(part) || part === ".." || part.startsWith(`..${sep}`);
  });
// Python is the bootstrap: reject every Git checkout before executing it.
// Inspect both spellings so symlinks cannot hide a checkout-owned installation.
const inCheckout = (path) => {
  for (let directory = dirname(path); ; directory = dirname(directory)) {
    try {
      lstatSync(join(directory, ".git"));
      return true;
    } catch (error) {
      if (error.code !== "ENOENT") return true;
    }
    if (dirname(directory) === directory) return false;
  }
};
const approved = (path) => {
  try {
    if (!isAbsolute(path) || !external(path) || inCheckout(path)) return null;
    const resolved = realpathSync(path);
    if (!external(resolved) || inCheckout(resolved) || !statSync(resolved).isFile()) return null;
    accessSync(resolved, process.platform === "win32" ? constants.F_OK : constants.X_OK);
    return resolved;
  } catch {
    return null;
  }
};
const configured = process.env.MTG_SECRET_GATE_PYTHON;
const executable = process.platform === "win32" ? "python.exe" : "python3";
const candidates = (process.env.PATH ?? "")
  .split(delimiter)
  .filter((entry) => isAbsolute(entry))
  .map((entry) => join(entry, executable));
const python =
  configured !== undefined ? approved(configured) : candidates.map(approved).find(Boolean);
if (!python) {
  console.error(
    "UNAVAILABLE: select an approved external Python installation on absolute PATH or MTG_SECRET_GATE_PYTHON; publication blocked.",
  );
  process.exit(21);
}
const result = spawnSync(python, ["-I", "scripts/secret_gate.py", ...process.argv.slice(2)], {
  stdio: "inherit",
});
if (result.error) console.error("UNAVAILABLE: Python could not start; publication blocked.");
process.exit(result.error ? 21 : (result.status ?? 4));
