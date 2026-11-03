import { spawnSync } from "node:child_process";
const python = process.platform === "win32" ? "python" : "python3";
const result = spawnSync(python, ["scripts/secret_gate.py", ...process.argv.slice(2)], {
  stdio: "inherit",
});
if (result.error) console.error("UNAVAILABLE: Python could not start; publication blocked.");
process.exit(result.error ? 21 : (result.status ?? 4));
