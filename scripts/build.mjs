// SPDX-License-Identifier: AGPL-3.0-or-later
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";

const root = fileURLToPath(new URL("../", import.meta.url));
const output = resolve(root, "dist");
// Delete only this checkout's generated directory, before compiling with
// noEmitOnError. A failed build cannot leave a stale runnable application.
if (dirname(output) !== resolve(root) || output !== join(resolve(root), "dist"))
  throw Error("Unexpected build output path");
rmSync(output, { recursive: true, force: true });
const result = spawnSync(
  process.execPath,
  [join(root, "node_modules/tsrs/bin/tsrs"), "-p", "tsconfig.json", "--fast"],
  { cwd: root, stdio: "inherit", windowsHide: true },
);
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);
mkdirSync(output, { recursive: true });
for (const file of ["collaboration.html", "collaboration.css"])
  cpSync(join(root, "src", file), join(output, file));
