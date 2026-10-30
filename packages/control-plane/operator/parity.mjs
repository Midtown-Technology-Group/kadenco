// SPDX-License-Identifier: AGPL-3.0-or-later
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const result = spawnSync(
  process.execPath,
  [
    "--test",
    "test/host-callers.test.mjs",
    "test/collaboration.test.mjs",
    "test/relay-correctness.test.mjs",
    "test/thread-settings.test.mjs",
  ],
  { cwd: root, stdio: "inherit", windowsHide: true },
);
process.exitCode = result.status ?? 1;
