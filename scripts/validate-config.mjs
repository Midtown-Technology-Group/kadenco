// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { configSchema } from "../src/config.mjs";
try {
  configSchema.parse(JSON.parse(readFileSync(process.argv[2], "utf8")));
} catch {
  console.error("Invalid adapter policy; no configuration details logged.");
  process.exitCode = 1;
}
