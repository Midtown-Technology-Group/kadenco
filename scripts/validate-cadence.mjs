// SPDX-License-Identifier: AGPL-3.0-or-later
import { goalManifestFile } from "../dist/cadence-manifest.mjs";
try {
  if (process.argv.length !== 3) throw Error();
  const manifest = goalManifestFile(process.argv[2])();
  console.log(
    JSON.stringify({ valid: true, goals: manifest.goals.length, nativeAccessValidated: false }),
  );
} catch {
  console.error("Invalid cadence manifest; no configuration details logged.");
  process.exitCode = 1;
}
