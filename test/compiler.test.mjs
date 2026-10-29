// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

test("both pinned compilers reject a known type error with checking enabled", () => {
  const directory = mkdtempSync(join(tmpdir(), "kadenco-compiler-"));
  try {
    const input = join(directory, "invalid.mts");
    writeFileSync(input, 'const number: number = "not a number"; export {number};');
    for (const compiler of ["tsrs/bin/tsrs", "typescript/bin/tsc"]) {
      const binary = fileURLToPath(new URL("../node_modules/" + compiler, import.meta.url));
      const result = spawnSync(
        process.execPath,
        [binary, "--ignoreConfig", "--noEmit", "--skipLibCheck", input],
        { encoding: "utf8", windowsHide: true },
      );
      assert.ifError(result.error);
      assert.notEqual(result.status, 0, compiler);
      assert.match(result.stdout + result.stderr, /TS2322/, compiler);
    }
  } finally {
    assert.equal(dirname(resolve(directory)), resolve(tmpdir()));
    rmSync(directory, { recursive: true, force: true });
  }
});
