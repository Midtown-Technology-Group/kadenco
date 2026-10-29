// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { checkRelease } from "../scripts/release-check.mjs";

test("release identity binds tag, both lock versions and exact changelog heading", () => {
  const pkg = { version: "0.1.0-alpha.3" };
  const lock = { version: pkg.version, packages: { "": { version: pkg.version } } };
  const notes = `# Changelog\n\n## ${pkg.version}\n`;
  assert.equal(checkRelease(pkg, lock, notes).prerelease, true);
  assert.throws(() => checkRelease(pkg, lock, notes, "v0.1.0-alpha.2"), /tag_version_mismatch/);
  assert.throws(
    () => checkRelease(pkg, { ...lock, version: "0.1.0" }, notes),
    /lock_version_mismatch/,
  );
  assert.throws(
    () => checkRelease(pkg, { ...lock, packages: { "": { version: "0.1.0" } } }, notes),
    /lock_version_mismatch/,
  );
  assert.throws(() => checkRelease(pkg, lock, "## 0.1.0-alpha.30"), /missing_changelog_version/);
  assert.throws(
    () => checkRelease({ version: "01.1.0" }, lock, notes),
    /unsupported_release_version/,
  );
  assert.equal(
    checkRelease(
      { version: "1.0.0" },
      { version: "1.0.0", packages: { "": { version: "1.0.0" } } },
      "## 1.0.0",
    ).prerelease,
    false,
  );
});
