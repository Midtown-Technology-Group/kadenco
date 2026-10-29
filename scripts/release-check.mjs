// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

export function checkRelease(pkg, lock, changelog, tag = `v${pkg.version}`) {
  const version = pkg.version;
  if (
    !/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:alpha|beta|rc)\.(0|[1-9]\d*))?$/.test(version)
  )
    throw Error("unsupported_release_version");
  if (tag !== `v${version}`) throw Error("tag_version_mismatch");
  if (lock.version !== version || lock.packages?.[""]?.version !== version)
    throw Error("lock_version_mismatch");
  if (!changelog.split(/\r?\n/).some((line) => line === `## ${version}`))
    throw Error("missing_changelog_version");
  return { version, tag, prerelease: version.includes("-"), publication: "not_performed" };
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const root = new URL("../", import.meta.url);
  const json = (path) => JSON.parse(readFileSync(new URL(path, root), "utf8"));
  if (process.argv.length > 3) throw Error("unexpected_release_arguments");
  console.log(
    JSON.stringify(
      checkRelease(
        json("package.json"),
        json("package-lock.json"),
        readFileSync(new URL("CHANGELOG.md", root), "utf8"),
        process.argv[2],
      ),
    ),
  );
}
