// SPDX-License-Identifier: AGPL-3.0-or-later
import { build } from "esbuild";
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, relative, resolve } from "node:path";
const root = fileURLToPath(new URL("../../../", import.meta.url));
const directory = fileURLToPath(new URL("../", import.meta.url));
const sidecar = join(root, "dist");
const files = readdirSync(sidecar, { recursive: true })
  .filter((p) => typeof p === "string")
  .sort();
const hashes = {};
for (const path of files) {
  if (!/\.(mjs|html|css)$/.test(path)) continue;
  hashes[path.replaceAll("\\", "/")] = createHash("sha256")
    .update(readFileSync(join(sidecar, path)))
    .digest("hex");
}
if (!Object.keys(hashes).includes("sidecar.mjs")) throw Error("build_sidecar_first");
const result = await build({
  absWorkingDir: directory,
  entryPoints: ["src/edge-entry.ts"],
  outfile: "dist/edge-runtime.mjs",
  bundle: true,
  platform: "node",
  format: "esm",
  target: "node22",
  packages: "external",
  plugins: [
    {
      name: "existing-sidecar-artifact",
      setup(b) {
        b.onResolve({ filter: /^\.\.\/\.\.\/\.\.\/dist\// }, (args) => ({
          path: args.path,
          external: true,
        }));
      },
    },
  ],
  sourcemap: "external",
  sourcesContent: false,
  metafile: true,
  banner: { js: "// SPDX-License-Identifier: AGPL-3.0-or-later" },
});
// Keep the exact original sidecar modules shared, including diagnostics context
// and SDK service objects. Do not accidentally bundle a second sidecar copy.
if (
  Object.keys(result.metafile.inputs).some(
    (p) =>
      resolve(directory, p).startsWith(sidecar + "/") ||
      resolve(directory, p).startsWith(sidecar + "\\"),
  )
)
  throw Error("duplicated_sidecar_artifact");
const path = join(directory, "dist", "edge-runtime.mjs");
const manifest = {
  schema: 1,
  source: execFileSync("git", ["rev-parse", "HEAD"], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  }).trim(),
  dirty: !!execFileSync("git", ["status", "--porcelain"], {
    cwd: root,
    encoding: "utf8",
    windowsHide: true,
  }).trim(),
  package_version: JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version,
  bundle: relative(directory, path).replaceAll("\\", "/"),
  sha256: createHash("sha256").update(readFileSync(path)).digest("hex"),
  sidecar_modules: hashes,
  dependency_locks: Object.fromEntries(
    [
      "package.json",
      "package-lock.json",
      "packages/control-plane/package.json",
      "packages/control-plane/package-lock.json",
    ].map((name) => [
      name,
      createHash("sha256")
        .update(readFileSync(join(root, name)))
        .digest("hex"),
    ]),
  ),
  production_ready: false,
};
writeFileSync(join(directory, "dist", "edge-build.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log(
  JSON.stringify({
    bundle: manifest.bundle,
    sha256: manifest.sha256,
    dirty: manifest.dirty,
    production_ready: false,
  }),
);
