// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  readdirSync,
  readFileSync,
  writeFileSync,
  openSync,
  fstatSync,
  closeSync,
  constants,
} from "node:fs";
import { join, relative } from "node:path";
import { createHash } from "node:crypto";
const manifestName = "WORKER-BUILD.json";
function files(root, directory = root, result = {}) {
  for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name),
  )) {
    const path = join(directory, entry.name),
      name = relative(root, path).replaceAll("\\", "/");
    if (name === manifestName) continue;
    if (entry.isDirectory()) {
      files(root, path, result);
      continue;
    }
    if (!entry.isFile()) throw Error("worker_output_alias_refused");
    const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const before = fstatSync(fd);
      if (!before.isFile()) throw Error("worker_output_alias_refused");
      result[name] = createHash("sha256").update(readFileSync(fd)).digest("hex");
      const after = fstatSync(fd);
      if (
        before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs ||
        before.ino !== after.ino
      )
        throw Error("worker_output_changed");
    } finally {
      closeSync(fd);
    }
  }
  return result;
}
export function recordWorkerBuild(root, identity) {
  if (
    !/^[a-f0-9]{40}$/.test(identity.source) ||
    typeof identity.version !== "string" ||
    typeof identity.dirty !== "boolean"
  )
    throw Error("worker_build_identity_required");
  const manifest = { schema: 1, ...identity, files: files(root) };
  if (!manifest.files["v0/workers/default/worker.config.json"])
    throw Error("production_worker_artifact_required");
  writeFileSync(join(root, manifestName), JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}
export function verifyWorkerBuild(root, identity) {
  const manifest = JSON.parse(readFileSync(join(root, manifestName), "utf8"));
  if (
    manifest.schema !== 1 ||
    manifest.source !== identity.source ||
    manifest.version !== identity.version ||
    manifest.dirty !== false
  )
    throw Error("worker_release_provenance_mismatch");
  if (JSON.stringify(files(root)) !== JSON.stringify(manifest.files))
    throw Error("worker_release_bytes_mismatch");
  const config = JSON.parse(
    readFileSync(join(root, "v0/workers/default/worker.config.json"), "utf8"),
  );
  if (config.name !== "kadenco-control-plane" || config.previewUrls !== false)
    throw Error("production_worker_artifact_required");
  return manifest;
}
