// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  readFileSync,
  lstatSync,
  realpathSync,
  openSync,
  fstatSync,
  closeSync,
  constants,
} from "node:fs";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, isAbsolute, relative, sep } from "node:path";
import { connect } from "node:net";
import { localArchiveReference } from "./local-archive.ts";
import { signRetirement, type RetirementEvidence } from "./activation.ts";
const run = promisify(execFile),
  hash = (s: string | Buffer) => createHash("sha256").update(s).digest("hex");
export const retirementTombstone = (id: string) => {
  if (!/^[a-zA-Z0-9-]{1,100}$/.test(id)) throw Error("invalid_retirement_identity");
  return "throw 'KADENCO_BOOTSTRAP_RETIRED:" + id + "'\r\n";
};
export type ManagedRetirementInput = {
  root: string;
  entry: string;
  credentials: string;
  releaseEntry: string;
  archivePath: string;
  archiveSha256: string;
  fenceId: string;
  ports: number[];
};
function contained(root: string, path: string) {
  const r = relative(root, path);
  return r !== "" && !isAbsolute(r) && r !== ".." && !r.startsWith(".." + sep);
}
const psLiteral = (s: string) => "'" + s.replaceAll("'", "''") + "'";
async function closed(port: number) {
  return new Promise<boolean>((resolve) => {
    const socket = connect({ host: "127.0.0.1", port });
    let done = false;
    const finish = (v: boolean) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(v);
    };
    socket.once("connect", () => finish(false));
    socket.once("error", (e) => finish((e as NodeJS.ErrnoException).code === "ECONNREFUSED"));
    socket.setTimeout(1000, () => finish(false));
  });
}
/** Verifies an ALREADY enforced managed Windows bootstrap retirement. It does
 * not stop tasks, move credentials or change ACLs. Those are explicit operator
 * cutover actions. A privileged OS owner can deliberately undo them; no proof
 * or DO epoch can defend against that owner reintroducing the old key/code. */
export async function verifyManagedRetirement(input: ManagedRetirementInput) {
  if (process.platform !== "win32") throw Error("managed_retirement_platform_unqualified");
  const root = realpathSync(input.root);
  if (
    ![input.entry, input.credentials, input.releaseEntry, input.archivePath].every(
      (p) => isAbsolute(p) && contained(root, p),
    )
  )
    throw Error("retirement_path_outside_source");
  for (const p of [input.entry, input.credentials, input.releaseEntry, input.archivePath]) {
    const parent = realpathSync(dirname(p));
    if (parent !== root && !contained(root, parent)) throw Error("retirement_path_outside_source");
  }
  if (
    !input.ports.length ||
    input.ports.length > 2 ||
    input.ports.some((p) => !Number.isSafeInteger(p) || p < 1 || p > 65535)
  )
    throw Error("retirement_ports_invalid");
  const check = () => {
    const fd = openSync(input.entry, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
    try {
      const entry = fstatSync(fd);
      if (
        !entry.isFile() ||
        entry.nlink !== 1 ||
        readFileSync(fd, "utf8") !== retirementTombstone(input.fenceId)
      )
        throw Error("legacy_bootstrap_not_retired");
      const path = lstatSync(input.entry);
      if (path.isSymbolicLink() || path.dev !== entry.dev || path.ino !== entry.ino)
        throw Error("legacy_bootstrap_not_retired");
    } finally {
      closeSync(fd);
    }
    try {
      lstatSync(input.credentials);
      throw Error("legacy_credentials_still_present");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    if (localArchiveReference(input.archivePath).archive_sha256 !== input.archiveSha256)
      throw Error("historical_archive_changed");
  };
  check();
  const markers = [input.entry, input.releaseEntry].map((p) => p.replaceAll("/", "\\"));
  const command =
    "$ErrorActionPreference='Stop'; $matches=@(Get-CimInstance Win32_Process | Where-Object {$_.ProcessId -ne $PID -and $_.CommandLine -and (" +
    markers
      .map(
        (p) =>
          "$_.CommandLine.Replace('/','\\').IndexOf(" +
          psLiteral(p) +
          ",[StringComparison]::OrdinalIgnoreCase) -ge 0",
      )
      .join(" -or ") +
    ")}); @($matches | ForEach-Object {$_.ProcessId}) | ConvertTo-Json -Compress";
  let stdout: string;
  try {
    ({ stdout } = await run(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", command],
      { windowsHide: true, timeout: 10000, maxBuffer: 65536 },
    ));
  } catch {
    throw Error("legacy_process_probe_failed");
  }
  const pids = stdout.trim() ? JSON.parse(stdout) : [];
  if ((Array.isArray(pids) ? pids : [pids]).length) throw Error("legacy_process_still_running");
  if (!(await Promise.all(input.ports.map(closed))).every(Boolean))
    throw Error("legacy_ingress_still_open");
  let refused = false;
  // Hold a Windows deny-write/deny-delete handle from the final content check
  // through execution. A separate stat/read followed by -File would reopen an
  // unpinned path and could execute replacement bytes instead of the tombstone.
  const revival =
    "$ErrorActionPreference='Stop'; $f=[IO.File]::Open(" +
    psLiteral(input.entry) +
    ", [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read); " +
    "try {$r=New-Object IO.StreamReader($f); $s=$r.ReadToEnd(); if($s -cne " +
    psLiteral(retirementTombstone(input.fenceId)) +
    "){throw 'retirement_content_changed'}; & " +
    psLiteral(input.entry) +
    "} finally {$f.Dispose()}";
  try {
    await run(
      "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", revival],
      { windowsHide: true, timeout: 10000, maxBuffer: 8192 },
    );
  } catch (e) {
    const r = e as { code?: number; stderr?: string };
    refused =
      r.code === 1 && String(r.stderr).includes("KADENCO_BOOTSTRAP_RETIRED:" + input.fenceId);
  }
  if (!refused) throw Error("legacy_revival_not_denied");
  check();
  if (!(await Promise.all(input.ports.map(closed))).every(Boolean))
    throw Error("legacy_ingress_still_open");
  return {
    archive_sha256: input.archiveSha256,
    source_release_sha256: hash(readFileSync(input.releaseEntry)),
    bootstrap_sha256: hash(retirementTombstone(input.fenceId)),
    credential_path_sha256: hash(input.credentials),
    processes: 0 as const,
    ingress_closed: true as const,
    revival_denied: true as const,
  };
}
/** One-shot activation with explicit same-ID receipt recovery after uncertainty.
 * Only the operator's temporary migration credential signs these observations;
 * it is never registered as an Eddie caller or passed to a native child. */
export async function activateManagedSource(input: {
  call: (op: string, p: object) => Promise<Record<string, unknown>>;
  token: string;
  actor: string;
  hosts: string[];
  id: string;
  epoch: number;
  importId: string;
  digest: string;
  source: ManagedRetirementInput;
}) {
  const previous = await input.call("activation_receipt", { activation_id: input.id });
  if (previous.committed === true) {
    if (
      previous.digest !== input.digest ||
      previous.import_id !== input.importId ||
      previous.previous_epoch !== input.epoch
    )
      throw Error("activation_receipt_conflict");
    return previous;
  }
  if (previous.committed !== false) throw Error("activation_receipt_unavailable");
  const c = await input.call("activation_challenge", {
    activation_id: input.id,
    expected_epoch: input.epoch,
    import_id: input.importId,
    digest: input.digest,
  });
  if (
    typeof c.nonce !== "string" ||
    c.epoch !== input.epoch ||
    c.import_id !== input.importId ||
    c.digest !== input.digest ||
    typeof c.migration_id !== "string" ||
    typeof c.expires !== "number"
  )
    throw Error("activation_challenge_denied");
  const physical = await verifyManagedRetirement(input.source),
    now = Date.now();
  const routes = [...input.hosts.map((h) => "native:" + h), "callback", "restart"];
  const proof: RetirementEvidence = {
    ...physical,
    kind: "managed_bootstrap_retirement",
    challenge: c.nonce,
    epoch: input.epoch,
    import_id: input.importId,
    migration_id: c.migration_id,
    snapshot: input.digest,
    issued: now,
    expires: Math.min(now + 60000, c.expires),
    routes,
    denied: routes,
    issuer: input.actor,
  };
  const result = await input.call("activate", {
    activation_id: input.id,
    expected_epoch: input.epoch,
    import_id: input.importId,
    digest: input.digest,
    retirement: signRetirement(proof, input.token),
  });
  if (
    result.activated !== true ||
    result.epoch !== input.epoch + 1 ||
    result.digest !== input.digest
  )
    throw Error("activation_outcome_unverified");
  return result;
}
