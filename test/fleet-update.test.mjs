// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { join } from "node:path";
import {
  ISSUER,
  identityPattern,
  REPOSITORY,
  SIGNER,
  checkArchiveListing,
  checkStatement,
  checksumFor,
  compareVersions,
  currentTarget,
  newerReleases,
  lock,
  reconcile,
  managedRelease,
  releaseName,
  adopt,
  healthCheck,
  runUpdate,
  isTransient,
  snappyDecode,
  switchCurrent,
  verifyProvenance,
} from "../scripts/fleet-update.mjs";

const source = "a".repeat(40),
  digest = "b".repeat(64);
const statement = (overrides = {}) => ({
  _type: "https://in-toto.io/Statement/v1",
  subject: [{ name: "kadenco-0.1.0-alpha.26.tgz", digest: { sha256: digest } }],
  predicateType: "https://slsa.dev/provenance/v1",
  predicate: {
    buildDefinition: {
      externalParameters: {
        workflow: {
          ref: "refs/heads/main",
          repository: `https://github.com/${REPOSITORY}`,
          path: ".github/workflows/release.yml",
        },
      },
      internalParameters: { github: { runner_environment: "github-hosted" } },
      resolvedDependencies: [
        {
          uri: `git+https://github.com/${REPOSITORY}@refs/heads/main`,
          digest: { gitCommit: source },
        },
      ],
    },
  },
  ...overrides,
});
const bundle = (s) => ({
  mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
  dsseEnvelope: {
    payloadType: "application/vnd.in-toto+json",
    payload: Buffer.from(JSON.stringify(s)).toString("base64"),
    signatures: [],
  },
});

test("SemVer precedence orders alpha numbers numerically and releases after prereleases", () => {
  assert.equal(compareVersions("0.1.0-alpha.10", "0.1.0-alpha.9"), 1);
  assert.equal(compareVersions("0.1.0-alpha.25", "0.1.0-beta.1"), -1);
  assert.equal(compareVersions("0.1.0", "0.1.0-rc.1"), 1);
  assert.equal(compareVersions("0.1.0-rc.1", "0.1.0"), -1);
  assert.equal(compareVersions("0.2.0", "0.1.9"), 1);
  assert.equal(compareVersions("1.0.0", "1.0.0"), 0);
  assert.throws(() => compareVersions("v1.0.0", "1.0.0"), /update_version_invalid/);
});

test("candidates are every published release newer than the installed one, newest first", () => {
  const releases = [
    { tag_name: "v0.1.0-alpha.26" },
    { tag_name: "v0.1.0-alpha.28", draft: true },
    { tag_name: "v0.1.0-alpha.9" },
    { tag_name: "not-a-version" },
    { tag_name: "v0.1.0-alpha.27" },
    { tag_name: "v0.1.0-alpha.25" },
  ];
  assert.deepEqual(
    newerReleases(releases, "0.1.0-alpha.25").map((c) => c.version),
    ["0.1.0-alpha.27", "0.1.0-alpha.26"],
  );
  assert.deepEqual(newerReleases(releases, "0.1.0-alpha.27"), []);
  assert.deepEqual(newerReleases(releases, "0.1.0-beta.1"), []);
});

test("checksum lookup requires exactly one well-formed line for the asset", () => {
  const sums = `${digest}  kadenco-0.1.0-alpha.26.tgz\n${"c".repeat(64)}  BUILD.json\n`;
  assert.equal(checksumFor(sums, "kadenco-0.1.0-alpha.26.tgz"), digest);
  assert.throws(() => checksumFor(sums, "missing.tgz"), /update_checksum_missing/);
  assert.throws(
    () => checksumFor(sums + `${digest}  BUILD.json\n`, "BUILD.json"),
    /update_checksums_invalid/,
  );
  assert.throws(() => checksumFor("garbage line\n", "x"), /update_checksums_invalid/);
});

test("provenance statement must name this package, workflow on main, hosted runner and source", () => {
  checkStatement(statement(), { digest, source });
  assert.throws(
    () => checkStatement(statement(), { digest: "d".repeat(64), source }),
    /update_provenance_subject/,
  );
  assert.throws(
    () => checkStatement(statement(), { digest, source: "e".repeat(40) }),
    /update_provenance_source/,
  );
  const s = statement();
  s.predicate.buildDefinition.externalParameters.workflow.ref = "refs/heads/feature";
  assert.throws(() => checkStatement(s, { digest, source }), /update_provenance_workflow/);
  const forked = statement();
  forked.predicate.buildDefinition.externalParameters.workflow.repository =
    "https://github.com/someone/kadenco";
  assert.throws(() => checkStatement(forked, { digest, source }), /update_provenance_workflow/);
  const selfHosted = statement();
  selfHosted.predicate.buildDefinition.internalParameters.github.runner_environment = "self-hosted";
  assert.throws(() => checkStatement(selfHosted, { digest, source }), /update_provenance_runner/);
  assert.throws(
    () =>
      checkStatement(statement({ predicateType: "https://in-toto.io/attestation/release/v0.2" }), {
        digest,
        source,
      }),
    /update_provenance_type/,
  );
});

test("an update needs one bundle whose exact signer, signature and statement all verify", async () => {
  const signerOf =
    (san, issuer = ISSUER) =>
    async () => ({ identity: { subjectAlternativeName: san, extensions: { issuer } } });
  const verify = signerOf(SIGNER);
  assert.equal(await verifyProvenance([bundle(statement())], { digest, source, verify }), true);
  // The pattern handed to sigstore-js is exact: no prefix or wildcard match.
  const pattern = new RegExp(identityPattern(SIGNER));
  assert.ok(pattern.test(SIGNER));
  assert.ok(!pattern.test(SIGNER + "-evil"));
  assert.ok(!pattern.test(SIGNER.replace("release.yml", "releaseXyml")));
  // A workflow on another branch, a look-alike or another issuer is refused,
  // whatever its statement claims.
  for (const v of [
    signerOf(SIGNER + "-evil"),
    signerOf(SIGNER.replace("release.yml", "releaseXyml")),
    signerOf(SIGNER, "https://example.invalid"),
  ])
    await assert.rejects(
      verifyProvenance([bundle(statement())], { digest, source, verify: v }),
      /update_provenance_unverified/,
    );
  // A valid signature over a statement for other bytes is refused.
  await assert.rejects(
    verifyProvenance([bundle(statement())], { digest: "f".repeat(64), source, verify }),
    /update_provenance_unverified/,
  );
  // A failing signature is refused even when the statement matches.
  const reject = async () => {
    throw Error("bad signature");
  };
  await assert.rejects(
    verifyProvenance([bundle(statement())], { digest, source, verify: reject }),
    /update_provenance_unverified/,
  );
  await assert.rejects(
    verifyProvenance([], { digest, source, verify }),
    /update_provenance_unverified/,
  );
  // Other attestation types are skipped, not fatal.
  const other = bundle(statement({ predicateType: "https://in-toto.io/attestation/release/v0.2" }));
  assert.equal(
    await verifyProvenance([other, bundle(statement())], { digest, source, verify }),
    true,
  );
  assert.equal(isTransient(Error("update_trust_root_unavailable")), true);
});
test("snappy decoding handles literals and back-references and refuses corrupt input", () => {
  assert.equal(
    snappyDecode(Buffer.from([0x09, 0x08, 0x61, 0x62, 0x63, 0x09, 0x03])).toString(),
    "abcabcabc",
  );
  const long = Buffer.alloc(100, 0x78);
  assert.equal(
    snappyDecode(Buffer.concat([Buffer.from([100, 0xf0, 99]), long])).toString(),
    "x".repeat(100),
  );
  // Two-byte offset copy: "ab" then copy 4 bytes from offset 2.
  assert.equal(
    snappyDecode(Buffer.from([0x06, 0x04, 0x61, 0x62, 0x0e, 0x02, 0x00])).toString(),
    "ababab",
  );
  assert.throws(
    () => snappyDecode(Buffer.from([0x09, 0x08, 0x61, 0x62, 0x63, 0x09, 0x09])),
    /update_bundle_encoding/,
  );
  assert.throws(() => snappyDecode(Buffer.from([0x05, 0x08, 0x61])), /update_bundle_encoding/);
  assert.throws(
    () => snappyDecode(Buffer.from([0xff, 0xff, 0xff, 0xff, 0x0f])),
    /update_bundle_encoding/,
  );
});

test("archives must be plain files and directories under package/", () => {
  checkArchiveListing(
    ["package/package.json", "package/scripts/caller.mjs"],
    ["-rw-r--r-- 0/0 1 x", "-rw-r--r-- 0/0 2 y"],
  );
  assert.throws(() => checkArchiveListing([], []), /update_archive_unsafe/);
  assert.throws(() => checkArchiveListing(["other/x"], ["-rw-r--r--"]), /update_archive_unsafe/);
  assert.throws(
    () => checkArchiveListing(["package/../x"], ["-rw-r--r--"]),
    /update_archive_unsafe/,
  );
  assert.throws(
    () => checkArchiveListing(["package/link"], ["lrwxrwxrwx"]),
    /update_archive_unsafe/,
  );
  assert.throws(
    () => checkArchiveListing(["package/hard"], ["hrw-r--r--"]),
    /update_archive_unsafe/,
  );
});

test("current switches between releases under base and refuses anything else", () => {
  const base = mkdtempSync(join(tmpdir(), "kadenco-update-"));
  try {
    for (const n of ["kadenco-a", "kadenco-b"])
      mkdirSync(join(base, "releases", n), { recursive: true });
    switchCurrent(base, join(base, "releases", "kadenco-a"));
    assert.equal(currentTarget(base), join(base, "releases", "kadenco-a"));
    switchCurrent(base, join(base, "releases", "kadenco-b"));
    assert.equal(currentTarget(base), join(base, "releases", "kadenco-b"));
    assert.throws(() => switchCurrent(base, base), /update_release_outside_base/);
    assert.throws(
      () => switchCurrent(base, join(base, "elsewhere")),
      /update_release_outside_base/,
    );
    rmSync(join(base, "current"));
    mkdirSync(join(base, "current"));
    writeFileSync(join(base, "current", "x"), "");
    assert.throws(
      () => switchCurrent(base, join(base, "releases", "kadenco-a")),
      /update_current_not_link/,
    );
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

// --------------------------------------------------------- state machine --
const base = () => mkdtempSync(join(tmpdir(), "kadenco-update-"));
function fakeRelease(root, version, d = "1".repeat(64), { marker = true } = {}) {
  const name = releaseName(version, d),
    dir = join(root, "releases", name);
  mkdirSync(join(dir, "scripts"), { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "kadenco", version }));
  writeFileSync(join(dir, "BUILD.json"), JSON.stringify({ version, source }));
  if (marker)
    writeFileSync(join(dir, ".fleet-update.json"), JSON.stringify({ version, source, digest: d }));
  return { name, dir, version, source, digest: d };
}
const stateOf = (root) => JSON.parse(readFileSync(join(root, "update-state.json"), "utf8"));
const record = (r) => ({ name: r.name, version: r.version, source: r.source, digest: r.digest });

test("only directories whose marker binds name, version, source and digest are managed", () => {
  const root = base();
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "2".repeat(64));
    assert.equal(managedRelease(root, a.name).digest, "2".repeat(64));
    const b = fakeRelease(root, "0.1.0-alpha.27", "3".repeat(64), { marker: false });
    assert.equal(managedRelease(root, b.name), null);
    // A marker for other bytes does not adopt the directory.
    writeFileSync(
      join(b.dir, ".fleet-update.json"),
      JSON.stringify({ version: b.version, source, digest: "4".repeat(64) }),
    );
    assert.equal(managedRelease(root, b.name), null);
    assert.equal(managedRelease(root, "../escape"), null);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reconcile adopts a switch that crashed before saving state and restores a missing link", () => {
  const root = base();
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "5".repeat(64)),
      b = fakeRelease(root, "0.1.0-alpha.27", "6".repeat(64));
    switchCurrent(root, b.dir);
    const state = reconcile(root, { current: record(a) });
    assert.equal(state.current.name, b.name);
    assert.equal(state.previous.name, a.name);
    rmSync(join(root, "current"));
    reconcile(root, state);
    assert.equal(currentTarget(root), b.dir);
    assert.throws(() => reconcile(base(), {}), /update_not_configured/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reconcile completes an interrupted Windows-style switch from current.next", () => {
  const root = base();
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "7".repeat(64)),
      b = fakeRelease(root, "0.1.0-alpha.27", "8".repeat(64));
    switchCurrent(root, a.dir);
    // Interrupted after creating current.next and removing current.
    symlinkSync(
      b.dir,
      join(root, "current.next"),
      process.platform === "win32" ? "junction" : "dir",
    );
    rmSync(join(root, "current"));
    const state = reconcile(root, { current: record(a) });
    assert.equal(currentTarget(root), b.dir);
    assert.equal(state.current.name, b.name);
    assert.equal(existsSync(join(root, "current.next")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the lock admits one process at a time and is released when its holder exits", async () => {
  const root = base();
  try {
    const holder = spawn(
      process.execPath,
      [
        "--input-type=module",
        "-e",
        `const m = await import(${JSON.stringify(new URL("../scripts/fleet-update.mjs", import.meta.url).href)});
         await m.lock(${JSON.stringify(root)}); console.log("held"); setInterval(() => {}, 1000);`,
      ],
      { stdio: ["ignore", "pipe", "inherit"] },
    );
    await new Promise((ok) => holder.stdout.once("data", ok));
    await assert.rejects(lock(root), /update_locked/);
    holder.kill("SIGKILL");
    await new Promise((ok) => holder.once("close", ok));
    const unlock = await lock(root);
    await assert.rejects(lock(root), /update_locked/);
    // Another spelling of the same directory is the same lock.
    const alias =
      process.platform === "win32"
        ? root.replace(/^[A-Za-z]:/, (d) =>
            d === d.toUpperCase() ? d.toLowerCase() : d.toUpperCase(),
          )
        : root + "-alias";
    if (process.platform !== "win32") symlinkSync(root, alias, "dir");
    await assert.rejects(lock(alias), /update_locked/);
    if (process.platform !== "win32") rmSync(alias);
    await unlock();
    await (
      await lock(root)
    )();
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("reconcile ignores a link to a same-named directory outside releases", () => {
  const root = base(),
    outside = base();
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "c".repeat(64)),
      b = fakeRelease(root, "0.1.0-alpha.27", "d".repeat(64));
    const decoy = fakeRelease(outside, "0.1.0-alpha.27", "d".repeat(64));
    assert.equal(decoy.name, b.name);
    symlinkSync(
      decoy.dir,
      join(root, "current"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const state = reconcile(root, { current: record(a) });
    assert.equal(state.current.name, a.name);
    assert.equal(currentTarget(root), a.dir);
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});
test("adoption health-checks, switches, records state and rewrites catalogs through current", async () => {
  const root = base(),
    home = base();
  try {
    const r = fakeRelease(root, "0.1.0-alpha.26", "9".repeat(64));
    writeFileSync(
      join(r.dir, "scripts", "install-agent-tools.mjs"),
      readFileSync(new URL("../scripts/install-agent-tools.mjs", import.meta.url)),
    );
    writeFileSync(join(r.dir, "scripts", "package.json"), JSON.stringify({ type: "module" }));
    mkdirSync(join(r.dir, "node_modules"), { recursive: true });
    symlinkSync(
      join(
        new URL("..", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
        "node_modules",
        "jsonc-parser",
      ),
      join(r.dir, "node_modules", "jsonc-parser"),
      process.platform === "win32" ? "junction" : "dir",
    );
    const config = {
      schema: 1,
      host: "h1",
      launcher: "posix",
      credential: join(home, "cred.json"),
      node: process.execPath,
    };
    const seen = [];
    const result = await adopt(
      root,
      config,
      managedRelease(root, r.name),
      ["--opencode-major", "2"],
      {
        health: async (_launch, host) => (seen.push(host), { host }),
        home,
        schedule: () => ({ timer: "stub" }),
      },
    );
    assert.deepEqual(seen, ["h1"]);
    assert.equal(result.schedule.timer, "stub");
    assert.equal(currentTarget(root), r.dir);
    assert.equal(stateOf(root).current.digest, "9".repeat(64));
    assert.equal(existsSync(join(root, "fleet-update-entry.mjs")), true);
    const claude = JSON.parse(readFileSync(join(home, ".claude.json"), "utf8")).mcpServers
      .ask_eddie;
    assert.equal(claude.args[0], join(root, "current", "scripts", "invoke-eddie-posix.mjs"));
  } finally {
    rmSync(root, { recursive: true, force: true });
    rmSync(home, { recursive: true, force: true });
  }
});

test("health check refuses a binding for another host and waits for the caller to exit", async () => {
  const fake = `process.stdin.setEncoding("utf8");let b="";process.stdin.on("data",d=>{b+=d;let i;while((i=b.indexOf("\\n"))>=0){const m=JSON.parse(b.slice(0,i));b=b.slice(i+1);if(m.id===undefined)continue;let result={};if(m.method==="tools/list")result={tools:${JSON.stringify(
    [
      "ask_eddie",
      "get_eddie_reply",
      "acknowledge_eddie_reply",
      "acknowledge_thread_delivery",
      "get_eddie_conversation",
      "get_eddie_capabilities",
    ].map((name) => ({ name })),
  )}};if(m.method==="tools/call")result={content:[{type:"text",text:JSON.stringify({host_caller:true,host:"other",delivery_acknowledgement:{available:true}})}]};process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:m.id,result})+"\\n");}});`;
  await assert.rejects(
    healthCheck({ command: process.execPath, args: ["-e", fake] }, "mine", 20000),
    /update_health_host/,
  );
  const ok = await healthCheck({ command: process.execPath, args: ["-e", fake] }, "other", 20000);
  assert.equal(ok.host, "other");
});

test("a release with broken publication is skipped and remembered, not retried every run", async () => {
  const root = base(),
    realFetch = globalThis.fetch;
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "a".repeat(64));
    switchCurrent(root, a.dir);
    writeFileSync(join(root, "update-state.json"), JSON.stringify({ current: record(a) }));
    writeFileSync(
      join(root, "update.json"),
      JSON.stringify({
        schema: 1,
        host: "h",
        launcher: "posix",
        credential: join(root, "c"),
        node: process.execPath,
      }),
    );
    const dl = `https://github.com/${REPOSITORY}/releases/download/`;
    const assets = (v) =>
      [`kadenco-${v}.tgz`, "SHA256SUMS", "BUILD.json"].map((name) => ({
        name,
        browser_download_url: `${dl}v${v}/${name}`,
      }));
    const releases = [
      { tag_name: "v0.1.0-alpha.29", assets: assets("0.1.0-alpha.29") },
      { tag_name: "v0.1.0-alpha.28", assets: [] },
      { tag_name: "v0.1.0-alpha.27", assets: assets("0.1.0-alpha.27") },
    ];
    const files = {
      "v0.1.0-alpha.29/SHA256SUMS": `${"0".repeat(64)}  kadenco-0.1.0-alpha.29.tgz\n`,
      "v0.1.0-alpha.29/BUILD.json": "{ not json",
      "v0.1.0-alpha.27/SHA256SUMS": `${"0".repeat(64)}  kadenco-0.1.0-alpha.27.tgz\n`,
      "v0.1.0-alpha.27/BUILD.json": JSON.stringify({ version: "0.1.0-alpha.27", source }),
      "v0.1.0-alpha.27/kadenco-0.1.0-alpha.27.tgz": "not the listed bytes",
    };
    let listStatus = 200;
    globalThis.fetch = async (url) => {
      const u = String(url),
        list = u.includes("/releases?");
      const r = new Response(list ? JSON.stringify(releases) : files[u.slice(dl.length)], {
        status: list ? listStatus : 200,
      });
      Object.defineProperty(r, "url", { value: u });
      return r;
    };
    const first = await runUpdate(root);
    assert.equal(first.result, "current");
    // A malformed release, one with no assets and one with wrong bytes are each
    // skipped; none of them stops the run.
    assert.deepEqual(
      first.skipped.map((s) => s.version),
      ["0.1.0-alpha.29", "0.1.0-alpha.28", "0.1.0-alpha.27"],
    );
    assert.match(first.skipped[2].reason, /update_checksum_mismatch/);
    const rejected = stateOf(root).rejected;
    assert.deepEqual(Object.keys(rejected).sort(), [
      "v0.1.0-alpha.27",
      "v0.1.0-alpha.28",
      "v0.1.0-alpha.29",
    ]);
    assert.ok(Date.parse(rejected["v0.1.0-alpha.27"].retry_after) > Date.now() + 23 * 3600e3);
    assert.deepEqual((await runUpdate(root)).skipped, []);
    // An unavailable GitHub API ends the run without condemning any release.
    listStatus = 503;
    await assert.rejects(runUpdate(root), /update_fetch_status:503/);
    assert.equal(isTransient(Error("update_fetch_status:503")), true);
    assert.equal(isTransient(Error("update_checksum_mismatch")), false);
    // A hold is honored after reconcile, and reported with the current version.
    listStatus = 200;
    writeFileSync(join(root, "update.hold"), "test\n");
    assert.deepEqual(await runUpdate(root), { result: "held", version: "0.1.0-alpha.26" });
  } finally {
    globalThis.fetch = realFetch;
    rmSync(root, { recursive: true, force: true });
  }
});

test("health cleanup reaches the caller's descendants and fails when one escapes", async () => {
  const tools = [
    "ask_eddie",
    "get_eddie_reply",
    "acknowledge_eddie_reply",
    "acknowledge_thread_delivery",
    "get_eddie_conversation",
    "get_eddie_capabilities",
  ].map((name) => ({ name }));
  // A caller that answers correctly, ignores end of input, and starts a
  // descendant sharing its output (escaping into a new session if asked).
  const fake = (escape) => `
    const { spawn } = require("node:child_process");
    spawn(process.execPath, ["-e", "setTimeout(() => {}, 4000)"], { stdio: ["ignore", "inherit", "ignore"], detached: ${escape} });
    setInterval(() => {}, 1000);
    process.stdin.setEncoding("utf8"); let b = "";
    process.stdin.on("data", (d) => { b += d; let i; while ((i = b.indexOf("\\n")) >= 0) { const m = JSON.parse(b.slice(0, i)); b = b.slice(i + 1);
      if (m.id === undefined) continue; let result = {};
      if (m.method === "tools/list") result = { tools: ${JSON.stringify(tools)} };
      if (m.method === "tools/call") result = { content: [{ type: "text", text: JSON.stringify({ host_caller: true, host: "h", delivery_acknowledgement: { available: true } }) }] };
      process.stdout.write(JSON.stringify({ jsonrpc: "2.0", id: m.id, result }) + "\\n"); } });`;
  const fast = { graceMs: 200, killWaitMs: 1500 };
  const ok = await healthCheck(
    { command: process.execPath, args: ["-e", fake(false)] },
    "h",
    20000,
    fast,
  );
  assert.equal(ok.host, "h");
  if (process.platform !== "win32")
    await assert.rejects(
      healthCheck({ command: process.execPath, args: ["-e", fake(true)] }, "h", 20000, fast),
      /update_health_cleanup/,
    );
});

test("fallback stops at the first good candidate and an unconfirmed cleanup ends the run", async () => {
  const root = base(),
    realFetch = globalThis.fetch;
  try {
    const a = fakeRelease(root, "0.1.0-alpha.26", "e".repeat(64));
    switchCurrent(root, a.dir);
    writeFileSync(join(root, "update-state.json"), JSON.stringify({ current: record(a) }));
    writeFileSync(
      join(root, "update.json"),
      JSON.stringify({
        schema: 1,
        host: "h",
        launcher: "posix",
        credential: join(root, "c"),
        node: process.execPath,
      }),
    );
    const releases = ["v0.1.0-alpha.28", "v0.1.0-alpha.27"].map((tag_name) => ({
      tag_name,
      assets: [],
    }));
    globalThis.fetch = async (url) => {
      const r = new Response(JSON.stringify(releases), { status: 200 });
      Object.defineProperty(r, "url", { value: String(url) });
      return r;
    };
    const built = {
      "0.1.0-alpha.28": fakeRelease(root, "0.1.0-alpha.28", "f".repeat(64)),
      "0.1.0-alpha.27": fakeRelease(root, "0.1.0-alpha.27", "0".repeat(64)),
    };
    const installs = [];
    const install = async (_base, _config, c) => (
      installs.push(c.version),
      managedRelease(root, built[c.version].name)
    );
    // A caller that may still be running stops the run: no older candidate starts.
    await assert.rejects(
      runUpdate(root, {
        install,
        health: async () => {
          throw Error("update_health_cleanup");
        },
      }),
      /update_health_cleanup/,
    );
    assert.deepEqual(installs, ["0.1.0-alpha.28"]);
    assert.equal(stateOf(root).rejected?.["v0.1.0-alpha.28"], undefined);
    // The newest good candidate is activated and nothing older is touched.
    installs.length = 0;
    const done = await runUpdate(root, { install, health: async (_l, host) => ({ host }) });
    assert.equal(done.result, "updated");
    assert.equal(done.to, "0.1.0-alpha.28");
    assert.deepEqual(installs, ["0.1.0-alpha.28"]);
    assert.equal(currentTarget(root), built["0.1.0-alpha.28"].dir);
    assert.equal(stateOf(root).previous.name, a.name);
  } finally {
    globalThis.fetch = realFetch;
    rmSync(root, { recursive: true, force: true });
  }
});
