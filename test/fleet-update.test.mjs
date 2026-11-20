// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ISSUER,
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
  isReleaseRejection,
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

test("an update needs one bundle whose signature and statement both verify", async () => {
  const calls = [];
  const verify = async (_bundle, options) => {
    calls.push(options);
    if (options.certificateIdentityURI !== SIGNER || options.certificateIssuer !== ISSUER)
      throw Error("identity");
  };
  assert.equal(await verifyProvenance([bundle(statement())], { digest, source, verify }), true);
  assert.deepEqual(calls[0], { certificateIdentityURI: SIGNER, certificateIssuer: ISSUER });
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

test("the lock admits one owner, retires a dead owner's lock and never removes another's", () => {
  const root = base();
  try {
    const unlock = lock(root);
    assert.throws(() => lock(root), /update_locked/);
    unlock();
    // A lock left by a process that no longer exists is retired.
    mkdirSync(join(root, "update.lock"));
    writeFileSync(
      join(root, "update.lock", "owner.json"),
      JSON.stringify({ token: "x", pid: 2 ** 30 }),
    );
    const second = lock(root);
    // If our lock was retired and re-taken by someone else, unlocking leaves theirs.
    renameSync(join(root, "update.lock"), join(root, "gone"));
    mkdirSync(join(root, "update.lock"));
    writeFileSync(
      join(root, "update.lock", "owner.json"),
      JSON.stringify({ token: "theirs", pid: process.pid }),
    );
    second();
    assert.equal(existsSync(join(root, "update.lock", "owner.json")), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
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
    const releases = [
      { tag_name: "v0.1.0-alpha.28", assets: [] },
      {
        tag_name: "v0.1.0-alpha.27",
        assets: ["kadenco-0.1.0-alpha.27.tgz", "SHA256SUMS", "BUILD.json"].map((name) => ({
          name,
          browser_download_url: dl + "v0.1.0-alpha.27/" + name,
        })),
      },
    ];
    const files = {
      SHA256SUMS: `${"0".repeat(64)}  kadenco-0.1.0-alpha.27.tgz\n`,
      "BUILD.json": JSON.stringify({ version: "0.1.0-alpha.27", source }),
      "kadenco-0.1.0-alpha.27.tgz": "not the listed bytes",
    };
    globalThis.fetch = async (url) => {
      const body = String(url).includes("/releases?")
        ? JSON.stringify(releases)
        : files[String(url).split("/").pop()];
      const r = new Response(body, { status: 200 });
      Object.defineProperty(r, "url", { value: String(url) });
      return r;
    };
    const first = await runUpdate(root);
    assert.equal(first.result, "current");
    assert.deepEqual(
      first.skipped.map((s) => s.version),
      ["0.1.0-alpha.28", "0.1.0-alpha.27"],
    );
    assert.match(first.skipped[1].reason, /update_checksum_mismatch/);
    assert.deepEqual(Object.keys(stateOf(root).rejected).sort(), [
      "v0.1.0-alpha.27",
      "v0.1.0-alpha.28",
    ]);
    assert.deepEqual((await runUpdate(root)).skipped, []);
    assert.equal(isReleaseRejection(Error("update_fetch_status:503")), false);
  } finally {
    globalThis.fetch = realFetch;
    rmSync(root, { recursive: true, force: true });
  }
});
