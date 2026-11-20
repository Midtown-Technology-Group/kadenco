// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
  selectRelease,
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

test("selects the newest published release strictly newer than the installed one", () => {
  const releases = [
    { tag_name: "v0.1.0-alpha.27", draft: true },
    { tag_name: "v0.1.0-alpha.26" },
    { tag_name: "v0.1.0-alpha.9" },
    { tag_name: "not-a-version" },
    { tag_name: "v0.1.0-alpha.25" },
  ];
  assert.equal(selectRelease(releases, "0.1.0-alpha.25").version, "0.1.0-alpha.26");
  assert.equal(selectRelease(releases, "0.1.0-alpha.26"), null);
  assert.equal(selectRelease(releases, "0.1.0-beta.1"), null);
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
