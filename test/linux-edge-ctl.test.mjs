// SPDX-License-Identifier: AGPL-3.0-or-later
// kadenco-edge-ctl.mjs runs as root against a directory the service account
// can write: it must never follow a planted link, act outside its transfer
// directory, or install an archive it has not vetted and verified.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  symlinkSync,
  existsSync,
  readdirSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";

const ctl = fileURLToPath(
  new URL("../packages/control-plane/operator/linux/kadenco-edge-ctl.mjs", import.meta.url),
);
const skip =
  process.platform === "linux"
    ? false
    : "the edge host and its fleet hosts are Linux (GNU stat, tar)";
const NAME = "kadenco-0.1.0-alpha.99-abcdef0";

function host() {
  const root = mkdtempSync(join(tmpdir(), "kadenco-ctl-"));
  for (const d of [
    "etc/kadenco",
    "var/lib/kadenco/eddie-t3",
    "opt/kadenco/releases",
    "root/kadenco-xfer",
    "run",
  ])
    mkdirSync(join(root, d), { recursive: true });
  const runtime = join(root, "var/lib/kadenco/eddie-t3");
  const etcDir = join(root, "etc/kadenco");
  writeFileSync(
    join(etcDir, "edge.json"),
    JSON.stringify({
      releasePath: join(root, "opt/kadenco/releases/old"),
      executorExpiresAt: 1,
      configPath: join(etcDir, "config.json"),
      supervisorConfig: join(etcDir, "central-supervisor.json"),
    }),
  );
  const etc = join(root, "etc/kadenco");
  writeFileSync(join(etc, "config.json"), '{"port":41880}');
  writeFileSync(
    join(etc, "central-supervisor.json"),
    JSON.stringify({ configPath: join(etc, "config.json"), bootstrap: { serviceExpiresAt: 1 } }),
  );
  const victim = join(root, "victim");
  writeFileSync(victim, "SECRET-CONTENT");
  return { root, runtime, etc, victim, xfer: join(root, "root/kadenco-xfer") };
}
const ctlRun = (h, ...args) => {
  const r = spawnSync(process.execPath, [ctl, ...args], {
    encoding: "utf8",
    env: { ...process.env, KADENCO_CTL_ROOT: h.root },
  });
  return {
    status: r.status,
    json: JSON.parse(r.stdout.trim().split("\n").at(-1) || "{}"),
    stdout: r.stdout,
  };
};
const transfer = (h, content) => {
  const p = join(h.xfer, "kadenco-" + randomBytes(16).toString("hex"));
  writeFileSync(p, content);
  return p;
};
/** A release archive built with Python's tarfile, so link and path members can be crafted. */
function archive(h, members) {
  const out = join(h.xfer, "kadenco-" + randomBytes(16).toString("hex"));
  const spec = JSON.stringify(members);
  execFileSync("python3", [
    "-c",
    `
import io, json, sys, tarfile
spec = json.loads(sys.argv[2])
with tarfile.open(sys.argv[1], "w:gz") as t:
    for m in spec:
        i = tarfile.TarInfo(m["name"])
        if m["type"] == "dir":
            i.type = tarfile.DIRTYPE; i.mode = 0o755; t.addfile(i)
        elif m["type"] == "link":
            i.type = tarfile.SYMTYPE; i.linkname = m["target"]; t.addfile(i)
        else:
            data = m["data"].encode(); i.size = len(data); i.mode = 0o644; t.addfile(i, io.BytesIO(data))
`,
    out,
    spec,
  ]);
  return out;
}
const good = [
  { name: NAME, type: "dir" },
  { name: `${NAME}/BUILD.json`, type: "file", data: '{"source":"x","version":"0.1.0-alpha.99"}' },
  { name: `${NAME}/dist`, type: "dir" },
  { name: `${NAME}/dist/a.mjs`, type: "file", data: "export {}" },
];
function expectedManifest(h) {
  const dir = mkdtempSync(join(h.root, "m-"));
  mkdirSync(join(dir, NAME, "dist"), { recursive: true });
  writeFileSync(join(dir, NAME, "BUILD.json"), good[1].data);
  writeFileSync(join(dir, NAME, "dist/a.mjs"), good[3].data);
  const m = ctlRun(h, "manifest", join(dir, NAME)).json.sha256;
  rmSync(dir, { recursive: true });
  return m;
}

test("get and install-file never follow a planted link", { skip }, () => {
  const h = host();
  try {
    rmSync(join(h.etc, "config.json"));
    symlinkSync(h.victim, join(h.etc, "config.json"));
    const got = ctlRun(h, "get", "config");
    assert.equal(got.status, 1);
    assert.doesNotMatch(got.stdout, /SECRET/);
    const r = ctlRun(h, "install-file", transfer(h, '{"port":1}'), "config");
    assert.equal(r.status, 1);
    assert.equal(readFileSync(h.victim, "utf8"), "SECRET-CONTENT");
    const backups = join(h.root, "var/backups/kadenco");
    assert.ok(
      !existsSync(backups) || readdirSync(backups).length === 0,
      "no backup of the link target",
    );
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test(
  "install-file replaces the file, keeps a root-only backup and consumes the transfer",
  { skip },
  () => {
    const h = host();
    try {
      const src = transfer(h, '{"port":41999}');
      const r = ctlRun(h, "install-file", src, "config");
      assert.equal(r.status, 0, r.stdout);
      assert.equal(readFileSync(join(h.etc, "config.json"), "utf8"), '{"port":41999}');
      assert.ok(r.json.backup.startsWith(join(h.root, "var/backups/kadenco") + "/"));
      assert.equal(readFileSync(r.json.backup, "utf8"), '{"port":41880}');
      // Only the published backup remains; its temporary file is gone.
      assert.deepEqual(readdirSync(join(h.root, "var/backups/kadenco")), [
        r.json.backup.split("/").at(-1),
      ]);
      assert.equal(existsSync(src), false);
      assert.equal(
        readdirSync(h.etc).filter((n) => n.startsWith(".")).length,
        0,
        "no temporary file left",
      );
    } finally {
      rmSync(h.root, { recursive: true, force: true });
    }
  },
);

test("operator files live outside the service-writable runtime directory", { skip }, () => {
  const h = host();
  try {
    // The service account owns the runtime directory's parent and could swap
    // the directory for a link to a tree it controls. Root must not follow it.
    const planted = join(h.root, "planted");
    mkdirSync(planted);
    writeFileSync(join(planted, "config.json"), "PLANTED");
    rmSync(h.runtime, { recursive: true });
    symlinkSync(planted, h.runtime);
    assert.equal(ctlRun(h, "get", "config").stdout, '{"port":41880}');
    const r = ctlRun(h, "install-file", transfer(h, '{"port":41998}'), "config");
    assert.equal(r.status, 0, r.stdout);
    assert.equal(readFileSync(join(h.etc, "config.json"), "utf8"), '{"port":41998}');
    assert.deepEqual(readdirSync(planted), ["config.json"]);
    assert.equal(readFileSync(join(planted, "config.json"), "utf8"), "PLANTED");
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test("a planted FIFO fails fast instead of blocking root", { skip }, () => {
  const h = host();
  try {
    rmSync(join(h.etc, "config.json"));
    execFileSync("mkfifo", [join(h.etc, "config.json")]);
    const started = Date.now();
    const r = spawnSync(process.execPath, [ctl, "get", "config"], {
      encoding: "utf8",
      timeout: 10000,
      env: { ...process.env, KADENCO_CTL_ROOT: h.root },
    });
    assert.equal(r.signal, null, "ctl blocked on the FIFO");
    assert.equal(r.status, 1);
    assert.ok(Date.now() - started < 10000);
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test("install-file refuses when the edge would load a different policy file", { skip }, () => {
  const h = host();
  try {
    const supervisor = join(h.etc, "central-supervisor.json");
    writeFileSync(
      supervisor,
      JSON.stringify({
        configPath: join(h.runtime, "config.json"),
        bootstrap: { serviceExpiresAt: 1 },
      }),
    );
    const r = ctlRun(h, "install-file", transfer(h, '{"port":41997}'), "config");
    assert.equal(r.status, 1);
    assert.equal(r.json.reason, "policy_path_mismatch");
    assert.equal(readFileSync(join(h.etc, "config.json"), "utf8"), '{"port":41880}');
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test(
  "install-file supervisor validates the incoming file and can repair a mismatch",
  { skip },
  () => {
    const h = host();
    const supervisor = join(h.etc, "central-supervisor.json");
    const good = JSON.stringify({
      configPath: join(h.etc, "config.json"),
      bootstrap: { serviceExpiresAt: 2 },
    });
    const stale = JSON.stringify({
      configPath: join(h.runtime, "config.json"),
      bootstrap: { serviceExpiresAt: 2 },
    });
    try {
      const before = readFileSync(supervisor, "utf8");
      const refused = ctlRun(h, "install-file", transfer(h, stale), "supervisor");
      assert.equal(refused.status, 1);
      assert.equal(refused.json.reason, "policy_path_mismatch");
      assert.equal(
        readFileSync(supervisor, "utf8"),
        before,
        "a stale supervisor file must not land",
      );

      // An installed mismatch is repaired by installing a correct supervisor file.
      writeFileSync(supervisor, stale);
      const repaired = ctlRun(h, "install-file", transfer(h, good), "supervisor");
      assert.equal(repaired.status, 0, repaired.stdout);
      assert.equal(readFileSync(supervisor, "utf8"), good);
    } finally {
      rmSync(h.root, { recursive: true, force: true });
    }
  },
);

test("transfer paths outside the transfer directory are refused and left alone", { skip }, () => {
  const h = host();
  try {
    for (const p of [
      h.victim,
      join(h.xfer, "..", "victim"),
      join(h.xfer, "kadenco-not-hex"),
      h.xfer + "-other/kadenco-" + "0".repeat(32),
    ]) {
      const r = ctlRun(h, "install-file", p, "config");
      assert.equal(r.status, 1, p);
      assert.equal(r.json.reason, "invalid_transfer_path", p);
    }
    assert.equal(readFileSync(h.victim, "utf8"), "SECRET-CONTENT");
    const link = join(h.xfer, "kadenco-" + "a".repeat(32));
    symlinkSync(h.victim, link);
    assert.equal(ctlRun(h, "install-file", link, "config").status, 1);
    assert.equal(readFileSync(h.victim, "utf8"), "SECRET-CONTENT");
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});

test("install-release vets the archive, verifies the manifest, then publishes", { skip }, () => {
  const h = host();
  const releases = join(h.root, "opt/kadenco/releases");
  const expected = expectedManifest(h);
  const install = (members, manifest = expected) =>
    ctlRun(h, "install-release", archive(h, members), NAME, manifest);
  try {
    const refused = [
      [
        [...good, { name: `${NAME}/dist/link`, type: "link", target: "/etc/passwd" }],
        "release_archive_member_type",
      ],
      [[...good, { name: `${NAME}/../escape`, type: "file", data: "x" }], "release_archive_path"],
      [[...good, { name: "other/file", type: "file", data: "x" }], "release_archive_layout"],
    ];
    for (const [members, reason] of refused) {
      const r = install(members);
      assert.equal(r.status, 1, reason);
      assert.equal(r.json.reason, reason);
    }
    const wrong = install(good, "0".repeat(64));
    assert.equal(wrong.json.reason, "release_manifest_mismatch");
    assert.deepEqual(readdirSync(releases), [], "nothing published or left staged");
    assert.equal(existsSync(join(h.root, "escape")), false);

    const ok = install(good);
    assert.equal(ok.status, 0, ok.stdout);
    assert.equal(ok.json.existing, false);
    assert.deepEqual(readdirSync(releases), [NAME]);
    assert.equal(install(good).json.existing, true);
    assert.equal(readdirSync(h.xfer).length, 0, "transfer files consumed");

    const set = ctlRun(h, "set-release", NAME);
    assert.equal(set.status, 0, set.stdout);
    assert.equal(
      JSON.parse(readFileSync(join(h.root, "etc/kadenco/edge.json"), "utf8")).releasePath,
      join(releases, NAME),
    );
    assert.equal(ctlRun(h, "set-release", "kadenco-0.1.0-alpha.98-abcdef0").json.reason, "ENOENT");
  } finally {
    rmSync(h.root, { recursive: true, force: true });
  }
});
