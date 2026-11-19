// SPDX-License-Identifier: AGPL-3.0-or-later
// The edge's SSH forced commands are access boundaries: allowed calls must pass
// through exactly, everything else must be refused without running anything.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import {
  mkdtempSync,
  writeFileSync,
  readFileSync,
  chmodSync,
  utimesSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const dir = new URL("../packages/control-plane/operator/linux/forced-command/", import.meta.url);
const posix = process.platform !== "win32";
const skip = posix ? false : "forced commands run under a POSIX sh";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "kadenco-edge-fc-"));
  const marker = join(root, "launcher-ran");
  const launcher = join(root, "run-t3.sh");
  writeFileSync(launcher, `#!/bin/sh\nprintf '%s\\n' "$@" > '${marker}'\necho launched\n`);
  chmodSync(launcher, 0o755);
  const token = join(root, "fleet.token");
  writeFileSync(token, "t".repeat(120));
  return { root, marker, launcher, token, base: join(root, "t3") };
}
const run = (argv, command, env = {}) =>
  spawnSync("sh", argv, {
    encoding: "utf8",
    env: { ...process.env, ...env, SSH_ORIGINAL_COMMAND: command },
  });
const q = (s) => `'${s}'`;
const words = (...w) => w.map(q).join(" ");

const ISSUE = [
  "auth",
  "session",
  "issue",
  "--scope",
  "orchestration:read",
  "--scope",
  "orchestration:operate",
  "--ttl",
  "2m",
  "--subject",
  "eddie-t3-delivery",
  "--label",
  "Eddie T3 private delivery",
  "--json",
];

test("linux forced command passes only the edge's own requests", { skip }, () => {
  const f = fixture();
  const wrapper = [new URL("kadenco-edge-ssh", dir).pathname, f.launcher, f.token, f.base];
  try {
    const issue = run(wrapper, words(f.launcher, ...ISSUE, "--base-dir", f.base));
    assert.equal(issue.status, 0, issue.stderr);
    assert.deepEqual(readFileSync(f.marker, "utf8").trim().split("\n"), [
      "auth",
      "session",
      "issue",
      "--scope",
      "orchestration:read",
      "--scope",
      "orchestration:operate",
      "--ttl",
      "2m",
      "--subject",
      "eddie-t3-delivery",
      "--json",
      "--label",
      "Eddie T3 private delivery",
      "--base-dir",
      f.base,
    ]);
    rmSync(f.marker);
    const revoke = run(
      wrapper,
      words(f.launcher, "auth", "session", "revoke", "abc-123", "--base-dir", f.base),
    );
    assert.equal(revoke.status, 0, revoke.stderr);
    assert.deepEqual(readFileSync(f.marker, "utf8").trim().split("\n"), [
      "auth",
      "session",
      "revoke",
      "abc-123",
      "--base-dir",
      f.base,
    ]);
    rmSync(f.marker);
    const tokenRead = run(wrapper, `stat -c %Y ${q(f.token)} && cat ${q(f.token)}`);
    assert.equal(tokenRead.status, 0);
    assert.match(tokenRead.stdout, /^\d+\nt{120}$/);

    const refused = [
      words(f.launcher, "auth", "session", "issue", "--subject", "owner", "--base-dir", f.base),
      words(
        f.launcher,
        "auth",
        "session",
        "issue",
        "--subject",
        "eddie-t3-delivery",
        "--ttl",
        "30d",
        "--base-dir",
        f.base,
      ),
      words(
        f.launcher,
        "auth",
        "session",
        "issue",
        "--subject",
        "eddie-t3-delivery",
        "--scope",
        "admin",
        "--base-dir",
        f.base,
      ),
      words(
        f.launcher,
        "auth",
        "session",
        "issue",
        "--subject",
        "eddie-t3-delivery",
        "--base-dir",
        "/tmp",
      ),
      words(f.launcher, "auth", "session", "issue", "--subject", "eddie-t3-delivery"),
      words(f.launcher, "auth", "session", "list", "--base-dir", f.base),
      words(f.launcher, "auth", "session", "revoke", "x;id", "--base-dir", f.base),
      words("/bin/sh", ...ISSUE, "--base-dir", f.base),
      words(f.launcher, ...ISSUE, "--base-dir", f.base) + "; id",
      words(f.launcher, "auth", "session", "issue", "$(id)", "--base-dir", f.base),
      `${q(f.launcher)} 'auth' 'session' 'issue' "--subject" 'eddie-t3-delivery'`,
      "cat /etc/passwd",
      `stat -c %Y ${q("/etc/shadow")} && cat ${q("/etc/shadow")}`,
      "",
    ];
    for (const command of refused) {
      const r = run(wrapper, command);
      assert.equal(r.status, 126, `not refused: ${command}`);
      assert.equal(existsSync(f.marker), false, `launcher ran for: ${command}`);
    }
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

function windowsWrapper(f, account) {
  const minted = join(f.root, "minted");
  execFileSync("mkdir", ["-p", minted]);
  const template = readFileSync(new URL("kadenco-edge-windows.sh", dir), "utf8");
  const config = [
    `account='${account}'`,
    `launcher='${f.launcher}'`,
    `basedir='${f.base}'`,
    `token='${f.token}'`,
    `minted='${minted}'`,
  ].join("\n");
  const filled = template.replace(
    /# --- configuration -+\n[\s\S]*?# --- end configuration -+\n/,
    (block) => block.split("\n")[0] + "\n" + config + "\n# --- end configuration\n",
  );
  assert.notEqual(filled, template, "configuration block not found");
  const path = join(f.root, "kadenco-edge-windows.sh");
  writeFileSync(path, filled);
  writeFileSync(join(minted, "runtime.json"), '{"port":3773}');
  writeFileSync(
    join(minted, "delivery.json"),
    '{"sessionId":"s1","token":"x","subject":"eddie-t3-delivery"}',
  );
  return { path, minted };
}

test(
  "windows forced command serves the pre-minted session only to the exact request",
  { skip },
  () => {
    const f = fixture();
    const me = execFileSync("whoami", { encoding: "utf8" }).trim().toLowerCase();
    const w = windowsWrapper(f, me);
    try {
      const issue = run([w.path], words(f.launcher, ...ISSUE, "--base-dir", f.base));
      assert.equal(issue.status, 0, issue.stderr);
      assert.equal(JSON.parse(issue.stdout).subject, "eddie-t3-delivery");
      assert.equal(
        run([w.path], words(f.launcher, "auth", "session", "revoke", "s1", "--base-dir", f.base))
          .status,
        0,
      );
      assert.equal(
        run([w.path], 'cat "$HOME/.t3/userdata/server-runtime.json"').stdout,
        '{"port":3773}',
      );

      // An old session is not served.
      const old = (Date.now() - 12 * 60000) / 1000;
      utimesSync(join(w.minted, "delivery.json"), old, old);
      assert.equal(run([w.path], words(f.launcher, ...ISSUE, "--base-dir", f.base)).status, 1);

      for (const command of [
        words(f.launcher, "auth", "session", "issue", "--subject", "owner", "--base-dir", f.base),
        words(
          f.launcher,
          "auth",
          "session",
          "issue",
          "--subject",
          "eddie-t3-delivery",
          "--ttl",
          "15m",
          "--base-dir",
          f.base,
        ),
        words(
          f.launcher,
          "auth",
          "session",
          "issue",
          "--subject",
          "eddie-t3-delivery",
          "--base-dir",
          "/tmp",
        ),
        words(f.launcher, "auth", "session", "list", "--base-dir", f.base),
        `cat ${q(join(w.minted, "delivery.json"))}`,
        `stat -c %Y ${q(join(w.minted, "delivery.json"))} && cat ${q(join(w.minted, "delivery.json"))}`,
        words(f.launcher, ...ISSUE, "--base-dir", f.base) + "; id",
        "",
      ])
        assert.equal(run([w.path], command).status, 126, `not refused: ${command}`);
      assert.equal(existsSync(f.marker), false, "the windows wrapper never runs the launcher");

      // Another account is refused outright, including one whose name is a
      // suffix of the caller's (account "unner" must not admit user "runner").
      for (const account of ["x" + me, me.slice(1)]) {
        const other = windowsWrapper(f, account);
        assert.equal(
          run([other.path], words(f.launcher, ...ISSUE, "--base-dir", f.base)).status,
          126,
          account,
        );
      }
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  },
);
