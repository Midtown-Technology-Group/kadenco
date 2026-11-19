// SPDX-License-Identifier: AGPL-3.0-or-later
// The edge's SSH forced commands are access boundaries: allowed calls must pass
// through exactly, everything else must be refused without running anything.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  chmodSync,
  utimesSync,
  existsSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = new URL("../packages/control-plane/operator/linux/forced-command/", import.meta.url);
const skip =
  process.platform === "linux"
    ? false
    : "the edge host and its fleet hosts are Linux (GNU stat, tar)";

// The exact argument vectors src/native-session.mts sends (each word single-quoted).
const READ = ["--scope", "orchestration:read"];
const OPERATE = ["--scope", "orchestration:read", "--scope", "orchestration:operate"];
const TAIL = [
  "--ttl",
  "2m",
  "--subject",
  "eddie-t3-delivery",
  "--label",
  "Eddie T3 private delivery",
  "--json",
];
// Quoted exactly like src/native-session.mts and the fleet transport.
const q = (s) => "'" + s.replaceAll("'", "'\\''") + "'";
const words = (...w) => w.map(q).join(" ");

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "kadenco-o'edge-fc-"));
  const marker = join(root, "launcher-ran");
  const pwned = join(root, "PWNED");
  const launcher = join(root, "run-t3.sh");
  // `auth session list` answers with two sessions; issue/revoke record their argv.
  writeFileSync(
    launcher,
    `#!/bin/sh
if [ "$3" = list ]; then
  echo '[{"sessionId":"edge-1","subject":"eddie-t3-delivery"},{"sessionId":"owner-1","subject":"owner"}]'
  exit 0
fi
printf '%s\\n' "$@" > "${marker}"
echo launched
`,
  );
  chmodSync(launcher, 0o755);
  const token = join(root, "fleet.token");
  writeFileSync(token, "t".repeat(120));
  return { root, marker, pwned, launcher, token, base: join(root, "t3") };
}
const run = (argv, command) =>
  spawnSync("sh", argv, {
    encoding: "utf8",
    env: { ...process.env, SSH_ORIGINAL_COMMAND: command },
  });
const ran = (f) => {
  const value = existsSync(f.marker) ? readFileSync(f.marker, "utf8").trim().split("\n") : null;
  rmSync(f.marker, { force: true });
  return value;
};
// Requests that must be refused on both platforms; none may run anything.
function refusals(f) {
  const issue = (...extra) => words(f.launcher, "auth", "session", "issue", ...extra);
  return [
    `${words(f.launcher, "auth", "session", "issue", ...READ, ...TAIL, "--base-dir", f.base)}\ntouch ${q(f.pwned)}`,
    `${words(f.launcher, "auth", "session", "list")}\ntouch ${q(f.pwned)}`,
    `touch ${q(f.pwned)}\n${words(f.launcher, "auth", "session", "issue", ...READ, ...TAIL, "--base-dir", f.base)}`,
    issue(...READ, ...TAIL, "--base-dir", f.base) + `; touch ${q(f.pwned)}`,
    issue(...READ, ...TAIL, "--base-dir", f.base) + "\r",
    issue(...READ, ...TAIL.slice(2), "--base-dir", f.base), // TTL omitted
    issue(...TAIL, "--base-dir", f.base), // scope omitted
    issue(...READ, "--ttl", "30d", ...TAIL.slice(2), "--base-dir", f.base),
    issue(...READ, ...TAIL.slice(0, 3), "owner", ...TAIL.slice(4), "--base-dir", f.base),
    issue("--scope", "admin", ...TAIL, "--base-dir", f.base),
    issue(...READ, ...TAIL, "--base-dir", "/tmp"),
    issue(...READ, ...TAIL),
    issue(...TAIL, ...READ, "--base-dir", f.base), // reordered
    issue("$(touch " + f.pwned + ")", ...TAIL, "--base-dir", f.base),
    words("/bin/sh", "auth", "session", "issue", ...READ, ...TAIL, "--base-dir", f.base),
    words(f.launcher, "auth", "session", "list", "--base-dir", f.base),
    words(f.launcher, "auth", "session", "revoke", "x;id", "--base-dir", f.base),
    words(f.launcher, "auth", "session", "revoke", "edge-1", "--base-dir", "/tmp"),
    words(f.launcher, "auth", "session", "revoke", "edge-1"),
    `${q(f.launcher)} 'auth' 'session' 'issue' "--subject" 'eddie-t3-delivery'`,
    "cat /etc/passwd",
    `stat -c %Y ${q("/etc/hostname")} && cat ${q("/etc/hostname")}`,
    "",
  ];
}

test("linux forced command passes only the edge's own requests", { skip }, () => {
  const f = fixture();
  const wrapper = [fileURLToPath(new URL("kadenco-edge-ssh", dir)), f.launcher, f.token, f.base];
  try {
    for (const [scope, granted] of [
      [READ, ["--scope", "orchestration:read"]],
      [OPERATE, ["--scope", "orchestration:read", "--scope", "orchestration:operate"]],
    ]) {
      const r = run(
        wrapper,
        words(f.launcher, "auth", "session", "issue", ...scope, ...TAIL, "--base-dir", f.base),
      );
      assert.equal(r.status, 0, r.stderr);
      assert.deepEqual(ran(f), [
        "auth",
        "session",
        "issue",
        ...granted,
        ...TAIL,
        "--base-dir",
        f.base,
      ]);
    }
    const revoke = run(
      wrapper,
      words(f.launcher, "auth", "session", "revoke", "edge-1", "--base-dir", f.base),
    );
    assert.equal(revoke.status, 0, revoke.stderr);
    assert.deepEqual(ran(f), ["auth", "session", "revoke", "edge-1", "--base-dir", f.base]);
    // Another client's session, or an unknown one, is never revoked.
    for (const id of ["owner-1", "missing"]) {
      assert.equal(
        run(wrapper, words(f.launcher, "auth", "session", "revoke", id, "--base-dir", f.base))
          .status,
        126,
        id,
      );
      assert.equal(ran(f), null, `revoked ${id}`);
    }
    const tokenRead = run(wrapper, `stat -c %Y ${q(f.token)} && cat ${q(f.token)}`);
    assert.equal(tokenRead.status, 0);
    assert.match(tokenRead.stdout, /^\d+\nt{120}$/);

    for (const command of refusals(f)) {
      const r = run(wrapper, command);
      assert.equal(r.status, 126, `not refused: ${JSON.stringify(command)}`);
      assert.equal(ran(f), null, `launcher ran for: ${JSON.stringify(command)}`);
      assert.equal(existsSync(f.pwned), false, `shell input executed: ${JSON.stringify(command)}`);
    }
  } finally {
    rmSync(f.root, { recursive: true, force: true });
  }
});

function windowsWrapper(f, account) {
  const minted = join(f.root, "minted");
  mkdirSync(minted, { recursive: true });
  const template = readFileSync(new URL("kadenco-edge-windows.sh", dir), "utf8");
  const config = [
    `account=${q(account)}`,
    `launcher=${q(f.launcher)}`,
    `basedir=${q(f.base)}`,
    `token=${q(f.token)}`,
    `minted=${q(minted)}`,
  ].join("\n");
  const filled = template.replace(
    /# --- configuration -+\n[\s\S]*?# --- end configuration -+\n/,
    (block) => block.split("\n")[0] + "\n" + config + "\n# --- end configuration\n",
  );
  assert.notEqual(filled, template, "configuration block not found");
  const path = join(f.root, "kadenco-edge-windows.sh");
  writeFileSync(path, filled);
  writeFileSync(join(minted, "runtime.json"), '{"port":3773}');
  const in15 = new Date(Date.now() + 15 * 60000).toISOString();
  writeFileSync(
    join(minted, "delivery-read.json"),
    JSON.stringify({ sessionId: "r1", scopes: ["orchestration:read"], expiresAt: in15 }, null, 2),
  );
  writeFileSync(
    join(minted, "delivery.json"),
    JSON.stringify(
      { sessionId: "o1", scopes: ["orchestration:read", "orchestration:operate"], expiresAt: in15 },
      null,
      2,
    ),
  );
  return { path, minted };
}

test(
  "windows forced command serves the pre-minted session of the requested scope only",
  { skip },
  () => {
    const f = fixture();
    const me = execFileSync("whoami", { encoding: "utf8" }).trim().toLowerCase();
    const w = windowsWrapper(f, me);
    const issue = (scope) =>
      words(f.launcher, "auth", "session", "issue", ...scope, ...TAIL, "--base-dir", f.base);
    try {
      assert.deepEqual(JSON.parse(run([w.path], issue(READ)).stdout).scopes, [
        "orchestration:read",
      ]);
      assert.deepEqual(JSON.parse(run([w.path], issue(OPERATE)).stdout).scopes, [
        "orchestration:read",
        "orchestration:operate",
      ]);
      assert.equal(
        run([w.path], words(f.launcher, "auth", "session", "revoke", "r1", "--base-dir", f.base))
          .status,
        0,
      );
      assert.equal(
        run([w.path], 'cat "$HOME/.t3/userdata/server-runtime.json"').stdout,
        '{"port":3773}',
      );

      // A session that expires in under 4 minutes is not served, even from a new file.
      writeFileSync(
        join(w.minted, "delivery-read.json"),
        JSON.stringify({
          sessionId: "r2",
          scopes: ["orchestration:read"],
          expiresAt: new Date(Date.now() + 120000).toISOString(),
        }),
      );
      assert.equal(run([w.path], issue(READ)).status, 1);

      // An old session is not served.
      const old = (Date.now() - 12 * 60000) / 1000;
      utimesSync(join(w.minted, "delivery.json"), old, old);
      assert.equal(run([w.path], issue(OPERATE)).status, 1);

      for (const command of [
        ...refusals(f),
        `cat ${q(join(w.minted, "delivery.json"))}`,
        `stat -c %Y ${q(join(w.minted, "delivery.json"))} && cat ${q(join(w.minted, "delivery.json"))}`,
      ]) {
        const r = run([w.path], command);
        assert.equal(r.status, 126, `not refused: ${JSON.stringify(command)}`);
        assert.equal(
          existsSync(f.pwned),
          false,
          `shell input executed: ${JSON.stringify(command)}`,
        );
      }
      assert.equal(ran(f), null, "the windows wrapper never runs the launcher");

      // Another account is refused outright, including one whose name is a
      // suffix of the caller's (account "unner" must not admit user "runner").
      for (const account of ["x" + me, me.slice(1)]) {
        const other = windowsWrapper(f, account);
        assert.equal(run([other.path], issue(READ)).status, 126, account);
      }
    } finally {
      rmSync(f.root, { recursive: true, force: true });
    }
  },
);
