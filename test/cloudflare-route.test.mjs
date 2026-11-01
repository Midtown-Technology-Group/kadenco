import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { routeWrangler } from "../scripts/cloudflare-route.mjs";

test("control-plane reads map explicitly without silently dropping target selection", () => {
  assert.deepEqual(routeWrangler(["whoami"]).argv, ["auth", "whoami"]);
  const name = "worker name; $(do-not-execute) & literal";
  assert.deepEqual(routeWrangler(["deployments", "list", "--name", name]).argv, [
    "workers",
    "deployments",
    "list",
    "--worker",
    name,
  ]);
  for (const suffix of [
    [],
    ["--env", "prod"],
    ["--config", "other.json"],
    ["--name", "a", "--name", "b"],
  ])
    assert.equal(routeWrangler(["deployments", "list", ...suffix]).allowed, false);
});
test("local build/types/explicit local dev retain argv and never become cf deploy", () => {
  for (const argv of [
    ["deploy", "--dry-run", "--outdir", "path with spaces"],
    ["types", "generated.d.ts", "--config", "path with spaces.json"],
    ["dev", "--local", "--port", "8787"],
  ]) {
    const original = [...argv];
    const result = routeWrangler(argv);
    assert.equal(result.executable, "wrangler");
    assert.deepEqual(result.argv, original);
    assert.deepEqual(argv, original);
    assert.equal(result.execute, false);
  }
});
test("unsupported mutations, auth, selectors and remote flags fail closed", () => {
  for (const argv of [
    ["deploy"],
    ["login"],
    ["secret", "put", "NAME"],
    ["dev"],
    ["dev", "--local", "--remote"],
    ["deploy", "--dry-run", "--unknown"],
    ["whoami", "--profile", "another"],
    ["types", "--api-token", "do-not-use"],
    ["types\nlogin"],
  ])
    assert.equal(routeWrangler(argv).allowed, false, JSON.stringify(argv));
});
test("CLI emits only structured plans, refuses with exit2, and spawns no cloud CLI", () => {
  const script = fileURLToPath(new URL("../scripts/cloudflare-route.mjs", import.meta.url));
  const child = spawnSync(process.execPath, [script, "whoami"], {
    encoding: "utf8",
    env: { ...process.env, PATH: "" },
  });
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).execute, false);
  const denied = spawnSync(process.execPath, [script, "deploy"], { encoding: "utf8" });
  assert.equal(denied.status, 2);
  assert.equal(JSON.parse(denied.stdout).allowed, false);
});
