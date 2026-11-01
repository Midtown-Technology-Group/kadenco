import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { resolveTool, runAgentWrangler } from "../scripts/agent-wrangler.mjs";

test("executor dispatches mapped reads once with literal argv and no shell", () => {
  const calls = [],
    worker = "a; $(literal) & name";
  const status = runAgentWrangler(["deployments", "list", "--name", worker], {
    resolveTool: (name) => {
      assert.equal(name, "cf");
      return "installed cf/bin/cf";
    },
    spawnSync: (...args) => {
      calls.push(args);
      return { status: 17 };
    },
  });
  assert.equal(status, 17);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0][1], [
    "installed cf/bin/cf",
    "workers",
    "deployments",
    "list",
    "--worker",
    worker,
  ]);
  assert.equal(calls[0][2].shell, false);
  assert.equal(calls[0][2].env, undefined); // Inherit existing identity; no credential copying.
});
test("local build stays Wrangler; refused writes and dev never resolve or spawn", () => {
  const argv = ["deploy", "--dry-run", "--outdir", "space here"];
  assert.equal(
    runAgentWrangler(argv, {
      resolveTool: (name) => {
        assert.equal(name, "wrangler");
        return "wrangler.js";
      },
      spawnSync: (_node, args) => {
        assert.deepEqual(args, ["wrangler.js", ...argv]);
        return { status: 0 };
      },
    }),
    0,
  );
  for (const args of [["deploy"], ["login"], ["whoami", "--profile", "other"], ["dev", "--local"]])
    assert.equal(
      runAgentWrangler(args, {
        report: () => {},
        resolveTool: () => assert.fail("must not resolve"),
        spawnSync: () => assert.fail("must not execute"),
      }),
      2,
    );
});
test("missing CLI or failed spawn never falls back, logs no credentials", () => {
  const reports = [];
  assert.equal(
    runAgentWrangler(["whoami"], {
      report: (s) => reports.push(s),
      resolveTool: () => {
        throw Error("existing_cf_installation_required");
      },
    }),
    1,
  );
  assert.match(reports[0], /existing_cf_installation_required/);
  assert.equal(
    runAgentWrangler(["whoami"], {
      report: () => {},
      resolveTool: () => "cf",
      spawnSync: () => ({ error: Error("fixture") }),
    }),
    1,
  );
});
test("real executable entrypoint uses existing npm CLI layout, including paths with spaces", () => {
  const root = mkdtempSync(join(tmpdir(), "kadenco CLI "));
  try {
    const pkg = join(root, "node_modules", "cf");
    mkdirSync(join(pkg, "bin"), { recursive: true });
    writeFileSync(
      join(pkg, "package.json"),
      JSON.stringify({ name: "cf", bin: { cf: "bin/cf.cjs" } }),
    );
    writeFileSync(
      join(pkg, "bin", "cf.cjs"),
      "console.log(JSON.stringify(process.argv.slice(2)));process.exitCode=23;",
    );
    assert.equal(resolveTool("cf", root, ""), join(pkg, "bin", "cf.cjs"));
    const child = spawnSync(
      process.execPath,
      [fileURLToPath(new URL("../scripts/agent-wrangler.mjs", import.meta.url)), "whoami"],
      { cwd: root, encoding: "utf8", env: { ...process.env, PATH: "" } },
    );
    assert.equal(child.status, 23, child.stderr);
    assert.deepEqual(JSON.parse(child.stdout), ["auth", "whoami"]);
    writeFileSync(
      join(pkg, "package.json"),
      JSON.stringify({ name: "cf", bin: "../../outside.js" }),
    );
    assert.throws(() => resolveTool("cf", root, ""), /installed_cli_entry_invalid/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
