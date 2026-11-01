// SPDX-License-Identifier: AGPL-3.0-or-later
import { pathToFileURL } from "node:url";

const refuse = (reason) => ({
  allowed: false,
  reason,
  next: "Use anonymous cf cli search for the operation, inspect its help/schema, and reconcile identity/account and approvals. Do not retry a denial through another caller.",
});

/** Produce an argv plan only. Never execute a command, transfer auth or change configuration. */
export function routeWrangler(argv) {
  if (!Array.isArray(argv) || argv.some((v) => typeof v !== "string" || /[\0\r\n]/.test(v)))
    return refuse("invalid_argv");
  const args = [...argv];
  const [command, subcommand] = args;
  const plan = (executable, routed, kind) => ({
    allowed: true,
    kind,
    executable,
    argv: routed,
    execute: false,
    account: "unchanged: verify the existing tool profile and account before execution",
  });
  const parse = (input, valueFlags, booleanFlags = []) => {
    const values = new Map();
    for (let i = 0; i < input.length; i++) {
      const flag = input[i];
      if (values.has(flag)) return null;
      if (booleanFlags.includes(flag)) values.set(flag, true);
      else if (valueFlags.includes(flag) && input[i + 1] && !input[i + 1].startsWith("-"))
        values.set(flag, input[++i]);
      else return null;
    }
    return values;
  };
  if (command === "whoami" && args.length === 1)
    return plan("cf", ["auth", "whoami"], "control-plane-read");
  if (command === "deployments" && subcommand === "list") {
    // Never silently discard Wrangler config/env/account selection: those need manual mapping.
    const flags = parse(args.slice(2), ["--name"]);
    if (!flags?.has("--name")) return refuse("explicit_worker_name_required_or_unsupported_flags");
    return plan(
      "cf",
      ["workers", "deployments", "list", "--worker", flags.get("--name")],
      "control-plane-read",
    );
  }
  if (command === "deploy" && args.includes("--dry-run")) {
    if (!parse(args.slice(1), ["--config", "--env", "--outdir", "--name"], ["--dry-run"]))
      return refuse("unsupported_local_build_flags");
    return plan("wrangler", args, "local-build");
  }
  if (command === "types") {
    const rest = args.slice(1);
    if (rest[0] && !rest[0].startsWith("-")) rest.shift();
    if (!parse(rest, ["--config", "--env"], ["--check"])) return refuse("unsupported_types_flags");
    return plan("wrangler", args, "local-types");
  }
  if (command === "dev" && args.includes("--local")) {
    if (!parse(args.slice(1), ["--config", "--env", "--port", "--ip"], ["--local"]))
      return refuse("unsupported_local_dev_flags");
    return plan("wrangler", args, "local-dev-review-bindings");
  }
  return refuse(
    "no_safe_mapping: cloud mutations, login and implicit/remote dev require explicit native cf review",
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const result = routeWrangler(process.argv.slice(2));
  process.stdout.write(JSON.stringify(result) + "\n");
  if (!result.allowed) process.exitCode = 2;
}
