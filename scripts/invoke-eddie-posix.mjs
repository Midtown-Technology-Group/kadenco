// SPDX-License-Identifier: AGPL-3.0-or-later
// The credential path is metadata; its content never enters argv or output.
import { readCallerCredential } from "./posix-credential.mjs";
try {
  const [path, mode, input, ...extra] = process.argv.slice(2);
  if (
    extra.length ||
    (mode &&
      !["ask", "get", "ack_reply", "ack_delivery", "conversation", "capabilities"].includes(
        mode,
      )) ||
    !!mode !== !!input
  )
    throw new Error();
  const c = readCallerCredential(path);
  process.env.EDDIE_T3_CALLER_TOKEN = c.token;
  delete c.token;
  process.env.EDDIE_T3_CALLER_ENDPOINT = c.endpoint;
  if (mode) {
    process.argv = [process.execPath, "caller.mjs", mode, input];
    await import("./caller.mjs");
  } else await import("./caller-mcp.mjs");
} catch {
  console.error("Eddie caller startup failed; check private enrollment and SSH forward.");
  process.exitCode = 1;
} finally {
  delete process.env.EDDIE_T3_CALLER_TOKEN;
  delete process.env.EDDIE_T3_CALLER_ENDPOINT;
}
