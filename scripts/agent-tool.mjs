// SPDX-License-Identifier: AGPL-3.0-or-later
// Universal terminal adapter for any harness with a shell. Uses the same MCP
// tools as native integrations, never starts/resumes T3 or exposes a bearer.
import { readFileSync } from "node:fs";
import { connectAgent } from "./agent-client.mjs";
let client,
  input,
  attempted = false;
try {
  const [connection, mode, path, ...extra] = process.argv.slice(2);
  const name = {
    ask: "ask_eddie",
    get: "get_eddie_reply",
    conversation: "get_eddie_conversation",
    capabilities: "get_eddie_capabilities",
    ack_reply: "acknowledge_eddie_reply",
    ack_delivery: "acknowledge_thread_delivery",
  }[mode];
  if (!name || !path || extra.length) throw Error();
  input = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  client = await connectAgent(connection);
  if (!client.callerToolNames.includes(name)) throw Error("caller_capability_unavailable");
  attempted = true;
  const result = await client.callTool({ name, arguments: input });
  console.log(JSON.stringify(result.structuredContent));
  if (result.isError) process.exitCode = 1;
} catch {
  console.error("Eddie call failed. No automatic retry.");
  if (attempted && input?.request_id)
    console.log(
      JSON.stringify({ request_id: input.request_id, outcome: "unknown", safe_to_resend: false }),
    );
  process.exitCode = 1;
} finally {
  await client?.close();
}
