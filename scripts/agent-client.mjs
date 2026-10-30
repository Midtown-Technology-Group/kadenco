// SPDX-License-Identifier: AGPL-3.0-or-later
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { readFileSync } from "node:fs";
const names = [
  "ask_eddie",
  "get_eddie_reply",
  "get_eddie_conversation",
  "get_eddie_capabilities",
  "acknowledge_eddie_reply",
];
const optionalNames = [
  "acknowledge_thread_delivery",
  "request_thread_sharing",
  "get_thread_sharing_request",
];
export async function connectAgent(path) {
  const launch = JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, ""));
  if (
    typeof launch.command !== "string" ||
    !Array.isArray(launch.args) ||
    launch.args.some((x) => typeof x !== "string") ||
    typeof launch.host !== "string"
  )
    throw Error("invalid_private_connection");
  const client = new Client(
    { name: "eddie-t3-agent", version: "0.10.5" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await client.connect(
      new StdioClientTransport({ command: launch.command, args: launch.args, stderr: "ignore" }),
    );
    const tools = (await client.listTools()).tools.map((t) => t.name).sort();
    if (
      !names.every((n) => tools.includes(n)) ||
      tools.some((n) => ![...names, ...optionalNames].includes(n))
    )
      throw Error("passive_host_caller_required");
    const r = await client.callTool({ name: "get_eddie_capabilities", arguments: {} });
    if (
      r.isError ||
      r.structuredContent?.host_caller !== true ||
      r.structuredContent.host !== launch.host
    )
      throw Error("host_binding_mismatch");
    client.callerToolNames = Object.freeze(tools);
    return client;
  } catch {
    await client.close();
    throw Error("eddie_agent_connection_unavailable");
  }
}
export const agentToolNames = Object.freeze(names);
