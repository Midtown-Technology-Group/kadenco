// SPDX-License-Identifier: AGPL-3.0-or-later
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";

export async function callerClient() {
  const token = process.env.EDDIE_T3_CALLER_TOKEN;
  delete process.env.EDDIE_T3_CALLER_TOKEN;
  const endpoint = process.env.EDDIE_T3_CALLER_ENDPOINT;
  delete process.env.EDDIE_T3_CALLER_ENDPOINT;
  const url = new URL(endpoint);
  // A remote caller must use an explicitly authorized existing SSH forward.
  // Never send this bearer to an arbitrary host or follow a redirect.
  if (
    !token ||
    url.protocol !== "http:" ||
    url.hostname !== "127.0.0.1" ||
    url.pathname !== "/mcp" ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  )
    throw new Error("invalid_caller_endpoint");
  const client = new Client(
    { name: "t3-eddie-caller", version: "0.10.5" },
    { versionNegotiation: { mode: { pin: "2026-07-28" } } },
  );
  try {
    await client.connect(
      new StreamableHTTPClientTransport(url, {
        requestInit: { headers: { Authorization: "Bearer " + token } },
        fetch: (url, options) =>
          fetch(url, { ...options, redirect: "error", signal: AbortSignal.timeout(30000) }),
      }),
    );
    const names = (await client.listTools()).tools.map((t) => t.name).sort();
    if (
      !["ask_eddie", "get_eddie_reply", "acknowledge_eddie_reply"].every((n) =>
        names.includes(n),
      ) ||
      names.some(
        (n) =>
          ![
            "ask_eddie",
            "get_eddie_reply",
            "acknowledge_eddie_reply",
            "acknowledge_thread_delivery",
            "get_eddie_conversation",
            "get_eddie_capabilities",
          ].includes(n),
      )
    )
      throw new Error("caller_role_required");
    client.callerToolNames = Object.freeze(names);
    const capability = names.includes("get_eddie_capabilities")
      ? await client.callTool({ name: "get_eddie_capabilities", arguments: {} })
      : null;
    if (capability?.isError) throw new Error("caller_role_required");
    client.hostCaller = capability?.structuredContent?.host_caller === true;
    return client;
  } catch {
    await client.close();
    throw new Error("caller_connection_failed");
  }
}
