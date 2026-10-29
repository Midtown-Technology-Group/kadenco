// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  hostAskArgs,
  hostGetArgs,
  hostAckArgs,
  hostConversationArgs,
  hostCapabilityArgs,
} from "../src/host-callers.mjs";
// One explicit MCP call, no launcher, background polling or native T3 writes.
// The Windows wrapper supplies only the separately enrolled caller credential.
import { readFileSync } from "node:fs";
import { askArgs, requestArgs, acknowledgeArgs, conversationArgs } from "../src/exchange.mjs";
import { z } from "zod";
import { ackCommandArgs } from "../src/commands.mjs";
import { callerClient } from "./caller-client.mjs";

let client,
  args,
  attempted = false;
try {
  const [mode, path, ...extra] = process.argv.slice(2);
  if (
    extra.length ||
    !["ask", "get", "ack_reply", "ack_delivery", "conversation", "capabilities"].includes(mode) ||
    !path
  )
    throw new Error();
  client = await callerClient();
  const schemas = client.hostCaller
    ? {
        ask: hostAskArgs,
        get: hostGetArgs,
        ack_reply: hostAckArgs,
        conversation: hostConversationArgs,
        capabilities: hostCapabilityArgs,
      }
    : null;
  args = (schemas ?? {
    ask: askArgs,
    get: requestArgs,
    ack_reply: acknowledgeArgs,
    ack_delivery: ackCommandArgs,
    conversation: conversationArgs,
    capabilities: z.object({}).strict(),
  })[mode].parse(JSON.parse(readFileSync(path, "utf8").replace(/^\uFEFF/, "")));
  attempted = true;
  const result = await client.callTool({
    name: {
      ask: "ask_eddie",
      get: "get_eddie_reply",
      ack_reply: "acknowledge_eddie_reply",
      ack_delivery: "acknowledge_thread_delivery",
      conversation: "get_eddie_conversation",
      capabilities: "get_eddie_capabilities",
    }[mode],
    arguments: args,
  });
  if (result.isError) {
    const allowed = [
      "forbidden",
      "source_run_not_active",
      "exchange_budget_exhausted",
      "idempotency_conflict",
      "authentication_required",
      "source_unavailable",
      "reply_not_available",
      "conversation_parent_required",
      "exchange_expired",
      "reply_mismatch",
    ];
    console.error(
      allowed.includes(result.structuredContent?.reason)
        ? result.structuredContent.reason
        : "request_denied",
    );
    process.exitCode = 1;
  } else console.log(JSON.stringify(result.structuredContent));
} catch {
  if (attempted && args?.request_id)
    console.log(
      JSON.stringify({
        request_id: args.request_id,
        outcome: "unknown",
        safe_to_resend: false,
        instruction:
          "Transport failed after call attempt. Reconcile this exact request ID; preserve the original arguments. No automatic retry or new UUID.",
      }),
    );
  console.error(
    "Caller request failed; inspect enrollment, input and adapter audit. Reuse the same request_id and arguments after uncertain submission.",
  );
  process.exitCode = 1;
} finally {
  await client?.close();
}
