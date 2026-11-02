// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
/** Resolve the original event contract. Task-finished events carry a session ID,
 * unlike fleet/lane/inbox events; never guess a host or create a return lane. */
export function eventTarget(bridge: Bridge, subscription: Record<string, unknown>, event: unknown) {
  const e = event as { name?: unknown; data?: Record<string, unknown> };
  if (!e || e.name !== subscription.name || !e.data || typeof e.data !== "object")
    throw Error("identity_mismatch");
  let host = subscription.host ?? e.data.host;
  let thread = subscription.threadId ?? e.data.thread_id ?? "aggregate";
  if (subscription.name === "t3.task.finished") {
    if (typeof subscription.owner !== "string" || typeof subscription.sessionId !== "string")
      throw Error("identity_mismatch");
    const session = bridge.grant(subscription.owner, subscription.sessionId);
    if (e.data.session_id !== session.id) throw Error("identity_mismatch");
    host = session.host;
    thread = session.threadId;
  }
  if (
    typeof host !== "string" ||
    !host ||
    host.length > 100 ||
    typeof thread !== "string" ||
    !thread ||
    thread.length > 2048 ||
    (subscription.host !== undefined && subscription.host !== host) ||
    (subscription.threadId !== undefined && subscription.threadId !== thread) ||
    (e.data.host !== undefined && e.data.host !== host) ||
    (e.data.thread_id !== undefined && e.data.thread_id !== thread)
  )
    throw Error("identity_mismatch");
  return { host, thread };
}
