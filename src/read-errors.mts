// SPDX-License-Identifier: AGPL-3.0-or-later
// Fixed diagnostic vocabulary only. Never return native exception text or tokens.
export const readReasons = new Set([
  "source_unavailable",
  "source_timeout",
  "source_internal_error",
  "source_temporarily_unavailable",
  "source_protocol_error",
  "invalid_source_request",
  "invalid_source_pagination",
  "authentication_required",
  "forbidden",
  "identity_mismatch",
  "thread_not_found",
  "invalid_inventory_cursor",
  "inventory_changed",
]);
export const transientReadReasons = new Set([
  "source_timeout",
  "source_internal_error",
  "source_temporarily_unavailable",
]);
export function readReason(error) {
  if (readReasons.has(error?.reason)) return error.reason;
  const message = String(error?.message ?? "");
  if (/thread_not_found/.test(message)) return "thread_not_found";
  if (
    /MCP authentication denied|existing.*credential.*(unavailable|stale)|no unexpired existing|MCP isError: (unauthorized|invalid_scope)/.test(
      message,
    )
  )
    return "authentication_required";
  return "source_unavailable";
}
export const rpcReadReason = (code) =>
  code === -32603
    ? "source_internal_error"
    : code === -32602
      ? "invalid_source_request"
      : "source_protocol_error";
