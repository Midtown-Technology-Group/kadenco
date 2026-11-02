// SPDX-License-Identifier: AGPL-3.0-or-later
/** Trusted operator transport. No retries, redirects, token logging or fallback
 * identity. Callers reconcile the original receipt after any uncertain response. */
export function centralTransport(options: {
  origin: string;
  token: () => string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}) {
  const url = new URL(options.origin);
  const timeout = options.timeoutMs ?? 10000;
  if (
    url.protocol !== "https:" ||
    url.origin !== options.origin ||
    url.username ||
    url.password ||
    !Number.isSafeInteger(timeout) ||
    timeout < 100 ||
    timeout > 60000
  )
    throw Error("invalid_central_transport");
  const send = options.fetch ?? fetch;
  return async (operation: string, payload: object): Promise<Record<string, unknown>> => {
    if (!/^[a-z][a-z_]{0,63}$/.test(operation)) throw Error("invalid_central_operation");
    const body = JSON.stringify(payload);
    if (Buffer.byteLength(body) > 65536) throw Error("central_request_too_large");
    const token = options.token();
    if (!token || token.length > 8192 || /[\r\n]/.test(token))
      throw Error("central_identity_required");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const response = await send(new URL("/" + operation, url), {
        method: "POST",
        redirect: "error",
        signal: controller.signal,
        headers: { authorization: "Bearer " + token, "content-type": "application/json" },
        body,
      });
      const reader = response.body?.getReader();
      if (!reader) throw Error("central_response_unavailable");
      let size = 0;
      const chunks: Uint8Array[] = [];
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > 65536) {
            await reader.cancel();
            throw Error("central_response_too_large");
          }
          chunks.push(value);
        }
      } finally {
        reader.releaseLock();
      }
      const data: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!data || typeof data !== "object" || Array.isArray(data))
        throw Error("central_response_invalid");
      // Return native refusal fields unchanged; consumers must check permits.
      // HTTP failure without a structured refusal is never treated as success.
      if (!response.ok) {
        const reason = (data as { reason?: unknown }).reason;
        if (typeof reason !== "string") throw Error("central_response_unavailable");
        return { reason, safe_to_resend: false };
      }
      return data as Record<string, unknown>;
    } catch (error) {
      // Never propagate fetch/URL/provider error text that might include secrets.
      if (
        error instanceof Error &&
        ["central_response_too_large", "central_response_invalid"].includes(error.message)
      )
        throw error;
      throw Error("central_transport_uncertain");
    } finally {
      clearTimeout(timer);
    }
  };
}
