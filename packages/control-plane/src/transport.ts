// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomUUID } from "node:crypto";
export type CentralDiagnostic = {
  correlation_id: string;
  operation: string;
  duration_ms: number;
  outcome: "ok" | "refused" | "uncertain";
  http_status: number | null;
  rate_limit_remaining?: number;
};
/** Trusted operator transport. No retries, redirects, token logging or fallback
 * identity. Callers reconcile the original receipt after any uncertain response. */
export function centralTransport(options: {
  origin: string;
  token: () => string;
  fetch?: typeof fetch;
  timeoutMs?: number;
  diagnostic?: (record: CentralDiagnostic) => void;
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
    const started = Date.now(),
      correlation_id = randomUUID();
    let http_status: number | null = null,
      outcome: CentralDiagnostic["outcome"] = "uncertain",
      remaining: number | undefined;
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
      http_status = response.status;
      const header = response.headers.get("x-ratelimit-remaining");
      if (header !== null && /^\d{1,15}$/.test(header) && Number.isSafeInteger(Number(header)))
        remaining = Number(header);
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
        outcome = "refused";
        return { reason, safe_to_resend: false };
      }
      outcome = typeof (data as { reason?: unknown }).reason === "string" ? "refused" : "ok";
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
      try {
        const emitted = options.diagnostic?.({
          correlation_id,
          operation,
          duration_ms: Math.max(0, Date.now() - started),
          http_status,
          outcome,
          ...(remaining === undefined ? {} : { rate_limit_remaining: remaining }),
        });
        void Promise.resolve(emitted).catch(() => {});
      } catch {
        /* Diagnostics never retry or replace the operation outcome. */
      }
    }
  };
}
