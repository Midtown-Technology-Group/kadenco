// SPDX-License-Identifier: AGPL-3.0-or-later
import type { DiagnosticRecord, NativeRecord } from "./contracts.mjs";
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import { readReason } from "./read-errors.mjs";
const context = new AsyncLocalStorage<{
  origin: string;
  operation: string;
  correlation_id: string;
}>();
export function diagnosticContext<T>(origin: string, operation: string, fn: () => T): T {
  return context.run({ origin, operation, correlation_id: randomUUID() }, fn);
}
const codes = new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "EHOSTUNREACH",
  "ENETUNREACH",
  "ENOENT",
  "EACCES",
  "EPIPE",
]);
const stages = new Set([
  "credential",
  "runtime_metadata",
  "ssh_forward",
  "mcp_initialize",
  "native_read",
  "host_read",
  "worker",
  "webhook",
]);
// Fixed fields only: never serialize exception messages, URLs, arguments,
// headers, credential files, keys, stdout/stderr or provider response bodies.
export function diagnosticRecord(host, stage, started, error, metadata: NativeRecord = {}) {
  const c = context.getStore(),
    code = error?.code ?? error?.cause?.code;
  const r: DiagnosticRecord = {
    at: new Date().toISOString(),
    host,
    stage: stages.has(stage) ? stage : "host_read",
    origin: ["worker", "mcp"].includes(c?.origin) ? c.origin : "internal",
    correlation_id: c?.correlation_id ?? randomUUID(),
    operation: c?.operation ?? "internal",
    duration_ms: Math.max(0, Date.now() - started),
    outcome: error ? "failed" : "ok",
    reason: error ? readReason(error) : null,
  };
  if (codes.has(code)) r.transport_code = code;
  if (
    Number.isInteger(metadata.http_status) &&
    metadata.http_status >= 100 &&
    metadata.http_status <= 599
  )
    r.http_status = metadata.http_status;
  if (
    Number.isFinite(metadata.credential_expires_at) &&
    Math.abs(metadata.credential_expires_at) <= 8640000000000000
  )
    r.credential_expires_at = new Date(metadata.credential_expires_at).toISOString();
  if (["cache", "existing_file"].includes(metadata.credential_source))
    r.credential_source = metadata.credential_source;
  if (
    ["searchThreads", "readThread", "listProjects", "listThreads"].includes(
      metadata.native_operation,
    )
  )
    r.native_operation = metadata.native_operation;
  if (
    ["cache_unavailable", "file_unavailable", "file_stale_or_malformed"].includes(
      metadata.credential_status,
    )
  )
    r.credential_status = metadata.credential_status;
  if (typeof metadata.event_id === "string" && /^evt_[a-f0-9]{64}$/.test(metadata.event_id))
    r.event_id = metadata.event_id;
  if (["acknowledged", "stopped", "pending"].includes(metadata.delivery_state))
    r.delivery_state = metadata.delivery_state;
  return r;
}
export async function diagnose(emit, host, stage, fn, metadata = {}) {
  const started = Date.now();
  const record = (error, meta) => {
    try {
      emit(diagnosticRecord(host, stage, started, error, meta));
    } catch {
      /* Telemetry failure must not alter operation or trigger retries. */
    }
  };
  try {
    const result = await fn();
    record(null, typeof metadata === "function" ? metadata(result) : metadata);
    return result;
  } catch (error) {
    record(error, {
      ...(typeof metadata === "function" ? {} : metadata),
      ...error?.diagnosticMetadata,
    });
    throw error;
  }
}
