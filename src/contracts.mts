// SPDX-License-Identifier: AGPL-3.0-or-later
import type { spawn } from "node:child_process";
import type net from "node:net";
import type { Session } from "./config.mjs";

// Native projections and legacy encrypted records have version-dependent fields.
// Runtime schema and authorization checks remain mandatory; this migration does
// not claim a statically modeled native T3 protocol or persisted-record registry.
export type NativeRecord = Record<string, any>;
export interface ReadOptions {
  runId?: string;
  afterPosition?: number;
  owner?: string;
}
export type RelaySession = Session & { owner?: string; projectId?: string; dynamicLane?: boolean };
export interface Backend {
  supportsFollowup: boolean;
  read(session: NativeRecord, activity?: boolean, options?: ReadOptions): Promise<NativeRecord>;
  preflight?(session: NativeRecord, runId: string): Promise<void>;
  followup(
    session: NativeRecord,
    message?: string,
    requestId?: string,
    runId?: string,
  ): Promise<NativeRecord>;
  close(): void | Promise<unknown>;
}
export interface DiagnosticRecord {
  at: string;
  host: string;
  stage: string;
  origin: string;
  correlation_id: string;
  operation: string;
  duration_ms: number;
  outcome: string;
  reason: string | null;
  transport_code?: string;
  http_status?: number;
  credential_expires_at?: string;
  credential_source?: string;
  native_operation?: string;
  credential_status?: string;
  event_id?: string;
  delivery_state?: string;
  event_loop_delay_max_ms?: number;
  sync_operation?: string;
  sync_operation_max_ms?: number;
  process_cpu_user_ms?: number;
  process_cpu_system_ms?: number;
}
export interface TransportOptions {
  hostsFile?: string;
  tokensFile?: string;
  fetchImpl?: typeof fetch;
  spawnImpl?: typeof spawn;
  execFileImpl?: (
    file: string,
    args: string[],
    options: NativeRecord,
  ) => Promise<{ stdout: string | Buffer; stderr?: string | Buffer } | string>;
  netImpl?: typeof net;
  now?: () => number;
  sshBinary?: string;
  hostsProvider?: () => { hosts: NativeRecord[] };
  cacheProvider?: () => Record<string, NativeRecord>;
  preopenedHosts?: string[];
  runtimePortCache?: Map<string, { port: number; expiresAt: number }>;
  diagnostic?: (event: DiagnosticRecord) => void;
}
