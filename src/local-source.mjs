// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from "node:sqlite";

// Native T3 durable projections, opened read-only with WAL-aware short reads.
// This is observation only, never an alternate write or delegation transport.
export function localSource(path) {
  const db = new DatabaseSync(path, { readOnly: true });
  db.exec("PRAGMA query_only=ON; PRAGMA busy_timeout=2000;");
  const thread = db.prepare(
    "SELECT payload_json FROM orchestration_v2_projection_threads WHERE thread_id=? AND deleted_at IS NULL",
  );
  const runs = db.prepare(
    "SELECT payload_json FROM orchestration_v2_projection_runs WHERE thread_id=? ORDER BY ordinal DESC LIMIT 20",
  );
  const messages = db.prepare(
    "SELECT payload_json FROM orchestration_v2_projection_messages WHERE thread_id=? AND (? IS NULL OR run_id=?) ORDER BY created_at,message_id LIMIT 26 OFFSET ?",
  );
  return {
    supportsFollowup: false,
    async read(session, _activity = false, options = {}) {
      if (session.host !== "local") throw new Error("local_host_required");
      db.exec("BEGIN");
      try {
        const row = thread.get(session.threadId);
        if (!row) throw new Error("thread_not_found");
        const t = JSON.parse(row.payload_json);
        const recentRuns = runs.all(session.threadId).map((r) => JSON.parse(r.payload_json));
        if (t.id !== session.threadId || recentRuns.some((r) => r.threadId !== session.threadId))
          throw new Error("projection_identity_mismatch");
        const offset = options.afterPosition ?? 0,
          runId = options.runId ?? null;
        const rows = messages
          .all(session.threadId, runId, runId, offset)
          .map((r) => JSON.parse(r.payload_json));
        const items = rows.slice(0, 25).map((m, i) => ({
          itemId: m.id,
          messageId: m.id,
          runId: m.runId,
          position: offset + i,
          sourceThreadId: m.threadId,
          createdBy: m.createdBy,
          creationSource: m.creationSource,
          type: m.role === "assistant" ? "assistant_message" : "user_message",
          text: String(m.text ?? "").slice(0, 4000),
          textTruncated: String(m.text ?? "").length > 4000,
          status: m.streaming ? "running" : "completed",
        }));
        const active = recentRuns.find((r) =>
          ["preparing", "queued", "starting", "running", "waiting"].includes(r.status),
        );
        return {
          thread: {
            threadId: t.id,
            providerInstanceId: t.providerInstanceId,
            model: t.modelSelection?.model,
            runtimeMode: t.runtimeMode,
            parentThreadId: t.lineage?.parentThreadId ?? null,
            relationshipToParent: t.lineage?.relationshipToParent ?? null,
            latestRunId: recentRuns[0]?.id ?? null,
            activeRunId: active?.id ?? null,
            status: recentRuns[0]?.status ?? "idle",
          },
          recentRuns: recentRuns.map((r) => ({
            ...r,
            runId: r.id,
            model: r.modelSelection?.model,
          })),
          items,
          hasMore: rows.length > 25,
          nextPosition: rows.length > 25 ? offset + 25 : null,
        };
      } finally {
        db.exec("ROLLBACK");
      }
    },
    async followup() {
      throw new Error("local_source_is_read_only_use_native_t3_delegation");
    },
    close() {
      db.close();
    },
  };
}
