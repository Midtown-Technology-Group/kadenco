// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ReadOptions, Backend } from "./contracts.mjs";
// Remote enrolled sessions reuse the same authorized, read-only fleet reader
// as inventory. No new credentials, scheduler, queue or execution path.
export function withFleetSessions(source: Backend, reader, policy) {
  const local = (session) => {
    if (session.host !== "local") throw new Error("remote_followup_not_authorized");
    return source;
  };
  return {
    ...source,
    async read(session, activity = false, options: ReadOptions = {}) {
      if (session.host === "local") return source.read(session, activity, options);
      const p = policy(),
        enrolled = p.sessions.find((s) => s.id === session.id);
      if (!enrolled || enrolled.host !== session.host || enrolled.threadId !== session.threadId)
        throw new Error("forbidden");
      const principal = p.principals.find(
        (x) =>
          x.enabled !== false &&
          x.sessions.includes(session.id) &&
          (!options.owner || x.id === options.owner) &&
          x.readHosts?.some((g) => g.host === session.host),
      );
      if (!reader || !principal) throw new Error("forbidden");
      const data = await reader.read(principal.id, {
        host: session.host,
        thread_id: session.threadId,
        view: activity ? "activity" : "messages",
        ...(options.afterPosition !== undefined ? { after_position: options.afterPosition } : {}),
      });
      return {
        ...data,
        recentRuns: data.runs,
        items: options.runId ? data.items.filter((i) => i.runId === options.runId) : data.items,
      };
    },
    preflight: (session, ...args: [string]) => local(session).preflight?.(session, ...args),
    followup: (session, ...args: [string?, string?, string?]) =>
      local(session).followup(session, ...args),
  };
}
