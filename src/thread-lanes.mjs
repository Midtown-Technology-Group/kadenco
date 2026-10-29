// SPDX-License-Identifier: AGPL-3.0-or-later
import { subscriptionActive } from "./subscription-state.mjs";
import { createHash } from "node:crypto";
const hash = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const fail = (reason) => Object.assign(new Error(reason), { reason });

// A return lane is a native T3 user-input route owned by the subscription.
// Subscription and delivery records already supply persistence/retry; no caller
// token, provider config, task queue or alternate agent identity is created.
export class ThreadLanes {
  constructor(bridge) {
    this.bridge = bridge;
  }
  binding(owner, { host, thread_id }, projectId) {
    const b = this.bridge;
    if (!b.commands) throw fail("two_way_lane_unavailable");
    b.commands.grant(owner, host, projectId);
    const identity = hash([owner, host, thread_id]);
    return {
      host,
      threadId: thread_id,
      sessionId: "thread_" + identity.slice(0, 32),
      laneId: "lane_" + identity,
      ...(projectId ? { projectId } : {}),
    };
  }
  async prepare(owner, target) {
    const binding = this.binding(owner, target);
    const result = await this.bridge.commands.requests(
      owner,
      { host: binding.host, thread_id: binding.threadId },
      { forLane: true },
    );
    if (typeof result.project_id !== "string" || !result.project_id)
      throw fail("identity_mismatch");
    return this.binding(owner, target, result.project_id);
  }
  authorize(sub) {
    if (!sub.projectId) throw fail("forbidden");
    const binding = this.binding(
      sub.owner,
      { host: sub.host, thread_id: sub.threadId },
      sub.projectId,
    );
    if (binding.laneId !== sub.laneId || binding.sessionId !== sub.sessionId)
      throw fail("forbidden");
    return binding;
  }
  subscriptions(owner) {
    const b = this.bridge;
    return b.store
      .all("subscription")
      .filter(
        (s) =>
          s.name === "t3.thread.activity" &&
          (!owner || s.owner === owner) &&
          subscriptionActive(s, b.now()),
      )
      .filter((s) => {
        try {
          this.authorize(s);
          return true;
        } catch {
          return false;
        }
      });
  }
  sessions(owner) {
    return [
      ...new Map(
        this.subscriptions(owner).map((s) => [
          s.sessionId,
          {
            id: s.sessionId,
            host: s.host,
            threadId: s.threadId,
            projectId: s.projectId,
            observeAfter: s.observeAfter,
            owner: s.owner,
            dynamicLane: true,
          },
        ]),
      ).values(),
    ];
  }
  session(owner, id) {
    return this.sessions(owner).find((s) => s.id === id);
  }
  async read(session, activity = false, options = {}) {
    const bound = this.session(session.owner, session.id);
    if (!bound || bound.host !== session.host || bound.threadId !== session.threadId)
      throw fail("forbidden");
    const data = await this.bridge.fleetReads.read(session.owner, {
      host: session.host,
      thread_id: session.threadId,
      view: activity ? "activity" : "messages",
      ...(options.afterPosition !== undefined ? { after_position: options.afterPosition } : {}),
    });
    if (data.thread.projectId !== bound.projectId) throw fail("identity_mismatch");
    if (!this.session(session.owner, session.id)) throw fail("forbidden");
    return {
      ...data,
      recentRuns: data.runs,
      items: options.runId ? data.items.filter((i) => i.runId === options.runId) : data.items,
    };
  }
  get(owner, target) {
    const b = this.bridge,
      binding = this.binding(owner, target);
    const subscriptions = this.subscriptions(owner).filter(
      (s) =>
        s.sessionId === binding.sessionId &&
        s.laneId === binding.laneId &&
        s.host === binding.host &&
        s.threadId === binding.threadId,
    );
    b.store.audit("lane.read", binding.laneId, subscriptions.length ? "active" : "inactive");
    return {
      session_id: binding.sessionId,
      host: binding.host,
      thread_id: binding.threadId,
      lane_id: binding.laneId,
      state: subscriptions.length ? "active" : "inactive",
      project_id: subscriptions[0]?.projectId ?? null,
      expires_at:
        subscriptions.length && !subscriptions.some((s) => s.expires === null)
          ? new Date(Math.max(...subscriptions.map((s) => s.expires))).toISOString()
          : null,
      temporary_lease_expires_at: subscriptions.some((s) => s.leaseExpires !== undefined)
        ? new Date(
            Math.min(
              ...subscriptions
                .filter((s) => s.leaseExpires !== undefined)
                .map((s) => s.leaseExpires),
            ),
          ).toISOString()
        : null,
      mechanism: "native_user_input",
      instruction:
        "The T3 agent asks through its existing native question/user-input tool. On input_requested, read the exact native_request_id with read_thread_requests and inspect reply_contract. Live questions use answer_thread_request; an authorized message/asynchronous reply uses continue_thread with the exact question source_run_id, a stable UUID and execution=allow_new_turn. That starts a new turn and requires separate task authority. Unknown modes or missing source runs have no supported reply action. Permission approvals are excluded. No ask_eddie tool or per-host credential installation is needed. Subscribe to t3.thread.activity; completion-only t3.task.finished is legacy monitoring.",
    };
  }
  async pages(sub) {
    const binding = this.authorize(sub),
      all = [];
    let cursor;
    do {
      const page = await this.bridge.commands.requests(
        sub.owner,
        {
          host: binding.host,
          thread_id: binding.threadId,
          ...(cursor ? { after_request_id: cursor } : {}),
        },
        { forLane: true },
      );
      if (page.project_id !== binding.projectId) throw fail("identity_mismatch");
      this.authorize(sub);
      all.push(...page.requests);
      if (
        page.next_cursor !== null &&
        page.next_cursor !== undefined &&
        (!page.next_cursor || (cursor && page.next_cursor <= cursor))
      )
        throw fail("source_unavailable");
      cursor = page.next_cursor;
    } while (cursor);
    return all;
  }
  async observe(session, data) {
    const b = this.bridge;
    if (
      data.thread.pendingRequestCount === 0 ||
      (!data.thread.activeRunId && !data.thread.pendingRequestCount)
    )
      return;
    for (const sub of b.store
      .all("subscription")
      .filter(
        (s) =>
          s.name === "t3.thread.activity" &&
          s.sessionId === session.id &&
          subscriptionActive(s, b.now()),
      )) {
      try {
        for (const request of await this.pages(sub)) {
          if (!request.run_id) continue;
          const eventId =
            "evt_" +
            hash([
              "t3.thread.activity",
              session.host,
              session.threadId,
              session.id,
              request.native_request_id,
            ]);
          const id = sub.id + ":" + eventId;
          if (
            b.store.insert("delivery", id, {
              id,
              subId: sub.id,
              event: {
                eventId,
                name: "t3.thread.activity",
                timestamp: new Date(b.now()).toISOString(),
                data: {
                  session_id: session.id,
                  host: session.host,
                  thread_id: session.threadId,
                  lane_id: sub.laneId,
                  kind: "input_requested",
                  run_id: request.run_id,
                  native_request_id: request.native_request_id,
                  live_answer_allowed: request.live_answer_allowed,
                },
                cursor: null,
              },
              attempts: 0,
              nextAt: b.now(),
              status: "pending",
            })
          )
            b.store.audit("lane.question", eventId, "observed");
        }
      } catch (e) {
        b.store.audit(
          "lane.observe",
          sub.laneId,
          e.reason === "forbidden" ? "revoked" : "unavailable",
        );
      }
    }
  }
  async deliverable(sub, event) {
    this.authorize(sub);
    if (
      event.data.kind === "input_requested" &&
      !(await this.pages(sub)).some(
        (r) =>
          r.native_request_id === event.data.native_request_id && r.run_id === event.data.run_id,
      )
    )
      throw fail("input_request_not_pending");
  }
}
