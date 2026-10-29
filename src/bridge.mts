// SPDX-License-Identifier: AGPL-3.0-or-later
import type { NativeRecord, ReadOptions, RelaySession } from "./contracts.mjs";
import type { Store } from "./store.mjs";
import type { Policy } from "./config.mjs";
import type { FleetReader } from "./fleet-read.mjs";
import type { Commands } from "./commands.mjs";
import type { Backend } from "./contracts.mjs";
import {
  subscriptionActive,
  subscriptionState,
  subscriptionExpiry,
} from "./subscription-state.mjs";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { callbackUrl, signingKey, signedPost } from "./webhook.mjs";
import { Exchanges } from "./exchange.mjs";
import { ThreadLanes } from "./thread-lanes.mjs";
import { FleetEvents } from "./fleet-events.mjs";
import { diagnosticRecord } from "./diagnostics.mjs";

const terminal = new Set(["completed", "failed", "cancelled", "interrupted"]);
const hash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
export const MAX_ACTIVE_SUBSCRIPTIONS = 8;
export const FOLLOWUP =
  "Eddie integration validation: inspect only the immediately preceding assistant result already in this conversation. Reply with exactly EDDIE_T3_FOLLOWUP_OK. Do not use tools, execute commands, edit files, delegate, or contact anyone. Stop after this one reply.";

export class Bridge {
  declare store: Store;
  declare backend: Backend;
  declare policy: () => Policy;
  declare post: (url: string, headers: Record<string, string>, body: string) => Promise<unknown>;
  declare now: () => number;
  declare exchanges: Exchanges;
  declare lanes: ThreadLanes;
  declare fleetEvents: FleetEvents;
  declare fleetReads?: FleetReader;
  declare commands?: Commands;

  constructor({
    store,
    backend,
    policy,
    post,
    now = Date.now,
  }: {
    store: Store;
    backend: Backend;
    policy: () => Policy;
    post: Bridge["post"];
    now?: () => number;
  }) {
    Object.assign(this, { store, backend, policy, post, now });
    this.exchanges = new Exchanges(this);
    this.lanes = new ThreadLanes(this);
    this.fleetEvents = new FleetEvents(this);
  }
  grant(owner, sessionId): RelaySession {
    const p = this.policy();
    const principal = p.principals.find((x) => x.id === owner && x.enabled !== false);
    const session = p.sessions.find((x) => x.id === sessionId);
    if (principal && session && principal.sessions.includes(sessionId)) return session;
    const lane = this.lanes?.session(owner, sessionId);
    if (lane) return lane;
    throw new Error("forbidden");
  }
  sessions(owner) {
    return [
      ...this.policy().sessions.filter((s) => {
        try {
          this.grant(owner, s.id);
          return true;
        } catch {
          return false;
        }
      }),
      ...this.lanes.sessions(owner),
    ].map((s) => ({
      id: s.id,
      host: s.host,
      threadId: s.threadId,
      followup: {
        action: "verify_result",
        enabled: !!(
          s.followup?.dedicated &&
          s.followup.expiresAt > this.now() &&
          this.backend.supportsFollowup !== false
        ),
        remaining: s.followup
          ? Math.max(0, (s.followup.maxPerDay ?? 1) - this.dailySpent(s.id))
          : 0,
        expiresAt: s.followup?.expiresAt ?? null,
      },
    }));
  }
  dailySpent(sessionId) {
    const start = Date.parse(new Date(this.now()).toISOString().slice(0, 10) + "T00:00:00Z");
    return this.store
      .all("followup")
      .filter(
        (f) => f.sessionId === sessionId && (!Number.isFinite(f.createdAt) || f.createdAt >= start),
      ).length;
  }
  async read(owner, sessionId, activity = false, options: ReadOptions = {}) {
    const s = this.grant(owner, sessionId),
      data: NativeRecord = await (s.dynamicLane ? this.lanes : this.backend).read(s, activity, {
        ...options,
        owner,
      });
    if (data.thread?.threadId !== s.threadId) throw new Error("thread_identity_mismatch");
    this.grant(owner, sessionId); // revoked while waiting
    for (const f of this.store
      .all("followup")
      .filter((f) => f.owner === owner && f.sessionId === sessionId)) {
      if (!f.messageId) continue;
      const message = data.items?.find((i) => i.messageId === f.messageId);
      const runId = f.followupRunId ?? message?.runId;
      const run = data.recentRuns?.find((r) => r.runId === runId);
      const status =
        run?.status ?? (terminal.has(f.status) ? f.status : message ? "observed" : f.status);
      if (status !== f.status || (runId && runId !== f.followupRunId)) {
        this.store.put("followup", hash([owner, f.requestId]), {
          ...f,
          status,
          followupRunId: runId ?? null,
        });
        this.store.audit("followup.lifecycle", hash([owner, f.requestId]), status);
      }
    }
    data.followups = this.store
      .all("followup")
      .filter((f) => f.owner === owner && f.sessionId === sessionId);
    this.store.audit(activity ? "logs.read" : "result.read", `${owner}:${sessionId}`, "returned");
    if (options.runId && data.recentRuns?.some((r) => r.runId === options.runId))
      this.store.audit(
        activity ? "logs.run.read" : "result.run.read",
        options.runId,
        `${owner}:${sessionId}`,
      );
    return data;
  }
  eventGrant(owner, p) {
    if (p.name === "t3.fleet.activity") {
      if (p.arguments?.scope !== "authorized_fleet" || !this.fleetEvents.hosts(owner).length)
        throw Object.assign(Error("forbidden"), { reason: "forbidden" });
      return;
    }
    if (p.name === "t3.eddie.requested") return this.exchanges.inbox(owner, p.arguments.inbox_id);
    if (p.name === "t3.task.finished") return this.grant(owner, p.arguments.session_id);
    if (p.name === "t3.thread.activity") return this.lanes.binding(owner, p.arguments);
    throw new Error("unsupported_event");
  }
  subscriptionId(owner, p) {
    return (
      "sub_" +
      hash([
        owner,
        p.delivery.url,
        p.name,
        p.name === "t3.fleet.activity"
          ? { scope: p.arguments.scope }
          : p.name === "t3.eddie.requested"
            ? { inbox_id: p.arguments.inbox_id }
            : p.name === "t3.thread.activity"
              ? { host: p.arguments.host, thread_id: p.arguments.thread_id }
              : { session_id: p.arguments.session_id },
      ])
    );
  }
  inboxSubscriptions(owner) {
    this.exchanges.inbox(owner);
    const now = this.now(),
      subscriptions = this.store
        .all("subscription")
        .filter((s) => s.owner === owner && s.name === "t3.eddie.requested" && s.inboxId === owner)
        .map((s) => ({
          subscription_id: s.id,
          last_refreshed_at: s.refreshedAt ? new Date(s.refreshedAt).toISOString() : null,
          active: subscriptionActive(s, now),
          state: subscriptionState(s, now),
          expires_at: subscriptionExpiry(s),
          refresh_before: subscriptionExpiry(s),
          seconds_remaining:
            s.expires === null ? null : Math.max(0, Math.floor((s.expires - now) / 1000)),
        }));
    this.store.audit("subscription.status", owner, "returned");
    return {
      inbox_id: owner,
      observed_at: new Date(now).toISOString(),
      subscriptions,
      renewal:
        "ChatGPT refreshes using events/subscribe before refreshBefore with the same subscription identity. This tool only observes; it cannot renew, enable, rotate keys or extend execution grants.",
      execution_authority_changed: false,
      delivery_acknowledgement_is_agent_execution: false,
    };
  }
  async subscribe(owner, p) {
    this.eventGrant(owner, p);
    const lane =
      p.name === "t3.thread.activity" ? await this.lanes.prepare(owner, p.arguments) : null;
    if (p.delivery.mode !== "webhook") throw new Error("unsupported_event");
    try {
      callbackUrl(p.delivery.url, this.policy().callbackHosts);
    } catch {
      // Only the hostname is diagnostic data. Paths, queries and signing keys
      // can contain callback credentials and must never enter the audit/error.
      let hostname;
      try {
        const h = new URL(p.delivery.url).hostname;
        if (/^[a-z0-9.-]{1,253}$/.test(h)) hostname = h;
      } catch {}
      this.store.audit("subscription.callback", hostname ?? "invalid", "not_allowed");
      throw Object.assign(new Error("callback_not_allowed"), { callbackHostname: hostname });
    }
    signingKey(p.delivery.secret);
    const id = this.subscriptionId(owner, p),
      old = this.store.get("subscription", id),
      now = this.now();
    if (
      !subscriptionActive(old, now) &&
      this.store.all("subscription").filter((s) => s.owner === owner && subscriptionActive(s, now))
        .length >= MAX_ACTIVE_SUBSCRIPTIONS
    )
      throw new Error("subscription_limit");
    const candidate: NativeRecord = {
      id,
      owner,
      name: p.name,
      ...(p.name === "t3.eddie.requested"
        ? { inboxId: p.arguments.inbox_id }
        : { sessionId: p.arguments.session_id }),
      ...lane,
      ...(lane ? { observeAfter: old?.observeAfter ?? new Date(now).toISOString() } : {}),
      url: p.delivery.url,
      secret: p.delivery.secret,
    };
    if (p.name === "t3.fleet.activity") {
      candidate.scope = p.arguments.scope;
      candidate.observeAfter = old?.observeAfter ?? new Date(now).toISOString();
      delete candidate.sessionId;
    }
    const verificationId = hash([owner, p.delivery.url]);
    const cached = this.store.get("verification", verificationId);
    if (!cached || cached.expires <= now || cached.keyHash !== hash(candidate.secret)) {
      const challenge = randomUUID();
      try {
        const r = await signedPost(candidate, { type: "verification", challenge }, this.post, now);
        const echo = JSON.parse(r.body).challenge;
        if (
          r.status < 200 ||
          r.status >= 300 ||
          typeof echo !== "string" ||
          Buffer.byteLength(echo) !== Buffer.byteLength(challenge) ||
          !timingSafeEqual(Buffer.from(echo), Buffer.from(challenge)) ||
          this.now() - now > 10000
        )
          throw new Error();
      } catch {
        this.store.audit("subscription.verify", id, "failed");
        throw new Error("challenge_failed");
      }
      this.store.put("verification", verificationId, {
        id: verificationId,
        keyHash: hash(candidate.secret),
        expires: this.now() + 300000,
      });
    }
    this.eventGrant(owner, p);
    if (
      lane &&
      JSON.stringify(lane) !==
        JSON.stringify(this.lanes.binding(owner, p.arguments, lane.projectId))
    )
      throw new Error("forbidden");
    const ttl = Math.min(p.ttlMs ?? 86400000, 86400000);
    let expires = p.ttlMs === null ? null : this.now() + ttl;
    const rotated = old && old.secret !== candidate.secret;
    this.store.transaction(() => {
      // Re-read after asynchronous callback verification and serialize admission.
      // A refresh (even omitting lease_seconds) never extends a temporary lease.
      const current = this.store.get("subscription", id),
        seconds = p.name === "t3.thread.activity" ? p.arguments.lease_seconds : undefined;
      if (
        !subscriptionActive(current, this.now()) &&
        this.store
          .all("subscription")
          .filter((s) => s.owner === owner && subscriptionActive(s, this.now())).length >=
          MAX_ACTIVE_SUBSCRIPTIONS
      )
        throw Error("subscription_limit");
      if (p.ttlMs === undefined && current?.expires === null && current.nonExpiring === true)
        expires = null;
      if (seconds !== undefined && (!Number.isInteger(seconds) || seconds < 60 || seconds > 3600))
        throw new Error("invalid_subscription_lease");
      if (seconds !== undefined && current && current.leaseExpires === undefined)
        throw new Error("standing_subscription_preserved");
      const leaseExpires =
        seconds !== undefined
          ? Math.min(current?.leaseExpires ?? Infinity, this.now() + seconds * 1000)
          : current?.leaseExpires;
      if (leaseExpires !== undefined) {
        if (leaseExpires <= this.now()) throw new Error("subscription_lease_expired");
        if (
          this.store
            .all("subscription")
            .some(
              (s) =>
                s.id !== id &&
                s.owner === owner &&
                subscriptionActive(s, this.now()) &&
                s.leaseExpires !== undefined,
            )
        )
          throw new Error("temporary_lane_limit");
        expires = expires === null ? leaseExpires : Math.min(expires, leaseExpires);
      }
      const sub = {
        ...candidate,
        active: true,
        expires,
        refreshedAt: now,
        ...(expires === null ? { nonExpiring: true } : {}),
        ...(leaseExpires !== undefined ? { leaseExpires } : {}),
        oldSecret: rotated ? old.secret : old?.oldSecret,
        rotateUntil: rotated ? this.now() + 300000 : old?.rotateUntil,
      };
      this.store.put("subscription", id, sub);
      if (p.name === "t3.eddie.requested") this.exchanges.catchup(sub);
      this.store.audit("subscription.active", id, "verified");
      if (lane) this.store.audit("lane.active", lane.laneId, "native_user_input");
    });
    return { id, refreshBefore: subscriptionExpiry({ expires }), cursor: null, truncated: false };
  }
  unsubscribe(owner, p) {
    this.eventGrant(owner, p);
    const id = this.subscriptionId(owner, p),
      s = this.store.get("subscription", id);
    if (s) this.store.put("subscription", id, { ...s, active: false });
    this.store.audit("subscription.stop", id, "inactive");
    return {};
  }
  async observe() {
    const sessions: RelaySession[] = [...this.policy().sessions, ...this.lanes.sessions()];
    for (const session of sessions) {
      if (
        !this.policy().principals.some((p) => {
          try {
            this.grant(p.id, session.id);
            return true;
          } catch {
            return false;
          }
        })
      )
        continue;
      let data;
      try {
        data = await (session.dynamicLane ? this.lanes : this.backend).read(session, false);
      } catch {
        this.store.audit("source.read", session.id, "unavailable");
        continue;
      }
      if (data.thread?.threadId !== session.threadId) {
        this.store.audit("source.read", session.id, "identity_mismatch");
        continue;
      }
      await this.lanes.observe(session, data);
      const runs = data.recentRuns ?? [];
      for (const run of runs) {
        if (
          !terminal.has(run.status) ||
          typeof run.runId !== "string" ||
          !run.runId ||
          !Number.isFinite(Date.parse(run.completedAt))
        )
          continue;
        const eventId = "evt_" + hash([session.host, session.threadId, run.runId]);
        // Only observe transitions after enrollment; bootstrap history is not a new finish.
        const seenKey = "run_" + hash([session.host, session.threadId, session.id, run.runId]);
        const seen = this.store.get("run", seenKey);
        if (seen) continue;
        const event: NativeRecord = {
          eventId,
          name: "t3.task.finished",
          timestamp: run.completedAt,
          data: { session_id: session.id, run_id: run.runId, status: run.status },
          cursor: null,
        };
        this.store.transaction(() => {
          this.store.put("run", seenKey, { runId: run.runId, sessionId: session.id });
          if (Date.parse(run.completedAt) < Date.parse(session.observeAfter)) return;
          for (const sub of this.store.all("subscription")) {
            if (
              !subscriptionActive(sub, this.now()) ||
              sub.name === "t3.eddie.requested" ||
              sub.sessionId !== session.id
            )
              continue;
            try {
              this.grant(sub.owner, session.id);
            } catch {
              continue;
            }
            let outgoing: NativeRecord = event;
            if (sub.name === "t3.thread.activity") {
              try {
                this.lanes.authorize(sub);
              } catch {
                continue;
              }
              outgoing = {
                ...event,
                eventId:
                  "evt_" +
                  hash([
                    "t3.thread.activity",
                    session.host,
                    session.threadId,
                    session.id,
                    run.runId,
                  ]),
                name: "t3.thread.activity",
                data: {
                  ...event.data,
                  host: session.host,
                  thread_id: session.threadId,
                  lane_id: sub.laneId,
                  kind: "task_finished",
                },
              };
            }
            this.store.insert("delivery", `${sub.id}:${outgoing.eventId}`, {
              id: `${sub.id}:${outgoing.eventId}`,
              subId: sub.id,
              event: outgoing,
              attempts: 0,
              nextAt: this.now(),
              status: "pending",
            });
          }
          this.store.audit("task.finished", eventId, run.status);
        });
      }
    }
  }
  async deliver() {
    for (const d of this.store.all("delivery")) {
      if (d.status !== "pending" || d.nextAt > this.now()) continue;
      const s = this.store.get("subscription", d.subId);
      let authorized = subscriptionActive(s, this.now());
      try {
        if (s?.name === "t3.eddie.requested") await this.exchanges.deliverable(s, d.event);
        else if (s?.name === "t3.fleet.activity") await this.fleetEvents.deliverable(s, d.event);
        else if (s?.name === "t3.thread.activity") await this.lanes.deliverable(s, d.event);
        else this.grant(s?.owner, s?.sessionId);
      } catch (e) {
        // A native source outage must not permanently discard an exchange.
        if (
          authorized &&
          ["t3.eddie.requested", "t3.thread.activity", "t3.fleet.activity"].includes(s?.name) &&
          ![
            "forbidden",
            "input_request_not_pending",
            "provider_not_authorized",
            "thread_unavailable",
            "identity_mismatch",
          ].includes(e.reason)
        ) {
          this.store.put("delivery", d.id, { ...d, nextAt: this.now() + 30000 });
          this.store.audit(
            s.name === "t3.thread.activity" ? "lane.delivery" : "exchange.delivery",
            d.event.data.request_id ?? d.event.eventId,
            "source_unavailable",
          );
          continue;
        }
        authorized = false;
      }
      // Policy or subscription may have changed during the source read.
      const refreshed = this.store.get("subscription", d.subId);
      authorized = authorized && subscriptionActive(refreshed, this.now());
      if (!authorized) {
        this.store.put("delivery", d.id, { ...d, status: "revoked" });
        continue;
      }
      const attempts = d.attempts + 1;
      // Persist attempts before I/O. A crash can repeat a webhook, always with the same event ID.
      const sending = {
        ...d,
        attempts,
        nextAt: this.now() + Math.min(3600000, 1000 * 2 ** attempts),
      };
      this.store.put("delivery", d.id, sending);
      const deliveryStarted = Date.now();
      let status = 0;
      try {
        status = (await signedPost(s, d.event, this.post, this.now())).status;
      } catch {}
      const state =
        status >= 200 && status < 300
          ? "acknowledged"
          : attempts >= 6 || (status >= 300 && status < 500 && ![408, 429].includes(status))
            ? "stopped"
            : "pending";
      this.store.put("delivery", d.id, { ...sending, status: state, httpStatus: status });
      this.store.audit("webhook.delivery", d.id, `${state}:${status}`);
      const diagnosticHost = s.host ?? d.event.data?.host;
      if (typeof diagnosticHost === "string") {
        try {
          this.store.diagnostic(
            diagnosticRecord(
              diagnosticHost,
              "webhook",
              deliveryStarted,
              state === "acknowledged" ? null : { reason: "source_unavailable" },
              { http_status: status, event_id: d.event.eventId, delivery_state: state },
            ),
          );
        } catch {
          /* Diagnostics never change delivery or retry policy. */
        }
      }
      if (status === 410) this.store.put("subscription", s.id, { ...s, active: false });
    }
  }
  async followup(owner, { session_id, run_id, request_id }) {
    const session = this.grant(owner, session_id),
      key = hash([owner, request_id]);
    const existing = this.store.get("followup", key);
    if (existing) {
      if (existing.sessionId !== session_id || existing.runId !== run_id)
        throw new Error("idempotency_conflict");
      return existing;
    }
    const g = session.followup;
    if (!g || !g.dedicated || g.expiresAt <= this.now() || g.action !== "verify_result")
      throw new Error("followup_not_authorized");
    if (this.backend.supportsFollowup === false)
      throw new Error("followup_transport_not_authorized");
    const source = await this.read(owner, session_id);
    const prior = this.store.all("followup").filter((f) => f.sessionId === session_id);
    if (prior.some((f) => f.followupRunId === run_id))
      throw new Error("followup_of_followup_denied");
    if (prior.some((f) => f.status === "submission_uncertain"))
      throw new Error("unresolved_submission");
    if (
      source.thread.activeRunId ||
      source.thread.latestRunId !== run_id ||
      !source.recentRuns.some((r) => r.runId === run_id && r.status === "completed") ||
      source.thread.providerInstanceId !== g.providerInstanceId ||
      source.thread.model !== g.model ||
      g.providerInstanceId !== "opencode" ||
      source.thread.runtimeMode !== "approval-required"
    )
      throw new Error("followup_boundary_denied");
    await this.backend.preflight?.(session, run_id); // known auth/source failures must not spend the one-send allowance
    const refreshed = this.grant(owner, session_id).followup;
    if (
      !refreshed ||
      !refreshed.dedicated ||
      refreshed.expiresAt <= this.now() ||
      JSON.stringify(refreshed) !== JSON.stringify(g)
    )
      throw new Error("followup_grant_changed");
    const record = {
      owner,
      requestId: request_id,
      sessionId: session_id,
      runId: run_id,
      createdAt: this.now(),
      status: "submission_uncertain",
      action: "verify_result",
    };
    this.store.transaction(() => {
      if (this.store.get("followup", key)) throw new Error("concurrent_followup");
      if (
        this.store.all("followup").some((f) => f.sessionId === session_id && f.runId === run_id) ||
        this.dailySpent(session_id) >= (g.maxPerDay ?? 1)
      )
        throw new Error("followup_budget_exhausted");
      this.store.put("followup", key, record); // one per source run, bounded daily, across restarts
      this.store.audit("followup.reserve", key, "one_reply_no_tools");
    });
    try {
      const receipt = await this.backend.followup(session, FOLLOWUP, request_id, run_id);
      if (receipt.threadId !== session.threadId || !receipt.messageId) throw new Error();
      const result = {
        ...record,
        status: "accepted",
        messageId: receipt.messageId,
        followupRunId: receipt.runId ?? null,
      };
      this.store.put("followup", key, result);
      this.store.audit("followup.accepted", key, "execution_unconfirmed");
      return result;
    } catch {
      this.store.audit("followup.submit", key, "uncertain_no_resend");
      return record;
    }
  }
}
