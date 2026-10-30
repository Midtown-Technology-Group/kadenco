// SPDX-License-Identifier: AGPL-3.0-or-later
import { z } from "zod";
import { createHash } from "node:crypto";
import { HostCallers } from "./host-callers.mjs";
import { Collaboration } from "./collaboration.mjs";

const request = z
  .object({ thread_id: z.string().min(1).max(2048), request_id: z.string().uuid().toLowerCase() })
  .strict();
export const sharingRequestArgs = request.extend({
  run_id: z.string().min(1).max(2048),
  email: z
    .string()
    .trim()
    .email()
    .max(254)
    .transform((v) => v.toLowerCase()),
  reason: z.string().trim().min(1).max(500),
});
export const sharingReceiptArgs = request;
export const sharingDecisionArgs = z
  .object({ request_id: z.string().uuid().toLowerCase(), decision: z.enum(["approve", "decline"]) })
  .strict();
const fail = (reason) => Object.assign(new Error(reason), { reason });
const hash = (p) => createHash("sha256").update(JSON.stringify(p)).digest("hex");

/** Requests are evidence for a human review, never authority to grant access. */
export class SharingRequests {
  constructor(public bridge) {}
  collaboration() {
    return new Collaboration({
      policy: this.bridge.policy,
      store: this.bridge.store,
      reader: this.bridge.fleetReads,
      commands: this.bridge.commands,
      now: this.bridge.now,
    });
  }
  binding(owner) {
    const g = new HostCallers(this.bridge).grant(owner);
    return { host: g.host, reviewer: g.reviewer };
  }
  authorizeRecord(r) {
    const g = this.binding(r.owner);
    if (
      g.host !== r.host ||
      g.reviewer !== r.reviewer ||
      r.identity_scope !== this.collaboration().identityScope()
    )
      throw fail("forbidden");
    this.bridge.fleetReads.grant(g.reviewer, g.host, r.project_id);
  }
  receipt(r) {
    this.authorizeRecord(r);
    return {
      request_id: r.id,
      host: r.host,
      thread_id: r.thread_id,
      run_id: r.run_id,
      email: r.email,
      reason: r.reason,
      state: r.expires_at <= this.bridge.now() && r.state === "pending" ? "expired" : r.state,
      expires_at: r.expires_at,
      review_url:
        this.collaboration().config().origin +
        "/collaborate/#" +
        new URLSearchParams({ host: r.host, thread_id: r.thread_id, sharing_request_id: r.id }),
      ...(r.invitation_id ? { invitation_id: r.invitation_id } : {}),
      execution_started: false,
    };
  }
  async create(owner, input) {
    const p = sharingRequestArgs.parse(input),
      binding = this.binding(owner),
      scope = this.collaboration().identityScope(),
      digest = hash(p);
    const prior = this.bridge.store.get("collaboration.access-request", p.request_id);
    if (prior) {
      if (prior.owner !== owner || prior.digest !== digest) throw fail("idempotency_conflict");
      return this.receipt(prior);
    }
    const identity = new HostCallers(this.bridge).identity(owner, p.thread_id);
    const source = await this.bridge.exchanges.source(identity, {
      caller: identity,
      reviewer: binding.reviewer,
      host: binding.host,
      thread_id: p.thread_id,
    });
    if (
      source.thread.threadId !== p.thread_id ||
      source.thread.activeRunId !== p.run_id ||
      source.thread.archived
    )
      throw fail("source_run_not_active");
    return this.bridge.store.transaction(() => {
      const current = this.binding(owner);
      if (
        current.host !== binding.host ||
        current.reviewer !== binding.reviewer ||
        this.collaboration().identityScope() !== scope
      )
        throw fail("forbidden");
      this.bridge.fleetReads.grant(current.reviewer, current.host, source.thread.projectId);
      const existing = this.bridge.store.get("collaboration.access-request", p.request_id);
      if (existing) {
        if (existing.owner !== owner || existing.digest !== digest)
          throw fail("idempotency_conflict");
        return this.receipt(existing);
      }
      const pending = this.bridge.store
        .all("collaboration.access-request")
        .filter(
          (r) =>
            r.owner === owner &&
            r.expires_at > this.bridge.now() &&
            ["pending", "approving"].includes(r.state),
        );
      if (pending.length >= 20) throw fail("pending_limit");
      const r = {
        ...p,
        id: p.request_id,
        owner,
        ...binding,
        project_id: source.thread.projectId,
        identity_scope: scope,
        digest,
        state: "pending",
        expires_at: this.bridge.now() + 86400000,
        at: this.bridge.now(),
      };
      this.bridge.store.put("collaboration.access-request", r.id, r);
      this.bridge.store.audit("collaboration.access-request", r.id, "pending");
      return this.receipt(r);
    });
  }
  get(owner, input) {
    const p = sharingReceiptArgs.parse(input),
      r = this.bridge.store.get("collaboration.access-request", p.request_id);
    if (!r || r.owner !== owner || r.thread_id !== p.thread_id) throw fail("forbidden");
    return this.receipt(r);
  }
  review(user, id) {
    const service = this.collaboration();
    if (!service.admin(user)) throw fail("forbidden");
    const r = this.bridge.store.get("collaboration.access-request", z.string().uuid().parse(id));
    if (!r) throw fail("not_found");
    const receipt = this.receipt(r);
    service.reader.grant(service.config().brokerPrincipal, r.host, r.project_id);
    return receipt;
  }
  async decide(user, input) {
    const p = sharingDecisionArgs.parse(input);
    this.review(user, p.request_id);
    const r = this.bridge.store.transaction(() => {
      this.review(user, p.request_id);
      const r = this.bridge.store.get("collaboration.access-request", p.request_id);
      if (r.state === "approved" || r.state === "declined") {
        if ((r.state === "approved") !== (p.decision === "approve"))
          throw fail("idempotency_conflict");
        return r;
      }
      if (r.expires_at <= this.bridge.now()) throw fail("invalid_expiry");
      if (r.state === "approving" && p.decision !== "approve") throw fail("request_in_progress");
      const next = {
        ...r,
        state: p.decision === "decline" ? "declined" : "approving",
        decided_by: user.subject,
        invitation_expires_at:
          r.invitation_expires_at ?? Math.min(r.expires_at, this.bridge.now() + 82800000),
      };
      this.bridge.store.put("collaboration.access-request", r.id, next);
      this.bridge.store.audit("collaboration.access-request.decision", r.id, next.state);
      return next;
    });
    if (r.state !== "approving") return this.receipt(r);
    // Same UUID and immutable expiry reconcile uncertain invitation creation.
    await this.collaboration().invite(
      user,
      {
        host: r.host,
        thread_id: r.thread_id,
        request_id: r.id,
        email: r.email,
        expires_at: r.invitation_expires_at,
      },
      (source) => {
        this.review(user, r.id);
        if (source && source.thread.projectId !== r.project_id) throw fail("identity_mismatch");
      },
    );
    return this.bridge.store.transaction(() => {
      this.review(user, r.id);
      const current = this.bridge.store.get("collaboration.access-request", r.id);
      const approved = { ...current, state: "approved", invitation_id: r.id };
      this.bridge.store.put("collaboration.access-request", r.id, approved);
      this.bridge.store.audit("collaboration.access-request.decision", r.id, "approved");
      return this.receipt(approved);
    });
  }
}
