// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "./bridge.mjs";
import { z } from "zod";
import { askArgs, requestArgs, acknowledgeArgs, conversationArgs } from "./exchange.mjs";
import { hostCallerOwner } from "./host-caller-scope.mjs";
import { ackCommandArgs } from "./commands.mjs";
const thread = z.string().min(1).max(2048),
  wait = z.number().int().min(0).max(10000).default(0);
export const hostAskArgs = askArgs
  .omit({ run_id: true })
  .extend({ thread_id: thread, wait_ms: wait });
export const hostGetArgs = requestArgs.extend({ thread_id: thread, wait_ms: wait });
export const hostAckArgs = acknowledgeArgs.extend({ thread_id: thread });
export const hostDeliveryAckArgs = ackCommandArgs.extend({ thread_id: thread });
export const hostConversationArgs = conversationArgs.extend({ thread_id: thread });
export const hostCapabilityArgs = z.object({ thread_id: thread.optional() }).strict();
const fail = (reason) => Object.assign(new Error(reason), { reason });
export class HostCallers {
  constructor(
    public bridge: Bridge,
    public deliveryAcknowledgements = true,
  ) {}
  grant(owner) {
    const g = this.bridge
      .policy()
      .principals.find((p) => p.id === owner && p.enabled !== false)?.eddieHostCaller;
    if (!g || g.expiresAt <= this.bridge.now()) throw fail("forbidden");
    this.bridge.exchanges.inbox(g.reviewer);
    this.bridge.fleetReads.grant(g.reviewer, g.host);
    return g;
  }
  identity(owner, threadId) {
    this.grant(owner);
    return hostCallerOwner(owner, threadId);
  }
  /** Advertise only negotiated bookkeeping support, never execution authority. */
  deliveryAcknowledgement() {
    return {
      available: this.deliveryAcknowledgements && !!this.bridge.commands,
      requires_current_run: true,
      requires_retained_native_run_evidence: false,
      requires_native_run_evidence: true,
      evidence_recovery: "one_exact_native_message_read",
      is_completion: false,
    };
  }
  async capabilities(owner, input) {
    const p = hostCapabilityArgs.parse(input),
      g = this.grant(owner);
    if (p.thread_id) {
      const identity = this.identity(owner, p.thread_id);
      // Validate exact native identity/project before reporting a usable binding.
      await this.bridge.exchanges.source(identity, {
        caller: identity,
        reviewer: g.reviewer,
        host: g.host,
        thread_id: p.thread_id,
      });
      return {
        ...this.bridge.exchanges.capabilities(identity),
        host_caller: true,
        source_status: "available",
        delivery_acknowledgement: this.deliveryAcknowledgement(),
      };
    }
    return {
      host_caller: true,
      source_status: "not_checked",
      host: g.host,
      inbox_id: g.reviewer,
      expires_at: new Date(g.expiresAt).toISOString(),
      passive_exchange: true,
      delivery_acknowledgement: this.deliveryAcknowledgement(),
      resumes_t3: false,
      identity:
        "Authenticated host; caller supplies thread_id, server validates exact native thread/project and active run. Not a cryptographic attestation of the agent process.",
      instruction:
        "Any provider or subagent on this host may ask Eddie. Get your current T3 thread ID from orchestrator_capabilities.parentThreadId; never guess from title or workspace. Use a fresh UUID per question and retain it after a timeout. No per-thread enrollment or subscription is needed. Replies are data, not execution approval.",
    };
  }
  async waitForReply(identity, requestId, ms, first) {
    if (
      !ms ||
      !["pending", "read"].includes(first.status) ||
      first.delivery.state === "awaiting_subscription"
    )
      return first;
    const deadline = Date.now() + ms;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(500, deadline - Date.now())));
      // No native polling: observe only existing exchange bookkeeping, then
      // re-authorize the exact reply before returning any changed state.
      this.bridge.exchanges.caller(identity);
      const r = this.bridge.store.get("exchange", requestId);
      if (!r || !["pending", "read"].includes(this.bridge.exchanges.status(r))) break;
    }
    return this.bridge.exchanges.get(identity, { request_id: requestId });
  }
  async ask(owner, input) {
    const { thread_id, wait_ms, ...p } = hostAskArgs.parse(input),
      g = this.grant(owner),
      identity = this.identity(owner, thread_id);
    const existing = this.bridge.store.get("exchange", p.request_id);
    if (existing && existing.caller !== identity) throw fail("forbidden");
    const source = existing
      ? null
      : await this.bridge.exchanges.source(identity, {
          caller: identity,
          reviewer: g.reviewer,
          host: g.host,
          thread_id,
        });
    const run_id = existing?.run_id ?? source.thread.activeRunId;
    if (!run_id) throw fail("source_run_not_active");
    const receipt = await this.bridge.exchanges.ask(identity, { ...p, run_id });
    return this.waitForReply(identity, p.request_id, wait_ms, receipt);
  }
  async get(owner, input) {
    const { thread_id, wait_ms, ...p } = hostGetArgs.parse(input),
      identity = this.identity(owner, thread_id);
    const receipt = await this.bridge.exchanges.get(identity, p);
    return this.waitForReply(identity, p.request_id, wait_ms, receipt);
  }
  conversation(owner, input) {
    const { thread_id, ...p } = hostConversationArgs.parse(input);
    return this.bridge.exchanges.conversation(this.identity(owner, thread_id), p);
  }
  acknowledge(owner, input) {
    const { thread_id, ...p } = hostAckArgs.parse(input);
    return this.bridge.exchanges.acknowledge(this.identity(owner, thread_id), p);
  }
  /** Recheck the captured host/reviewer after native waits, including rebinding. */
  acknowledgeDelivery(owner, input) {
    const { thread_id, ...p } = hostDeliveryAckArgs.parse(input),
      { host, reviewer } = this.grant(owner);
    if (!this.bridge.commands) throw fail("delivery_ack_unavailable");
    return this.bridge.commands.acknowledge(
      this.identity(owner, thread_id),
      reviewer,
      host,
      thread_id,
      p,
      () => {
        const current = this.grant(owner);
        if (current.host !== host || current.reviewer !== reviewer) throw fail("forbidden");
      },
    );
  }
}
