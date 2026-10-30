// SPDX-License-Identifier: AGPL-3.0-or-later
import type { NativeRecord } from "./contracts.mjs";
import type { Store } from "./store.mjs";
import type { Policy } from "./config.mjs";
import type { FleetReader } from "./fleet-read.mjs";
import type { Commands } from "./commands.mjs";
// Restricted human collaboration. No browser receives a broker/native credential.
import { createHash } from "node:crypto";
import { z } from "zod";

const text = z.string().trim().min(1),
  id = text.max(2048),
  subject = text.max(200);
const target = { host: text.max(100), thread_id: id };
export const targetArgs = z.object(target).strict();
export const grantArgs = z
  .object({
    ...target,
    subject,
    expected_revision: z.number().int().min(0),
    capabilities: z.array(z.enum(["view", "propose", "send", "review"])).max(4),
    expires_at: z.number().int().positive(),
  })
  .strict()
  .refine(
    (p) =>
      new Set(p.capabilities).size === p.capabilities.length &&
      (!p.capabilities.length || p.capabilities.includes("view")) &&
      (!p.capabilities.includes("send") || p.capabilities.includes("propose")),
  );
export const invitationArgs = targetArgs
  .extend({
    request_id: z.string().uuid().toLowerCase(),
    email: z
      .string()
      .trim()
      .email()
      .max(254)
      .transform((v) => v.toLowerCase()),
    expires_at: z.number().int().positive(),
  })
  .strict();
export const claimArgs = targetArgs
  .extend({ invitation_id: z.string().uuid().toLowerCase() })
  .strict();
export const messageArgs = z
  .object({
    ...target,
    request_id: z.string().uuid().toLowerCase(),
    text: text.max(4000),
    intent: z.enum(["propose", "send"]),
    source_run_id: id.optional(),
  })
  .strict()
  .refine((p) => p.intent !== "send" || !!p.source_run_id);
export const decisionArgs = z
  .object({
    ...target,
    message_id: text.regex(/^[a-f0-9]{64}$/),
    action: z.enum(["send", "dismiss"]),
    source_run_id: id.optional(),
  })
  .strict()
  .refine((p) => p.action !== "send" || !!p.source_run_id);
const digest = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const fail = (reason) => Object.assign(new Error(reason), { reason });
const publicReceipt = (r) => ({
  message_id: r.id,
  host: r.host,
  thread_id: r.thread_id,
  sender: r.sender,
  sender_email: r.sender_email ?? null,
  text: r.text,
  state: r.state,
  created_at: r.at,
  reviewer: r.reviewer ?? null,
  source_run_id: r.source_run_id ?? null,
  receipt: r.receipt ?? null,
  reason: r.reason ?? null,
  safe_to_resend: false,
});
const boundedReceipt = (r) =>
  Object.fromEntries(
    [
      "stored",
      "submission",
      "message_id",
      "run_id",
      "run_status",
      "terminal",
      "completed",
      "agent_acknowledged",
      "native_message_status",
      "run_bound",
      "run_status_fresh",
      "result",
      "result_fresh",
      "source_status",
      "safe_to_resend",
    ]
      .filter((k) => r[k] !== undefined)
      .map((k) => [k, r[k]]),
  );
function commandUuid(id) {
  const h = digest(["t3-collaboration", id]);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-5${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`;
}

export class Collaboration {
  declare policy: () => Policy;
  declare store: Store;
  declare reader: FleetReader;
  declare commands: Commands;
  declare now: () => number;

  constructor({ policy, store, reader, commands, now = Date.now }) {
    Object.assign(this, { policy, store, reader, commands, now });
  }
  config() {
    const p = this.policy(),
      c = p.collaboration;
    if (!c?.enabled) throw fail("sharing_disabled");
    const owner = p.principals.find((p) => p.id === c.brokerPrincipal && p.enabled !== false);
    if (!owner || owner.eddieCaller || owner.eddieHostCaller) throw fail("forbidden");
    return c;
  }
  identityScope() {
    const c = this.config();
    return digest([c.issuer, c.audience, c.identityProviderId]);
  }
  key(user, p) {
    return digest([this.identityScope(), user, p.host, p.thread_id]);
  }
  identityKey(subject) {
    return digest([this.identityScope(), subject]);
  }
  admin(user) {
    return (
      (user.expiresAt === undefined || user.expiresAt > this.now()) &&
      (!user.identity_scope || user.identity_scope === this.identityScope()) &&
      this.config().ownerSubjects.includes(user.subject)
    );
  }
  grant(user, p, cap = "view") {
    const c = this.config();
    this.reader.grant(c.brokerPrincipal, p.host);
    if (user.expiresAt !== undefined && user.expiresAt <= this.now())
      throw fail("authentication_required");
    if (user.identity_scope && user.identity_scope !== this.identityScope())
      throw fail("authentication_required");
    const g = this.store.get("collaboration.grant", this.key(user.subject, p));
    if (g?.project_id) this.reader.grant(c.brokerPrincipal, p.host, g.project_id);
    if (!this.admin(user) && (!g || g.expires_at <= this.now() || !g.capabilities.includes(cap)))
      throw fail("forbidden");
    if (!this.admin(user) && p.project_id !== undefined && g.project_id !== p.project_id)
      throw fail("identity_mismatch");
    return {
      config: c,
      revision: this.admin(user) ? "owner" : g.revision,
      projectId: g?.project_id,
    };
  }
  identity(user) {
    this.config();
    if (user.identity_scope && user.identity_scope !== this.identityScope())
      throw fail("authentication_required");
    this.store.put("collaboration.identity", this.identityKey(user.subject), {
      subject: user.subject,
      email: user.email,
      identity_scope: this.identityScope(),
    });
    return {
      subject: user.subject,
      email: user.email,
      owner: this.admin(user),
      identity_scope: this.identityScope(),
    };
  }
  list(user) {
    this.config();
    return this.store
      .all("collaboration.grant")
      .filter((g) => {
        if (
          g.identity_scope !== this.identityScope() ||
          g.subject !== user.subject ||
          g.expires_at <= this.now() ||
          !g.capabilities.includes("view")
        )
          return false;
        try {
          this.grant(user, g);
          return true;
        } catch {
          return false;
        }
      })
      .map((g) => ({
        host: g.host,
        thread_id: g.thread_id,
        capabilities: g.capabilities,
        expires_at: g.expires_at,
      }));
  }
  permissions(user, p) {
    this.grant(user, p);
    const g = this.store.get("collaboration.grant", this.key(user.subject, p));
    return {
      capabilities: this.admin(user) ? ["view", "propose", "send", "review"] : g.capabilities,
      owner: this.admin(user),
    };
  }
  async setGrant(user, input) {
    const p = grantArgs.parse(input),
      c = this.config();
    if (!this.admin(user)) throw fail("forbidden");
    if (p.expires_at > this.now() + 30 * 86400000 || p.expires_at <= this.now())
      throw fail("invalid_expiry");
    if (!this.store.get("collaboration.identity", this.identityKey(p.subject)))
      throw fail("identity_not_seen");
    const source = await this.reader.read(c.brokerPrincipal, {
      host: p.host,
      thread_id: p.thread_id,
    });
    if (source.thread.threadId !== p.thread_id || source.thread.archived)
      throw fail("thread_unavailable");
    return this.store.transaction(() => {
      if (!this.admin(user)) throw fail("forbidden");
      this.reader.grant(c.brokerPrincipal, p.host, source.thread.projectId);
      const old = this.store.get("collaboration.grant", this.key(p.subject, p));
      if ((old?.revision ?? 0) !== p.expected_revision) throw fail("revision_conflict");
      const record = {
        ...p,
        identity_scope: this.identityScope(),
        project_id: source.thread.projectId,
        revision: p.expected_revision + 1,
        changed_by: user.subject,
      };
      this.store.put("collaboration.grant", this.key(p.subject, p), record);
      this.store.audit(
        "collaboration.grant",
        this.key(p.subject, p),
        `${user.subject}:${record.revision}:${p.capabilities.join(",")}`,
      );
      return record;
    });
  }
  async invite(user, input) {
    const p = invitationArgs.parse(input),
      scope = this.identityScope();
    if (!this.admin(user)) throw fail("forbidden");
    if (p.expires_at <= this.now() || p.expires_at > this.now() + 86400000)
      throw fail("invalid_expiry");
    const existing = this.store.get("collaboration.invitation", p.request_id);
    const same = (r) =>
      r.identity_scope === scope && r.created_by === user.subject && r.digest === digest(p);
    if (existing) {
      if (!same(existing)) throw fail("idempotency_conflict");
      return existing;
    }
    const source = await this.reader.read(this.config().brokerPrincipal, {
      host: p.host,
      thread_id: p.thread_id,
    });
    if (source.thread.threadId !== p.thread_id || source.thread.archived)
      throw fail("thread_unavailable");
    return this.store.transaction(() => {
      if (!this.admin(user) || this.identityScope() !== scope) throw fail("forbidden");
      this.reader.grant(this.config().brokerPrincipal, p.host, source.thread.projectId);
      if (p.expires_at <= this.now()) throw fail("invalid_expiry");
      const prior = this.store.get("collaboration.invitation", p.request_id);
      if (prior) {
        if (!same(prior)) throw fail("idempotency_conflict");
        return prior;
      }
      const pending = this.store
        .all("collaboration.invitation")
        .filter(
          (r) =>
            r.identity_scope === scope &&
            r.host === p.host &&
            r.thread_id === p.thread_id &&
            r.state === "pending" &&
            r.expires_at > this.now(),
        );
      if (pending.length >= 20) throw fail("pending_limit");
      const record = {
        ...p,
        id: p.request_id,
        identity_scope: scope,
        project_id: source.thread.projectId,
        created_by: user.subject,
        digest: digest(p),
        state: "pending",
        at: this.now(),
      };
      this.store.put("collaboration.invitation", record.id, record);
      this.store.audit("collaboration.invite", record.id, "view,propose");
      return record;
    });
  }
  invitation(user, p) {
    const r = this.store.get("collaboration.invitation", p.invitation_id);
    if (
      !r ||
      r.identity_scope !== this.identityScope() ||
      r.host !== p.host ||
      r.thread_id !== p.thread_id ||
      r.email !== user.email.toLowerCase() ||
      r.expires_at <= this.now() ||
      !this.config().ownerSubjects.includes(r.created_by) ||
      !["pending", "claimed"].includes(r.state)
    )
      throw fail("invitation_unavailable");
    if (user.expiresAt !== undefined && user.expiresAt <= this.now())
      throw fail("authentication_required");
    if (user.identity_scope && user.identity_scope !== r.identity_scope)
      throw fail("authentication_required");
    if (r.claimed_by && r.claimed_by !== user.subject) throw fail("invitation_unavailable");
    return r;
  }
  async claim(user, input) {
    const p = claimArgs.parse(input),
      original = this.invitation(user, p);
    const source = await this.reader.read(this.config().brokerPrincipal, {
      host: p.host,
      thread_id: p.thread_id,
    });
    if (
      source.thread.threadId !== p.thread_id ||
      source.thread.projectId !== original.project_id ||
      source.thread.archived
    )
      throw fail("thread_unavailable");
    return this.store.transaction(() => {
      const r = this.invitation(user, p);
      this.reader.grant(this.config().brokerPrincipal, p.host, r.project_id);
      const key = this.key(user.subject, p),
        prior = this.store.get("collaboration.grant", key);
      if (r.state === "claimed") {
        if (prior?.invitation_id !== r.id || prior.revision !== r.grant_revision)
          throw fail("invitation_unavailable");
        this.grant(user, p, "propose");
        return {
          host: p.host,
          thread_id: p.thread_id,
          capabilities: prior.capabilities,
          expires_at: prior.expires_at,
        };
      }
      // An invitation never replaces or revives an existing owner-managed grant.
      if (prior) throw fail("grant_already_exists");
      const grant = {
        host: p.host,
        thread_id: p.thread_id,
        subject: user.subject,
        capabilities: ["view", "propose"],
        expires_at: r.expires_at,
        identity_scope: r.identity_scope,
        project_id: r.project_id,
        revision: 1,
        changed_by: r.created_by,
        invitation_id: r.id,
      };
      this.store.put("collaboration.grant", key, grant);
      this.store.put("collaboration.invitation", r.id, {
        ...r,
        state: "claimed",
        claimed_by: user.subject,
        grant_revision: 1,
      });
      this.store.audit("collaboration.invitation.claim", r.id, user.subject);
      return {
        host: p.host,
        thread_id: p.thread_id,
        capabilities: grant.capabilities,
        expires_at: grant.expires_at,
      };
    });
  }
  revokeInvitation(user, input) {
    const p = claimArgs.parse(input);
    if (!this.admin(user)) throw fail("forbidden");
    return this.store.transaction(() => {
      const r = this.store.get("collaboration.invitation", p.invitation_id);
      if (
        !r ||
        r.identity_scope !== this.identityScope() ||
        r.host !== p.host ||
        r.thread_id !== p.thread_id
      )
        throw fail("invitation_unavailable");
      const key = r.claimed_by && this.key(r.claimed_by, p),
        grant = key && this.store.get("collaboration.grant", key);
      if (grant?.invitation_id === r.id && grant.revision === r.grant_revision)
        this.store.put("collaboration.grant", key, {
          ...grant,
          capabilities: [],
          revision: grant.revision + 1,
          changed_by: user.subject,
        });
      this.store.put("collaboration.invitation", r.id, { ...r, state: "revoked" });
      this.store.audit("collaboration.invitation.revoke", r.id, user.subject);
      return { revoked: true };
    });
  }
  invitations(user, p) {
    if (!this.admin(user)) throw fail("forbidden");
    return this.store
      .all("collaboration.invitation")
      .filter(
        (r) =>
          r.identity_scope === this.identityScope() &&
          r.host === p.host &&
          r.thread_id === p.thread_id,
      );
  }
  administration(user, p) {
    if (!this.admin(user)) throw fail("forbidden");
    return {
      invitations: this.invitations(user, p),
      identities: this.store
        .all("collaboration.identity")
        .filter((i) => i.identity_scope === this.identityScope()),
      grants: this.store
        .all("collaboration.grant")
        .filter(
          (g) =>
            g.identity_scope === this.identityScope() &&
            g.host === p.host &&
            g.thread_id === p.thread_id,
        ),
    };
  }
  async view(user, input) {
    const p = targetArgs.parse(input),
      { config: c, revision } = this.grant(user, p);
    const page = await this.reader.read(c.brokerPrincipal, { ...p, view: "messages" });
    this.grant(user, p);
    if (this.grant(user, p).revision !== revision) throw fail("permissions_changed");
    if (
      page.thread.threadId !== p.thread_id ||
      (!this.admin(user) && this.grant(user, p).projectId !== page.thread.projectId)
    )
      throw fail("identity_mismatch");
    this.store.audit("collaboration.read", this.key(user.subject, p), user.subject);
    // Exact local user/assistant messages only. No plans, tools, reasoning or files.
    return {
      thread: {
        thread_id: p.thread_id,
        title: page.thread.title,
        status: page.thread.status,
        source_run_id: page.thread.latestRunId,
        model: page.thread.model,
      },
      items: page.items
        .filter((i) => ["user_message", "assistant_message"].includes(i.type))
        .map((i) => ({
          id: i.itemId,
          text: i.text,
          status: i.status,
          role: i.type === "user_message" ? "user" : "assistant",
          truncated: i.textTruncated,
        })),
      history:
        "Bounded recent local messages only; tools, reasoning, attachments and inherited histories excluded.",
      permissions: this.permissions(user, p),
    };
  }
  messages(user, input) {
    const p = targetArgs.parse(input);
    this.grant(user, p);
    let reviewer = true;
    try {
      this.grant(user, p, "review");
    } catch {
      reviewer = false;
    }
    return this.store
      .all("collaboration.message")
      .filter((r) => {
        if (
          r.identity_scope !== this.identityScope() ||
          r.host !== p.host ||
          r.thread_id !== p.thread_id ||
          (!reviewer && r.sender !== user.subject)
        )
          return false;
        try {
          this.reader.grant(this.config().brokerPrincipal, r.host, r.project_id);
          return true;
        } catch {
          return false;
        }
      })
      .sort((a, b) => a.at - b.at)
      .slice(-100)
      .map(publicReceipt);
  }
  async propose(user, input) {
    const p = messageArgs.parse(input);
    this.grant(user, p, p.intent === "send" ? "send" : "propose");
    const id = digest([this.identityScope(), user.subject, p.request_id]),
      bodyDigest = digest(p),
      old = this.store.get("collaboration.message", id);
    if (old) {
      if (old.digest !== bodyDigest) throw fail("idempotency_conflict");
      this.reader.grant(this.config().brokerPrincipal, old.host, old.project_id);
      return publicReceipt(old);
    }
    // Validate the exact target exists, inside broker read scope, before durable storage.
    const c = this.config(),
      source = await this.reader.read(c.brokerPrincipal, { host: p.host, thread_id: p.thread_id });
    if (source.thread.threadId !== p.thread_id || source.thread.archived)
      throw fail("thread_unavailable");
    if (!this.admin(user) && this.grant(user, p).projectId !== source.thread.projectId)
      throw fail("identity_mismatch");
    const selected = this.store.transaction(() => {
      this.grant(user, p, p.intent === "send" ? "send" : "propose");
      const prior = this.store.get("collaboration.message", id);
      if (prior) {
        if (prior.digest !== bodyDigest) throw fail("idempotency_conflict");
        return { record: prior, dispatch: false };
      }
      if (
        this.store
          .all("collaboration.message")
          .filter(
            (r) =>
              r.sender === user.subject &&
              r.host === p.host &&
              r.thread_id === p.thread_id &&
              r.state === "pending",
          ).length >= 3
      )
        throw fail("pending_limit");
      const r: NativeRecord = {
        ...p,
        id,
        identity_scope: this.identityScope(),
        digest: bodyDigest,
        sender: user.subject,
        sender_email: user.email,
        project_id: source.thread.projectId,
        at: this.now(),
        state: p.intent === "send" ? "reserved" : "pending",
        command_request_id: commandUuid(id),
      };
      if (p.intent === "send") {
        r.actor = user.subject;
        r.actor_expires_at = user.expiresAt;
        r.actor_revision = this.grant(user, p, "send").revision;
        r.sender_revision = this.grant(user, p, "view").revision;
        r.broker_principal = c.brokerPrincipal;
      }
      this.store.insert("collaboration.message", id, r);
      this.store.audit("collaboration.message", id, `${user.subject}:${r.state}`);
      return { record: r, dispatch: p.intent === "send" };
    });
    // Only the caller that changed missing -> reserved can dispatch. Concurrent
    // submissions reconcile the original command, never create another one.
    if (selected.dispatch) return this.dispatch(user, selected.record);
    return publicReceipt(selected.record);
  }
  async decide(user, input) {
    const p = decisionArgs.parse(input);
    this.grant(user, p, "review");
    const selected = this.store.transaction(() => {
      this.grant(user, p, "review");
      const r = this.store.get("collaboration.message", p.message_id);
      if (
        !r ||
        r.identity_scope !== this.identityScope() ||
        r.host !== p.host ||
        r.thread_id !== p.thread_id
      )
        throw fail("not_found");
      if (r.state !== "pending") return { record: r, dispatch: false };
      if (p.action === "send" && r.sender === user.subject) this.grant(user, r, "send");
      // A revoked original sender cannot have a queued proposal approved later.
      const sender = { subject: r.sender };
      if (p.action === "send") this.grant(sender, r, "propose");
      r.reviewer = user.subject;
      r.actor = user.subject;
      r.actor_expires_at = user.expiresAt;
      r.actor_revision = this.grant(user, r, "review").revision;
      r.sender_revision = p.action === "send" ? this.grant(sender, r, "propose").revision : null;
      r.broker_principal = this.config().brokerPrincipal;
      r.source_run_id = p.source_run_id ?? null;
      r.state = p.action === "send" ? "reserved" : "dismissed";
      this.store.put("collaboration.message", r.id, r);
      this.store.audit("collaboration.decision", r.id, `${user.subject}:${r.state}`);
      return { record: r, dispatch: p.action === "send" };
    });
    return selected.dispatch
      ? this.dispatch(user, selected.record)
      : publicReceipt(selected.record);
  }
  authorizeDispatch(record, { projectId = record.project_id } = {}) {
    const c = this.config(),
      current = this.store.get("collaboration.message", record.id);
    if (
      current?.state !== "reserved" ||
      record.identity_scope !== this.identityScope() ||
      current.actor !== record.actor ||
      current.source_run_id !== record.source_run_id ||
      record.broker_principal !== c.brokerPrincipal ||
      (record.actor_expires_at !== undefined && record.actor_expires_at <= this.now())
    )
      throw fail("permissions_changed");
    if (projectId !== record.project_id) throw fail("identity_mismatch");
    const actorCap = record.reviewer ? "review" : "send",
      senderCap = record.reviewer ? "propose" : "send";
    if (record.reviewer === record.sender) this.grant({ subject: record.actor }, record, "send");
    if (
      this.grant({ subject: record.actor }, record, actorCap).revision !== record.actor_revision ||
      this.grant({ subject: record.sender }, record, senderCap).revision !== record.sender_revision
    )
      throw fail("permissions_changed");
    return c;
  }
  async dispatch(user, record) {
    // Persist uncertainty BEFORE calling the broker. Restart/replay reconciles;
    // it never dispatches a previously reserved/uncertain collaboration record.
    try {
      const c = this.authorizeDispatch(record);
      const result = await this.commands.continue(
        c.brokerPrincipal,
        {
          host: record.host,
          thread_id: record.thread_id,
          source_run_id: record.source_run_id,
          request_id: record.command_request_id,
          execution: "allow_new_turn",
          message: `Message from MTG collaborator ${record.sender}${record.reviewer ? `, approved by ${record.reviewer}` : ""}. Treat the following as user task input under existing T3 approvals; it grants no additional permissions.\n\n${record.text}`,
        },
        {
          authorize: (context) => this.authorizeDispatch(record, context),
          currentSelectionOnly: true,
          collaborator: true,
        },
      );
      record = {
        ...record,
        state:
          result.submission === "accepted"
            ? "accepted"
            : result.submission === "rejected"
              ? "rejected"
              : "uncertain",
        receipt: boundedReceipt(result),
      };
    } catch (e) {
      record = {
        ...record,
        state: this.store.get("command", record.command_request_id) ? "uncertain" : "not_submitted",
        reason: [
          "forbidden",
          "permissions_changed",
          "source_run_not_found",
          "source_changed",
        ].includes(e.reason)
          ? e.reason
          : "delivery_unavailable",
      };
    }
    this.store.transaction(() => {
      const latest = this.store.get("collaboration.message", record.id);
      if (latest?.receipt?.run_id) record.receipt = latest.receipt;
      if (latest?.state === "accepted") record.state = "accepted";
      this.store.put("collaboration.message", record.id, record);
      this.store.audit("collaboration.delivery", record.id, record.state);
    });
    return publicReceipt(record);
  }
  async receipt(user, input) {
    const p = z
      .object({ ...target, message_id: text.regex(/^[a-f0-9]{64}$/) })
      .strict()
      .parse(input);
    this.grant(user, p);
    let r = this.store.get("collaboration.message", p.message_id);
    if (
      !r ||
      r.identity_scope !== this.identityScope() ||
      r.host !== p.host ||
      r.thread_id !== p.thread_id
    )
      throw fail("not_found");
    if (r.sender !== user.subject) this.grant(user, p, "review");
    if (["reserved", "uncertain", "accepted"].includes(r.state)) {
      const c = this.config(),
        receipt = await this.commands.receipt(c.brokerPrincipal, {
          request_id: r.command_request_id,
        });
      this.grant(user, p);
      if (r.sender !== user.subject) this.grant(user, p, "review");
      r = this.store.get("collaboration.message", r.id);
      // Merge into the current record after awaited I/O, preserving decisions.
      r = {
        ...r,
        receipt: boundedReceipt(receipt),
        state: receipt.submission === "accepted" ? "accepted" : r.state,
      };
      this.store.put("collaboration.message", r.id, r);
    }
    return publicReceipt(r);
  }
}
