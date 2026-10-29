// SPDX-License-Identifier: AGPL-3.0-or-later
import { subscriptionState, subscriptionExpiry } from "./subscription-state.mjs";
import { MAX_ACTIVE_SUBSCRIPTIONS } from "./bridge.mjs";
// Observability only: reuse the exact authorized inventory page/cursor. Never
// create subscriptions, reserve commands, query questions, or start an agent.
export async function communicationStatus(bridge, owner, input) {
  const page = await bridge.fleetReads.inventory(owner, input),
    now = bridge.now();
  const policy = bridge.policy(),
    principal = policy.principals.find((p) => p.id === owner && p.enabled !== false);
  if (!principal) throw Object.assign(Error("forbidden"), { reason: "forbidden" });
  bridge.fleetReads.grant(owner, input.host);
  const command = principal.commandHosts?.find((g) => g.host === input.host);
  const passive = policy.principals.filter(
    (p) =>
      p.enabled !== false &&
      p.eddieHostCaller?.host === input.host &&
      p.eddieHostCaller.reviewer === owner &&
      p.eddieHostCaller.expiresAt > now,
  );
  const subscriptions = bridge.store.all("subscription").filter((s) => s.owner === owner);
  const state = (s) => subscriptionState(s, now);
  const inbox = subscriptions.some(
    (s) => s.name === "t3.eddie.requested" && s.inboxId === owner && state(s) === "active",
  );
  const rows = page.threads.map((t) => {
    bridge.fleetReads.grant(owner, input.host, t.projectId);
    const lanes = subscriptions.filter(
      (s) =>
        s.name === "t3.thread.activity" &&
        s.host === input.host &&
        s.threadId === t.threadId &&
        s.projectId === t.projectId,
    );
    const projectAllowed = !command?.projectIds || command.projectIds.includes(t.projectId);
    const reason = !command
      ? "command_grant_missing"
      : command.expiresAt <= now
        ? "command_grant_expired"
        : !projectAllowed
          ? "project_not_authorized"
          : !t.providerInstanceId
            ? "provider_unknown"
            : !command.providerInstanceIds.includes(t.providerInstanceId)
              ? "provider_not_authorized"
              : null;
    return {
      ...t,
      communication: {
        passive_host_binding: passive.length > 0,
        passive_inbox_active: inbox,
        agent_tool_installation: "not_verified",
        command_scope_reason: reason,
        native_preflight_required: true,
        event_lane: lanes.some((s) => state(s) === "active")
          ? "active"
          : lanes.some((s) => state(s) === "expired")
            ? "expired"
            : "inactive",
        aggregate_event_subscription:
          !reason &&
          subscriptions.some((s) => s.name === "t3.fleet.activity" && state(s) === "active"),
        subscriptions: lanes.map((s) => ({
          subscription_id: s.id,
          state: state(s),
          expires_at: subscriptionExpiry(s),
        })),
        native_question_mode: "not_checked",
        round_trip: "not_verified",
      },
    };
  });
  bridge.store.audit("communication.inventory", owner, input.host);
  return {
    ...page,
    threads: rows,
    communication: {
      observed_at: new Date(now).toISOString(),
      new_subscription_limit: MAX_ACTIVE_SUBSCRIPTIONS,
      active_subscriptions: subscriptions.filter((s) => state(s) === "active").length,
      passive_replies_start_runs: false,
      live_answers_require_exact_pending_request: true,
      asynchronous_replies_require_explicit_new_turn: true,
      instruction:
        "Follow every next_cursor, including empty pages. This reports grants and subscriptions, not native connectivity, installed agent tools, task authority or completed round trips. Inspect exact native questions before answering. Renew through MCP Events without extending grants; never auto-resume or replay uncertain commands.",
    },
  };
}
