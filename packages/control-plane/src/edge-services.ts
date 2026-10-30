// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
export async function deliverClaimed(
  id: string,
  ports: {
    epoch: number;
    call: (op: string, p: object) => Promise<Record<string, unknown>>;
    postExisting: (reference: string, event: unknown) => Promise<number>;
  },
) {
  const claim = await ports.call("outbox_claim", { id, epoch: ports.epoch });
  if (claim.claimed !== true) return { state: "blocked" };
  const binding = { id, generation: claim.generation, epoch: ports.epoch };
  const permit = await ports.call("outbox_begin", binding);
  if (permit.may_attempt !== true) return { state: "blocked" };
  let http_status = 0;
  try {
    http_status = await ports.postExisting(String(claim.callback_reference), {
      ...(claim.event as object),
      scope: claim.callback_scope,
    });
  } catch (e) {
    const reason = (e as { reason?: string; message?: string }).reason ?? (e as Error).message;
    if (
      reason &&
      [
        "forbidden",
        "input_request_not_pending",
        "provider_not_authorized",
        "thread_unavailable",
        "identity_mismatch",
      ].includes(reason)
    )
      return ports.call("outbox_stop", { ...binding, source_reason: reason });
  }
  // A lost result response is reconciled/retried with the original event ID, never
  // interpreted as agent execution. Existing edge callback signer/allowlist applies.
  return ports.call("outbox_result", { ...binding, http_status });
}

import { signedPost } from "../../../dist/webhook.mjs";
import { subscriptionActive } from "../../../dist/subscription-state.mjs";
/** Callback secrets/allowlist, pending-question/native checks remain on the one
 * edge that already owns the encrypted subscription and signer. */
export function existingCallback(bridge: Bridge) {
  return async (reference: string, envelope: unknown) => {
    const event = (envelope as { data: unknown }).data;
    const subscription = bridge.store.get("subscription", reference);
    const scope = (
      envelope as { scope?: { owner: string; host: string; thread: string; name: string } }
    ).scope;
    const data = (event as { data?: { host?: string; thread_id?: string } })?.data;
    if (
      !scope ||
      scope.owner !== subscription?.owner ||
      scope.name !== subscription?.name ||
      scope.host !== (subscription?.host ?? data?.host) ||
      scope.thread !== (subscription?.threadId ?? data?.thread_id ?? "aggregate")
    )
      throw Error("forbidden");
    if (!subscriptionActive(subscription, bridge.now())) throw Error("forbidden");
    if (subscription.name === "t3.eddie.requested")
      await bridge.exchanges.deliverable(subscription, event);
    else if (subscription.name === "t3.fleet.activity")
      await bridge.fleetEvents.deliverable(subscription, event);
    else if (subscription.name === "t3.thread.activity")
      await bridge.lanes.deliverable(subscription, event);
    else bridge.grant(subscription.owner, subscription.sessionId);
    const refreshed = bridge.store.get("subscription", reference);
    if (
      !subscriptionActive(refreshed, bridge.now()) ||
      JSON.stringify(refreshed) !== JSON.stringify(subscription)
    )
      throw Error("forbidden");
    return (await signedPost(subscription, event, bridge.post, bridge.now())).status;
  };
}

import type { OperationBinding } from "./binding.ts";
/** One bounded pass: existing observers retain native source/cursor semantics;
 * only durable callback ownership is transferred centrally. Never calls deliver(). */
export async function observeExisting(
  bridge: Bridge,
  ports: {
    epoch: number;
    refreshLease: () => Promise<void>;
    ownerCall: (op: string, p: object) => Promise<Record<string, unknown>>;
    executorCall: (op: string, p: object) => Promise<Record<string, unknown>>;
    binding: (subscription: Record<string, unknown>, event?: unknown) => OperationBinding;
  },
) {
  await ports.refreshLease();
  await bridge.observe();
  await bridge.fleetEvents.observe();
  const results: { id: string; state: string }[] = [];
  for (const d of bridge.store.all("delivery")) {
    if (results.length >= 100) break;
    if (d.status !== "pending") continue;
    const s = bridge.store.get("subscription", d.subId);
    if (!subscriptionActive(s, bridge.now())) continue;
    await ports.refreshLease();
    // Existing filtering/pending-question/native authorization is rechecked again at
    // callback time; observations are evidence, never permission to execute a task.
    const binding = ports.binding(s, d.event);
    const host = s.host ?? d.event.data?.host,
      thread = s.threadId ?? d.event.data?.thread_id ?? "aggregate";
    const centralSubscription = JSON.stringify([s.id, host, thread]);
    const request = {
      epoch: ports.epoch,
      id: centralSubscription,
      external_id: s.id,
      host: s.host ?? d.event.data?.host,
      thread_id: s.threadId ?? d.event.data?.thread_id ?? "aggregate",
      binding,
      expires: s.expires,
      name: s.name,
      callback_reference: s.id,
      ...(s.leaseExpires !== undefined ? { lease_expires: s.leaseExpires } : {}),
    };
    let subscribed = await ports.ownerCall("subscribe_central", request);
    if (subscribed.reason === "idempotency_conflict") {
      const prior = await ports.ownerCall("subscription_snapshot", {
        epoch: ports.epoch,
        id: centralSubscription,
      });
      if (prior.active !== true) throw Error("subscription_sync_denied");
      subscribed = await ports.ownerCall("subscribe_central", {
        ...request,
        expected_expires: prior.expires,
      });
    }
    if (subscribed.stored !== true) throw Error("subscription_sync_failed");
    const cursor = await ports.executorCall("observation_cursor", {
      epoch: ports.epoch,
      subscription_id: centralSubscription,
    });
    if (!Number.isSafeInteger(cursor.cursor)) throw Error("cursor_unavailable");
    const result = await ports.executorCall("observe_central", {
      epoch: ports.epoch,
      subscription_id: centralSubscription,
      expected_cursor: cursor.cursor,
      cursor: Number(cursor.cursor) + 1,
      run: d.event.data?.run_id ?? "coverage",
      kind: d.event.data?.kind ?? s.name,
      native_request_id:
        d.event.data?.native_request_id ?? d.event.data?.request_id ?? d.event.eventId,
      event: d.event,
    });
    if (result.stored !== true) throw Error("observation_not_stored");
    bridge.store.put("delivery", d.id, { ...d, status: "centralized", central_id: result.id });
    results.push({ id: String(result.id), state: "stored" });
  }
  return results;
}

/** Recover pending callbacks after edge restart; bounded pagination can return a
 * continuation instead of falsely claiming a complete scan. No background timer. */
export async function deliveryPass(ports: Parameters<typeof deliverClaimed>[1], after?: string) {
  let cursor = after,
    scanned = 0;
  const results: unknown[] = [];
  const seen = new Set<string>();
  for (let page = 0; page < 10; page++) {
    const pending = await ports.call("outbox_pending", {
      epoch: ports.epoch,
      ...(cursor ? { after: cursor } : {}),
    });
    if (!Array.isArray(pending.ids) || !(pending.next === null || typeof pending.next === "string"))
      throw Error("outbox_inventory_unavailable");
    for (const id of pending.ids) {
      scanned++;
      results.push(await deliverClaimed(String(id), ports));
    }
    if (pending.next === null) return { scanned, results, next: null };
    if (seen.has(pending.next)) throw Error("outbox_cursor_loop");
    seen.add(pending.next);
    cursor = pending.next;
  }
  return { scanned, results, next: cursor };
}
