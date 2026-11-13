// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
import { isDeepStrictEqual } from "node:util";
import { createHostLocalConnector } from "./host-local.ts";
import {
  observeExisting,
  deliveryPass,
  existingCallback,
  reconcileCallbackReceipts,
} from "./edge-services.ts";

/** Existing sidecar lifecycle hook, with one original host, one connection and
 * no fleet replica, listener, timer, credential discovery or native fallback. */
export function createHostLocalRuntime(
  bridge: Bridge,
  input: Parameters<typeof createHostLocalConnector>[0] & {
    enabled: boolean;
    checkpoint(): Promise<void>;
    ownerCall(owner: string, op: string, p: object): Promise<Record<string, unknown>>;
    binding: Parameters<typeof observeExisting>[1]["binding"];
  },
) {
  if (input.enabled !== true) throw Error("host_runtime_disabled");
  if (
    input.store !== bridge.store ||
    !/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(input.host) ||
    !Number.isSafeInteger(input.epoch) ||
    input.epoch < 1 ||
    !Buffer.isBuffer(input.key) ||
    input.key.length !== 32 ||
    !Buffer.isBuffer(input.payloadKey) ||
    input.payloadKey.length !== 32 ||
    typeof input.checkpoint !== "function"
  )
    throw Error("invalid_host_runtime");
  input = Object.freeze({
    ...input,
    key: Buffer.from(input.key),
    payloadKey: Buffer.from(input.payloadKey),
  });
  const commands = createHostLocalConnector(input);
  let closed = false,
    busy = false;
  let generation: number | undefined;
  let deliveryCursor: string | undefined, receiptCursor: string | undefined;
  const refresh = async () => {
    if (closed) throw Error("host_runtime_closed");
    const state = await input.call("link_status", {
      epoch: input.epoch,
      host: input.host,
      connection: commands.connection,
    });
    if (
      state.active !== true ||
      state.host !== input.host ||
      state.connection !== commands.connection ||
      !Number.isSafeInteger(state.generation) ||
      (generation !== undefined && state.generation !== generation)
    )
      throw Error("fenced");
    generation = Number(state.generation);
    const renewed = await input.call("link_renew", {
      epoch: input.epoch,
      host: input.host,
      connection: commands.connection,
      generation,
    });
    if (
      renewed.reason !== undefined ||
      renewed.host !== input.host ||
      renewed.connection !== commands.connection ||
      renewed.generation !== generation
    )
      throw Error("fenced");
  };
  const call = async (operation: string, payload: object) => {
    await refresh();
    const { epoch, ...body } = payload as Record<string, unknown>;
    if (epoch !== undefined && epoch !== input.epoch) throw Error("fenced");
    const result = await input.call("link_service", {
      epoch: input.epoch,
      host: input.host,
      connection: commands.connection,
      generation,
      operation,
      payload: body,
    });
    if (
      result.reason !== undefined &&
      !(
        operation === "outbox_receipt" &&
        result.receipt_refused === true &&
        ["forbidden", "not_found"].includes(String(result.reason))
      )
    )
      throw Error(String(result.reason));
    return result;
  };
  const post = existingCallback(
    bridge,
    async () => {
      await input.checkpoint();
      await refresh();
    },
    (subscription, event, binding) => {
      if (!isDeepStrictEqual(binding, input.binding(subscription, event))) throw Error("forbidden");
    },
  );
  return {
    connection: commands.connection,
    async cycle() {
      if (closed) return { state: "closed" };
      if (busy) return { state: "busy" };
      busy = true;
      try {
        const command = await commands.cycle();
        if (command.state !== "cycle_complete") return command;
        await observeExisting(bridge, {
          epoch: input.epoch,
          host: input.host,
          refreshLease: refresh,
          ownerCall: async () => {
            throw Error("owner_context_required");
          },
          ownerFor: input.ownerCall,
          executorCall: call,
          binding: input.binding,
        });
        await input.checkpoint();
        const delivery = await deliveryPass(
          {
            epoch: input.epoch,
            call,
            postExisting: async (reference, event) => {
              const scope = (event as { scope?: { host?: string } }).scope;
              if (scope?.host !== input.host) throw Error("identity_mismatch");
              return post(reference, event);
            },
          },
          deliveryCursor,
        );
        deliveryCursor = delivery.next ?? undefined;
        receiptCursor = await reconcileCallbackReceipts(
          bridge,
          { epoch: input.epoch, host: input.host, call, refreshLease: refresh },
          receiptCursor,
        );
        await input.checkpoint();
        return { state: "cycle_complete", command, delivery };
      } finally {
        busy = false;
      }
    },
    close() {
      closed = true;
      commands.close();
    },
  };
}
