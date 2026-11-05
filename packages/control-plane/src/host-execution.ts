// SPDX-License-Identifier: AGPL-3.0-or-later
import { consumeAuthorized, type Grant } from "./authorization.ts";
import type { AttemptJournal, Outcome } from "./edge.ts";
import { dispatchExisting, reconcileExisting, type SidecarServices } from "./native-adapter.ts";
import { unseal, type Envelope } from "./authorization.ts";
import { decryptHostPayload, hostPayloadIdentity } from "./host-payload.ts";
import type { LinkFrame } from "./host-links.ts";

/** Consume only a reference already committed to the host's durable inbox. */
export async function consumeHostReference(
  input: Omit<Parameters<typeof consumeHostOperation>[0], "packet"> & {
    frame: LinkFrame;
    payloadKey: Buffer;
  },
) {
  if (input.frame.host !== input.host) throw Error("host_identity_mismatch");
  const result = await input.call("link_payload", {
    epoch: input.epoch,
    host: input.host,
    connection: input.connection,
    generation: input.generation,
    request_id: input.frame.request_id,
  });
  if (
    result.request_id !== input.frame.request_id ||
    result.host !== input.host ||
    result.thread_id !== input.frame.thread_id ||
    typeof result.digest !== "string" ||
    typeof result.ciphertext !== "string"
  )
    throw Error("payload_identity_mismatch");
  const packet = decryptHostPayload(
    result.ciphertext,
    input.payloadKey,
    hostPayloadIdentity(input.host, input.frame.thread_id, input.frame.request_id, result.digest),
  );
  const envelope = unseal(packet, input.key) as Envelope;
  if (
    envelope.request_id !== input.frame.request_id ||
    envelope.thread_id !== input.frame.thread_id
  )
    throw Error("payload_identity_mismatch");
  return consumeHostOperation({ ...input, packet });
}

/** Explicit host-local entry; caller supplies existing authenticated transport,
 * current policy resolver, encrypted journal and original signed operation.
 * No credential discovery, registration, timers or service startup. */
export async function consumeHostOperation(input: {
  host: string;
  connection: string;
  generation: number;
  epoch: number;
  packet: { body: string; mac: string };
  key: Buffer;
  grant(): Promise<Grant>;
  now(): number;
  journal: AttemptJournal;
  call(op: string, body: object): Promise<Record<string, unknown>>;
  services: SidecarServices;
}) {
  const envelope = unseal(input.packet, input.key) as Envelope;
  if (envelope.host !== input.host) throw Error("host_identity_mismatch");
  const session = {
    host: input.host,
    connection: input.connection,
    generation: input.generation,
    epoch: input.epoch,
  };
  const checked = async (op: string, body: object) => {
    const result = await input.call(op, body);
    if (result.reason !== undefined) throw Error(String(result.reason));
    return result;
  };
  const observe = () => reconcileExisting(envelope, input.services);
  let commandGeneration: unknown;
  const record = async (outcome: Outcome) => {
    if (outcome.state !== "observed") return false;
    const receipt = JSON.parse(outcome.evidence) as Record<string, unknown>;
    if (receipt.completed !== true) {
      if (receipt.native_submitted === true)
        await checked("link_observe", {
          ...session,
          request_id: envelope.request_id,
          command_generation: commandGeneration,
          receipt,
        });
      return false;
    }
    await checked("link_record_receipt", {
      ...session,
      request_id: envelope.request_id,
      command_generation: commandGeneration,
      receipt,
    });
    return true;
  };
  const result = await consumeAuthorized(
    input.packet,
    input.key,
    input.grant,
    input.now,
    input.epoch,
    {
      journal: input.journal,
      validate: async () => {},
      execute: () => dispatchExisting(envelope, input.services),
      observe,
      call: async (op, body) => {
        const p = body as Record<string, unknown>;
        if (op === "claim") {
          const claimed = await checked("link_claim", {
            ...session,
            request_id: envelope.request_id,
          });
          commandGeneration = claimed.generation;
          return claimed;
        }
        if (op === "begin")
          return checked("link_begin", {
            ...session,
            request_id: envelope.request_id,
            command_generation: p.generation,
          });
        if (op === "receipt") {
          const receipt = await checked("receipt", body);
          commandGeneration = receipt.generation;
          return receipt;
        }
        if (op === "record_receipt") {
          if (!(await record(p.receipt as Outcome))) throw Error("native_execution_not_terminal");
          return { receipt_recorded: true };
        }
        throw Error("unsupported_host_operation");
      },
    },
  );
  // Reconnection can settle a known exact native receipt, never resubmit native IO.
  if (result.state === "reconcile" && "outcome" in result && result.outcome) {
    try {
      if (await record(result.outcome)) return { state: "recorded", outcome: result.outcome };
    } catch {
      /* Immutable uncertainty remains held for later read-only reconciliation. */
    }
  }
  return result;
}
