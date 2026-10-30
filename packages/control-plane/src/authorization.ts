// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
export type Envelope = {
  request_id: string;
  fleet: string;
  principal: string;
  grant: string;
  revision: number;
  host: string;
  project: string;
  provider: string;
  thread_id: string;
  run: string | null;
  kind: "continue" | "create" | "settings_standard" | "webhook";
  expires: number;
  payload: Record<string, unknown>;
};
export type Grant = Omit<Envelope, "request_id" | "kind" | "payload"> & {
  revoked: boolean;
  kinds: Envelope["kind"][];
};
// Sign exact serialized bytes, never reinterpret a parsed object's key ordering.
export function seal(value: unknown, key: Buffer) {
  if (key.length < 32) throw Error("weak_test_or_configured_key");
  const body = JSON.stringify(value);
  if (Buffer.byteLength(body) > 1048576) throw Error("body_too_large");
  return { body, mac: createHmac("sha256", key).update(body).digest("hex") };
}
export function unseal(packet: { body: string; mac: string }, key: Buffer): unknown {
  if (
    key.length < 32 ||
    Buffer.byteLength(packet.body) > 1048576 ||
    !/^[a-f0-9]{64}$/.test(packet.mac)
  )
    throw Error("invalid_signature");
  const expected = createHmac("sha256", key).update(packet.body).digest();
  if (!timingSafeEqual(expected, Buffer.from(packet.mac, "hex"))) throw Error("invalid_signature");
  return JSON.parse(packet.body);
}
export function validateOperation(e: Envelope, g: Grant, now: number) {
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(g.expires) ||
    !Number.isSafeInteger(g.revision) ||
    g.revision < 1 ||
    !["continue", "create", "settings_standard", "webhook"].includes(e.kind)
  )
    throw Error("invalid_authority");
  if (
    g.revoked ||
    !Number.isSafeInteger(e.expires) ||
    e.expires <= now ||
    g.expires <= now ||
    e.expires > g.expires ||
    !g.kinds.includes(e.kind)
  )
    throw Error("authority_expired_or_revoked");
  for (const key of [
    "fleet",
    "principal",
    "grant",
    "revision",
    "host",
    "project",
    "provider",
    "thread_id",
    "run",
  ] as const)
    if (e[key] !== g[key]) throw Error("binding_mismatch");
  if (
    !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(e.request_id) ||
    !Number.isSafeInteger(e.revision)
  )
    throw Error("invalid_operation");
  const permitted = {
    continue: ["text"],
    create: ["text", "title", "model", "options", "runtime_mode"],
    settings_standard: ["speed", "expected_fingerprint"],
    webhook: ["event_id", "body_sha256"],
  }[e.kind];
  if (!e.payload || Object.keys(e.payload).some((k) => !permitted.includes(k)))
    throw Error("invalid_payload");
  if (e.kind === "settings_standard") {
    if (e.payload.speed !== "standard") throw Error("invalid_payload");
  } else if (e.kind === "webhook") {
    if (
      typeof e.payload.event_id !== "string" ||
      !/^[a-f0-9]{64}$/.test(String(e.payload.body_sha256))
    )
      throw Error("invalid_payload");
  } else if (
    typeof e.payload.text !== "string" ||
    !e.payload.text.length ||
    e.payload.text.length > 16000 ||
    (e.kind === "create" && (e.run !== null || typeof e.payload.title !== "string"))
  )
    throw Error("invalid_payload");
  return createHash("sha256").update(JSON.stringify(e)).digest("hex");
}
export type Retirement = {
  migration_id: string;
  snapshot: string;
  issued: number;
  expires: number;
  routes: string[];
  denied: string[];
  revival_denied: boolean;
  issuer: string;
};
export function verifyRetirement(
  proof: Retirement,
  required: { migration_id: string; snapshot: string; routes: string[]; issuer: string },
  now: number,
) {
  if (
    proof.issuer !== required.issuer ||
    proof.migration_id !== required.migration_id ||
    proof.snapshot !== required.snapshot ||
    proof.issued > now ||
    proof.expires <= now ||
    !proof.revival_denied ||
    !required.routes.length ||
    new Set(required.routes).size !== required.routes.length ||
    required.routes.some((r) => !proof.routes.includes(r) || !proof.denied.includes(r))
  )
    throw Error("retirement_not_proven");
  return { verified_report: true, activation_permitted: false as const };
}

/** Authenticated operation entry point; no native implementation is supplied here. */
export async function consumeAuthorized(
  packet: { body: string; mac: string },
  key: Buffer,
  currentGrant: () => Promise<Grant>,
  now: () => number,
  epoch: number,
  ports: import("./edge.ts").EdgePorts,
) {
  const envelope = unseal(packet, key) as Envelope;
  const { consume } = await import("./edge.ts");
  const command = {
    request_id: envelope.request_id,
    epoch,
    host: envelope.host,
    thread_id: envelope.thread_id,
  };
  const validate = async () => {
    const digest = validateOperation(envelope, await currentGrant(), now());
    await ports.validate(command);
    return digest;
  };
  await validate();
  return consume(command, {
    ...ports,
    validate: async () => {
      await validate();
    },
    call: async (op, body) => {
      const result = await ports.call(op, body);
      if (
        op === "claim" &&
        result.claimed === true &&
        (result.kind !== envelope.kind || result.digest !== (await validate()))
      )
        throw Error("reservation_envelope_mismatch");
      return result;
    },
    execute: async (c) => {
      await validate();
      return ports.execute(c);
    },
  });
}
