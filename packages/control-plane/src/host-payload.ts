// SPDX-License-Identifier: AGPL-3.0-or-later
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
/** Existing configured host key only; this module never provisions trust. */
export function encryptHostPayload(
  packet: { body: string; mac: string },
  key: Buffer,
  identity: string,
) {
  if (key.length !== 32) throw Error("host_key_required");
  const nonce = randomBytes(12),
    cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(identity));
  const data = Buffer.concat([cipher.update(JSON.stringify(packet)), cipher.final()]);
  const result = Buffer.concat([nonce, cipher.getAuthTag(), data]).toString("base64");
  if (result.length > 32768) throw Error("body_too_large");
  return result;
}
export function decryptHostPayload(
  value: string,
  key: Buffer,
  identity: string,
): { body: string; mac: string } {
  if (key.length !== 32 || value.length > 32768) throw Error("host_key_required");
  const data = Buffer.from(value, "base64");
  if (data.length < 29) throw Error("invalid_request");
  const cipher = createDecipheriv("aes-256-gcm", key, data.subarray(0, 12));
  cipher.setAAD(Buffer.from(identity));
  cipher.setAuthTag(data.subarray(12, 28));
  return JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString());
}
export const hostPayloadIdentity = (
  host: string,
  thread: string,
  request: string,
  digest: string,
) => JSON.stringify([host, thread, request, digest]);
