// SPDX-License-Identifier: AGPL-3.0-or-later
import { gzipSync, gunzipSync } from "node:zlib";
const prefix = "gzip-base64-v1:";
const decodedLimit = 65536,
  bindingLimit = 5000;
/** Transport encoding only: expanded policy validation and authorization are
 * unchanged. Raw JSON remains compatible. Never discard grants to fit a binding. */
export function encodePolicy(raw: string) {
  if (typeof raw !== "string" || Buffer.byteLength(raw) > decodedLimit)
    throw Error("policy_transport_too_large");
  const encoded = prefix + gzipSync(Buffer.from(raw, "utf8")).toString("base64");
  if (Buffer.byteLength(encoded) > bindingLimit) throw Error("policy_binding_too_large");
  return encoded;
}
export function decodePolicy(raw: string) {
  if (typeof raw !== "string") throw Error("configuration_required");
  if (!raw.startsWith(prefix)) {
    if (Buffer.byteLength(raw) > decodedLimit) throw Error("configuration_required");
    return raw;
  }
  if (Buffer.byteLength(raw) > bindingLimit) throw Error("configuration_required");
  const value = raw.slice(prefix.length),
    bytes = Buffer.from(value, "base64");
  if (!value || bytes.toString("base64") !== value) throw Error("configuration_required");
  const decoded = gunzipSync(bytes, { maxOutputLength: decodedLimit });
  if (decoded.byteLength > decodedLimit) throw Error("configuration_required");
  return new TextDecoder("utf-8", { fatal: true }).decode(decoded);
}
