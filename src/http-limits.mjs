// SPDX-License-Identifier: AGPL-3.0-or-later
// Native responses are untrusted, including successful and malformed payloads.
export async function boundedResponseText(response, maximum = 2 * 1024 * 1024) {
  const fail = () =>
    Object.assign(new Error("source_response_too_large"), { reason: "source_protocol_error" });
  if (Number(response.headers.get("content-length")) > maximum) {
    void response.body?.cancel().catch(() => {});
    throw fail();
  }
  if (!response.body) return "";
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.byteLength;
    if (size > maximum) throw fail();
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, size).toString("utf8");
}
