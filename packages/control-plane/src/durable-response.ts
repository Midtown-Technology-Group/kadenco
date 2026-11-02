// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ServerResponse } from "node:http";
/** Delay actual HTTP bytes until all preceding operational writes are central.
 * Applies to JSON and each SSE chunk. Bounded buffering fails by disconnecting;
 * it never emits a successful response for an uncommitted mutation. */
export function durableResponse(
  res: ServerResponse,
  flush: () => Promise<void>,
  limit = 4 * 1024 * 1024,
) {
  const write = res.write.bind(res),
    end = res.end.bind(res),
    flushHeaders = res.flushHeaders.bind(res);
  let ended = false,
    queued = 0;
  let tail = Promise.resolve();
  const enqueue = (
    bytes: Buffer | undefined,
    final: boolean,
    callback?: (e?: Error | null) => void,
  ) => {
    if (ended || res.destroyed) {
      callback?.(Error("response_closed"));
      return false;
    }
    if (final) ended = true;
    const size = bytes?.length ?? 0;
    queued += size;
    if (queued > limit) {
      res.destroy();
      callback?.(Error("response_buffer_exceeded"));
      return false;
    }
    tail = tail
      .then(async () => {
        if (res.destroyed) throw Error("response_closed");
        await flush();
        if (res.destroyed) throw Error("response_closed");
        await new Promise<void>((resolve, reject) => {
          const finished = (error?: Error | null) => {
            queued -= size;
            callback?.(error);
            if (error) reject(error);
            else resolve();
          };
          if (final) end(bytes, finished);
          else if (bytes) write(bytes, finished);
          else {
            flushHeaders();
            finished();
          }
        });
      })
      .catch(() => {
        res.destroy();
      });
    return true;
  };
  res.flushHeaders = () => {
    enqueue(undefined, false);
  };
  const chunk = (value: unknown, encoding?: unknown) =>
    value === undefined || value === null
      ? undefined
      : typeof value === "string"
        ? Buffer.from(value, typeof encoding === "string" ? (encoding as BufferEncoding) : "utf8")
        : Buffer.from(value as Uint8Array);
  res.write = ((value: unknown, encoding?: unknown, callback?: (error?: Error | null) => void) =>
    enqueue(
      chunk(value, encoding),
      false,
      typeof encoding === "function" ? (encoding as typeof callback) : callback,
    )) as typeof res.write;
  res.end = ((value?: unknown, encoding?: unknown, callback?: () => void) => {
    if (typeof value === "function") enqueue(undefined, true, value as () => void);
    else
      enqueue(
        chunk(value, encoding),
        true,
        typeof encoding === "function" ? (encoding as () => void) : callback,
      );
    return res;
  }) as typeof res.end;
}
