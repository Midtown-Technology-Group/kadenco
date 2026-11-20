// SPDX-License-Identifier: AGPL-3.0-or-later
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";

export function readCallerCredential(path, { now = Date.now(), uid = process.getuid?.() } = {}) {
  try {
    if (!isAbsolute(path) || uid === undefined) throw new Error();
    const dir = lstatSync(dirname(path));
    if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== uid || dir.mode & 0o077)
      throw new Error();
    // Check and read the same open file: no link is followed and nothing can
    // be swapped in between.
    const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    let text;
    try {
      const file = fstatSync(fd);
      if (!file.isFile() || file.uid !== uid || file.mode & 0o077 || file.size > 16384)
        throw new Error();
      text = readFileSync(fd, "utf8");
    } finally {
      closeSync(fd);
    }
    const c = JSON.parse(text);
    if (
      typeof c.token !== "string" ||
      !c.token ||
      /\s/.test(c.token) ||
      !Number.isFinite(c.expiresAt) ||
      c.expiresAt <= now ||
      typeof c.host !== "string" ||
      !c.host
    )
      throw new Error();
    const u = new URL(c.endpoint);
    if (
      u.protocol !== "http:" ||
      u.hostname !== "127.0.0.1" ||
      !u.port ||
      u.pathname !== "/mcp" ||
      u.username ||
      u.password ||
      u.search ||
      u.hash
    )
      throw new Error();
    return c;
  } catch {
    throw new Error("private_caller_credential_unavailable");
  }
}
