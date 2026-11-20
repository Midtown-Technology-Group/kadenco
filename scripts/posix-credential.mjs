// SPDX-License-Identifier: AGPL-3.0-or-later
import { lstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute } from "node:path";

export function readCallerCredential(path, { now = Date.now(), uid = process.getuid?.() } = {}) {
  try {
    if (!isAbsolute(path) || uid === undefined) throw new Error();
    const file = lstatSync(path),
      dir = lstatSync(dirname(path));
    if (
      !file.isFile() ||
      file.isSymbolicLink() ||
      !dir.isDirectory() ||
      dir.isSymbolicLink() ||
      file.uid !== uid ||
      dir.uid !== uid ||
      file.mode & 0o077 ||
      dir.mode & 0o077 ||
      file.size > 16384
    )
      throw new Error();
    const c = JSON.parse(readFileSync(path, "utf8"));
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
