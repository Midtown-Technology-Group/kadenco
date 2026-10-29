// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only derivative of the installed MTG T3 Fleet 0.1.2 transport.
// Original SHA256 ca8fc11c9f379cf2228e9c4b9391320f36e4169a4caa65801311b8c8b88bd3c1.
// Preserve existing route/auth machinery; add native paginated project/thread
// enumeration and remove every write/queue handle. The installed cache is untouched.
// No auth bootstrap, refresh, pairing, token writes, arbitrary host, or raw tool API.
import { execFile as execFileCb, spawn as spawnDefault } from "node:child_process";
import { promisify } from "node:util";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import net from "node:net";
import { rpcReadReason } from "./read-errors.mjs";
import { diagnose } from "./diagnostics.mjs";
import { boundedResponseText } from "./http-limits.mjs";

const execFile = promisify(execFileCb);
const PROTOCOL_VERSION = "2025-06-18";
const REQUIRED = {
  read: ["orchestration:read"],
};
const TOOL_NAMES = Object.freeze({
  search: "t3_thread_search",
  read: "t3_thread_read",
  projects: "t3_project_list",
  threads: "t3_thread_list",
});
const SAFE_SSH_OPTIONS = [
  "-T",
  "-o",
  "BatchMode=yes",
  "-o",
  "ConnectTimeout=8",
  "-o",
  "StrictHostKeyChecking=yes",
];

export class FleetTransportError extends Error {
  constructor(message, reason) {
    super(message);
    this.reason = reason;
  }
}

function isPort(value) {
  return Number.isInteger(value) && value > 0 && value <= 65535;
}

function quotePath(value) {
  if (typeof value !== "string" || !value.startsWith("/") || /[\r\n\0]/.test(value)) {
    throw new FleetTransportError(
      "configured remote path must be absolute without control characters",
    );
  }
  return "'" + value.replaceAll("'", "'\\''") + "'";
}

function parseResponse(response, text) {
  if (!text) return null;
  const type = (response.headers.get("content-type") || "").toLowerCase();
  if (!type.includes("text/event-stream")) {
    try {
      return JSON.parse(text);
    } catch {
      throw new FleetTransportError("MCP returned invalid JSON", "source_protocol_error");
    }
  }
  const messages = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    const data = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trim())
      .filter(Boolean)
      .join("");
    if (data) {
      try {
        messages.push(JSON.parse(data));
      } catch {
        throw new FleetTransportError("MCP returned invalid event data", "source_protocol_error");
      }
    }
  }
  return messages.length <= 1 ? (messages[0] ?? null) : messages;
}

function pickReply(value) {
  return Array.isArray(value)
    ? value.find((item) => item && item.id != null) || value.at(-1)
    : value;
}

function extractToolResult(reply, operation) {
  const rpc = pickReply(reply);
  if (!rpc || typeof rpc !== "object")
    throw new FleetTransportError(`${operation}: malformed MCP response`, "source_protocol_error");
  if (rpc.error)
    throw new FleetTransportError(
      `${operation}: JSON-RPC error ${rpc.error.code ?? "unknown"}`,
      rpcReadReason(rpc.error.code),
    );
  const result = rpc.result;
  if (!result || typeof result !== "object")
    throw new FleetTransportError(`${operation}: missing MCP result`, "source_protocol_error");
  // MCP errors take precedence over success-shaped structured/text content.
  if (result.isError === true) {
    let payload = result.structuredContent;
    if (!payload) {
      try {
        payload = JSON.parse(result.content?.find((x) => x.type === "text")?.text);
      } catch {}
    }
    const known = new Set([
      "InternalError",
      "INTERNAL_ERROR",
      "InvalidArgument",
      "INVALID_ARGUMENT",
      "runtime_mode_escalation_denied",
      "thread_not_found",
      "unauthorized",
      "forbidden",
      "invalid_scope",
    ]);
    const code = known.has(payload?.code) ? `: ${payload.code}` : "";
    const reason = ["InternalError", "INTERNAL_ERROR"].includes(payload?.code)
      ? "source_internal_error"
      : ["InvalidArgument", "INVALID_ARGUMENT"].includes(payload?.code)
        ? "invalid_source_request"
        : ["unauthorized", "invalid_scope"].includes(payload?.code)
          ? "authentication_required"
          : ["forbidden", "runtime_mode_escalation_denied"].includes(payload?.code)
            ? "forbidden"
            : payload?.code === "thread_not_found"
              ? "thread_not_found"
              : undefined;
    throw new FleetTransportError(`${operation}: MCP isError${code}`, reason);
  }
  if (Object.hasOwn(result, "structuredContent")) return result.structuredContent;
  const texts = (result.content || [])
    .filter((item) => item?.type === "text")
    .map((item) => item.text);
  if (texts.length === 1) {
    try {
      return JSON.parse(texts[0]);
    } catch {
      return texts[0];
    }
  }
  return result;
}

function assertLoopbackMcpUrl(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new FleetTransportError("configured direct MCP URL is invalid");
  }
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !/^\/mcp\/?$/.test(url.pathname)
  ) {
    throw new FleetTransportError(
      "direct MCP URL must be a loopback /mcp endpoint without credentials or query",
    );
  }
  return `${url.protocol}//${url.host}`;
}

function safeHostEntry(hosts, name) {
  if (!Array.isArray(hosts) || typeof name !== "string" || !name) {
    throw new FleetTransportError("configured host selection is required");
  }
  const matches = hosts.filter((host) => host?.name === name && host.enabled !== false);
  if (matches.length !== 1)
    throw new FleetTransportError("host must match exactly one configured allowlist entry");
  const host = matches[0];
  if (host.url) {
    if (host.ssh) throw new FleetTransportError("host has ambiguous direct and SSH routes");
    assertLoopbackMcpUrl(host.url);
    return host;
  }
  if (typeof host.ssh !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(host.ssh)) {
    throw new FleetTransportError("host has no supported configured route");
  }
  if (!isPort(host.localPort))
    throw new FleetTransportError("SSH host must have its configured stable localPort");
  if (host.port !== undefined && !isPort(host.port))
    throw new FleetTransportError("configured remote port is invalid");
  return host;
}

function sessionRank(access) {
  return (
    {
      "read-only": 0,
      "approval-required": 1,
      null: 1,
      undefined: 1,
      "auto-accept-edits": 2,
      auto: 3,
      "full-access": 4,
    }[access] ?? 4
  );
}

// Select only an unexpired cached MCP-client session bound to the exact origin.
// This function never creates or refreshes a token.
export function selectExistingSession(
  cache,
  hostName,
  base,
  scope,
  now = Date.now(),
  minimumAccess = "read-only",
) {
  const required = REQUIRED[scope];
  if (!required) throw new FleetTransportError("unsupported authorization scope");
  const candidates = Object.entries(cache || {}).filter(([key, value]) => {
    const parts = key.split("|");
    return (
      parts[0] === hostName &&
      parts[1] === "mcp-client" &&
      value?.host === hostName &&
      value.base === base &&
      sessionRank(value.access) >= sessionRank(minimumAccess) &&
      Array.isArray(value.scopes) &&
      required.every((item) => value.scopes.includes(item)) &&
      typeof value.token === "string" &&
      value.token.length > 0 &&
      Number.isFinite(value.expiresAt) &&
      value.expiresAt > now + 30_000
    );
  });
  candidates.sort(
    (a, b) =>
      sessionRank(a[1].access) - sessionRank(b[1].access) || b[1].expiresAt - a[1].expiresAt,
  );
  if (!candidates.length) {
    throw Object.assign(
      new FleetTransportError(
        `no unexpired existing ${scope} session for ${hostName} at the exact configured origin; authentication is never bootstrapped automatically`,
        "authentication_required",
      ),
      { diagnosticMetadata: { credential_status: "cache_unavailable" } },
    );
  }
  const [cacheKey, entry] = candidates[0];
  return Object.freeze({
    token: entry.token,
    runtimeAccess: entry.access || "approval-required",
    scopes: [...entry.scopes],
    cacheKey,
    expiresAt: entry.expiresAt,
  });
}

class McpClient {
  #token;
  #fetch;
  #sessionId = null;
  #protocol = PROTOCOL_VERSION;
  #nextId = 1;
  #available = new Set();

  constructor(url, token, fetchImpl) {
    this.url = url;
    this.#token = token;
    this.#fetch = fetchImpl;
  }

  async #post(body) {
    const headers = {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${this.#token}`,
    };
    if (this.#sessionId) {
      headers["mcp-session-id"] = this.#sessionId;
      headers["MCP-Protocol-Version"] = this.#protocol;
    }
    let response;
    try {
      response = await this.#fetch(this.url, {
        method: "POST",
        redirect: "error",
        headers,
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15000),
      });
    } catch (error) {
      throw Object.assign(
        new FleetTransportError(
          "MCP transport request failed",
          ["TimeoutError", "AbortError"].includes(error?.name)
            ? "source_timeout"
            : "source_unavailable",
        ),
        { code: error?.code ?? error?.cause?.code },
      );
    }
    this.#sessionId = response.headers.get("mcp-session-id") || this.#sessionId;
    if (!response.ok) {
      void response.body?.cancel().catch(() => {});
      if (response.status === 401 || response.status === 403) {
        throw Object.assign(
          new FleetTransportError(
            `MCP authentication denied (HTTP ${response.status}); do not mint or refresh credentials automatically`,
            "authentication_required",
          ),
          { diagnosticMetadata: { http_status: response.status } },
        );
      }
      throw Object.assign(
        new FleetTransportError(
          `MCP HTTP ${response.status}`,
          response.status >= 500 ? "source_temporarily_unavailable" : "source_unavailable",
        ),
        { diagnosticMetadata: { http_status: response.status } },
      );
    }
    let text;
    try {
      text = await boundedResponseText(response);
    } catch (error) {
      if (["TimeoutError", "AbortError"].includes(error?.name))
        throw new FleetTransportError("MCP response body timed out", "source_timeout");
      throw error;
    }
    return parseResponse(response, text);
  }

  async initialize() {
    const reply = pickReply(
      await this.#post({
        jsonrpc: "2.0",
        id: this.#nextId++,
        method: "initialize",
        params: {
          protocolVersion: this.#protocol,
          capabilities: {},
          clientInfo: { name: "t3-fleet-safe-helper", version: "1.0.0" },
        },
      }),
    );
    if (reply?.error)
      throw new FleetTransportError(
        `MCP initialize JSON-RPC error ${reply.error.code ?? "unknown"}`,
        rpcReadReason(reply.error.code),
      );
    if (!reply?.result?.protocolVersion)
      throw new FleetTransportError("MCP initialize response did not negotiate a protocol version");
    this.#protocol = reply.result.protocolVersion;
    await this.#post({ jsonrpc: "2.0", method: "notifications/initialized" });
    const list = extractToolResult(
      await this.#post({
        jsonrpc: "2.0",
        id: this.#nextId++,
        method: "tools/list",
        params: {},
      }),
      "tools/list",
    );
    if (!Array.isArray(list?.tools))
      throw new FleetTransportError("MCP tools/list returned no tool list");
    this.#available = new Set(list.tools.map((tool) => tool.name));
  }

  async #callAllowed(name, args) {
    if (!Object.values(TOOL_NAMES).includes(name))
      throw new FleetTransportError("tool is outside the T3 Fleet allowlist");
    if (!this.#available.has(name))
      throw new FleetTransportError(`required read/write tool is unavailable: ${name}`);
    return extractToolResult(
      await this.#post({
        jsonrpc: "2.0",
        id: this.#nextId++,
        method: "tools/call",
        params: { name, arguments: args },
      }),
      name,
    );
  }

  readSession(scope, metadata) {
    const client = this;
    return Object.freeze({
      host: metadata.host,
      base: metadata.base,
      runtimeAccess: metadata.runtimeAccess,
      scopes: [...metadata.scopes],
      expiresAt: metadata.expiresAt,
      async searchThreads(args) {
        if (scope !== "read") throw new FleetTransportError("session lacks read scope");
        return client.#callAllowed(TOOL_NAMES.search, args);
      },
      async readThread(args) {
        if (scope !== "read") throw new FleetTransportError("session lacks read scope");
        return client.#callAllowed(TOOL_NAMES.read, args);
      },
      async listProjects(args) {
        if (scope !== "read") throw new FleetTransportError("session lacks read scope");
        return client.#callAllowed(TOOL_NAMES.projects, args);
      },
      async listThreads(args) {
        if (scope !== "read") throw new FleetTransportError("session lacks read scope");
        return client.#callAllowed(TOOL_NAMES.threads, args);
      },
      async dispose() {
        await client.dispose();
      },
    });
  }

  async dispose() {
    if (!this.#sessionId) return;
    try {
      await this.#fetch(this.url, {
        method: "DELETE",
        redirect: "error",
        signal: AbortSignal.timeout(5000),
        headers: {
          Authorization: `Bearer ${this.#token}`,
          "mcp-session-id": this.#sessionId,
          "MCP-Protocol-Version": this.#protocol,
        },
      });
    } catch {
      /* Closing the SSH forward still tears down the task-owned transport. */
    }
    this.#sessionId = null;
  }
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new FleetTransportError(`cannot read configured ${label}`);
  }
}

function isPortFree(netImpl, port) {
  return new Promise((resolve) => {
    const server = netImpl.createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "127.0.0.1", () => server.close(() => resolve(true)));
  });
}

function waitForTunnel(netImpl, port, child, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const started = Date.now();
    let finished = false;
    let timer;
    const done = (error) => {
      if (finished) return;
      finished = true;
      if (timer) clearInterval(timer);
      child.removeListener?.("exit", onExit);
      child.removeListener?.("error", onError);
      if (error) reject(error);
      else resolve();
    };
    const onExit = () =>
      done(new FleetTransportError("configured SSH forward exited before becoming ready"));
    const onError = () =>
      done(new FleetTransportError("could not start the configured SSH forward"));
    child.once?.("exit", onExit);
    child.once?.("error", onError);
    timer = setInterval(() => {
      if (Date.now() - started > timeoutMs)
        return done(new FleetTransportError("configured SSH forward did not become ready"));
      const socket = netImpl.createConnection({ host: "127.0.0.1", port });
      socket.once("connect", () => {
        socket.destroy();
        done();
      });
      socket.once("error", () => socket.destroy());
    }, 100);
  });
}

function defaultPaths() {
  const configDir = process.env.T3_FLEET_DIR || join(homedir(), ".config", "kadenco");
  return {
    hostsFile: process.env.T3_FLEET_HOSTS || join(configDir, "hosts.json"),
    tokensFile: process.env.T3_FLEET_TOKENS || join(configDir, "tokens.json"),
  };
}

export class T3FleetTransport {
  constructor({
    hostsFile,
    tokensFile,
    fetchImpl = fetch,
    spawnImpl = spawnDefault,
    execFileImpl = execFile,
    netImpl = net,
    now = Date.now,
    sshBinary,
    hostsProvider,
    cacheProvider,
    preopenedHosts = [],
    runtimePortCache,
    diagnostic = () => {},
  } = {}) {
    const defaults = defaultPaths();
    this.hostsFile = hostsFile || defaults.hostsFile;
    this.tokensFile = tokensFile || defaults.tokensFile;
    this.fetchImpl = fetchImpl;
    this.spawnImpl = spawnImpl;
    this.execFileImpl = execFileImpl;
    this.netImpl = netImpl;
    this.now = now;
    this.sshBinary = sshBinary || (process.platform === "win32" ? "ssh.exe" : "ssh");
    this.hostsProvider =
      hostsProvider || (() => readJson(this.hostsFile, "T3 Fleet host configuration"));
    this.cacheProvider =
      cacheProvider || (() => readJson(this.tokensFile, "existing T3 Fleet session cache"));
    this.preopenedHosts = new Set(preopenedHosts);
    this.tunnels = new Map();
    this.clients = new Set();
    this.runtimePortCache = runtimePortCache;
    this.diagnostic = diagnostic;
  }

  #hosts() {
    const data = this.hostsProvider();
    if (!Array.isArray(data?.hosts))
      throw new FleetTransportError("configured T3 Fleet host list is invalid");
    return data.hosts;
  }

  #sessionCache() {
    const data = this.cacheProvider();
    if (!data || typeof data !== "object" || Array.isArray(data))
      throw new FleetTransportError("existing session cache has an invalid shape");
    return data;
  }

  #runtimePortKey(host) {
    return JSON.stringify([host.name, host.ssh, host.runtimeFile ?? null]);
  }

  async #remotePort(host) {
    const key = this.#runtimePortKey(host),
      cached = this.runtimePortCache?.get(key);
    if (cached?.expiresAt > this.now() && isPort(cached.port)) {
      cached.expiresAt = this.now() + 60000;
      return cached.port;
    }
    const command = host.runtimeFile
      ? `cat ${quotePath(host.runtimeFile)}`
      : 'cat "$HOME/.t3/userdata/server-runtime.json"';
    try {
      const result = await this.execFileImpl(
        this.sshBinary,
        [...SAFE_SSH_OPTIONS, host.ssh, command],
        {
          encoding: "utf8",
          timeout: 10000,
          maxBuffer: 64 * 1024,
          windowsHide: true,
        },
      );
      const text = typeof result === "string" ? result : result.stdout;
      const runtime = JSON.parse(text);
      if (!isPort(runtime?.port))
        throw new FleetTransportError("remote T3 runtime has no valid listening port");
      // Reuse verified nonsecret runtime metadata during consecutive read pages.
      // Each operation still owns/closes its SSH forward and authenticates MCP
      // afresh. Never cache credentials or keep a shared port occupied while idle.
      this.runtimePortCache?.set(key, { port: runtime.port, expiresAt: this.now() + 60000 });
      return runtime.port;
    } catch (error) {
      if (error instanceof FleetTransportError) throw error;
      throw Object.assign(
        new FleetTransportError(
          "could not read T3 runtime metadata through the configured SSH alias",
        ),
        { code: error.code },
      );
    }
  }

  async #existingFileSession(host, base, scope) {
    // A file explicitly enrolled by the operator, produced by the pre-existing
    // refresher. Never issue, pair, refresh, persist or log a credential here.
    const path = quotePath(host.existingTokenFile);
    if (
      !host.ssh ||
      !Number.isInteger(host.tokenMaxAgeSeconds) ||
      host.tokenMaxAgeSeconds < 60 ||
      host.tokenMaxAgeSeconds > 1500
    ) {
      throw new FleetTransportError(
        "existing-token source requires SSH and a bounded freshness policy",
      );
    }
    let raw;
    try {
      const result = await this.execFileImpl(
        this.sshBinary,
        [...SAFE_SSH_OPTIONS, host.ssh, `stat -c %Y ${path} && cat ${path}`],
        { encoding: "utf8", timeout: 10000, maxBuffer: 16384, windowsHide: true },
      );
      raw = typeof result === "string" ? result : result.stdout;
    } catch (error) {
      throw Object.assign(
        new FleetTransportError(
          "existing enrolled credential source is unavailable",
          "authentication_required",
        ),
        { code: error.code, diagnosticMetadata: { credential_status: "file_unavailable" } },
      );
    }
    const newline = raw.indexOf("\n");
    const modified = Number(raw.slice(0, newline).trim()) * 1000;
    const token = raw.slice(newline + 1).trim();
    const age = this.now() - modified;
    if (
      newline < 0 ||
      !Number.isFinite(modified) ||
      age < -60000 ||
      age > host.tokenMaxAgeSeconds * 1000 ||
      token.length < 100 ||
      /\s/.test(token)
    ) {
      throw Object.assign(
        new FleetTransportError(
          "existing enrolled credential is malformed or stale; no renewal attempted",
          "authentication_required",
        ),
        { diagnosticMetadata: { credential_status: "file_stale_or_malformed" } },
      );
    }
    // CLI-issued MCP credentials do not grant a broader runtime ceiling.
    return {
      token,
      runtimeAccess: "approval-required",
      scopes: [...REQUIRED[scope]],
      cacheKey: null,
    };
  }

  async #openConfiguredTunnel(host, remotePort) {
    // Concurrent short reads/sends share an origin, but never trust or take
    // over another process's listener. Wait boundedly for it to release.
    const deadline = Date.now() + 10000;
    while (!(await isPortFree(this.netImpl, host.localPort))) {
      if (Date.now() >= deadline)
        throw new FleetTransportError(
          `configured local port ${host.localPort} remained occupied; refusing alternate origin or port`,
        );
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const forward = `127.0.0.1:${host.localPort}:127.0.0.1:${remotePort}`;
    const child = this.spawnImpl(
      this.sshBinary,
      [
        ...SAFE_SSH_OPTIONS,
        "-o",
        "ExitOnForwardFailure=yes",
        "-o",
        "ServerAliveInterval=15",
        "-N",
        "-L",
        forward,
        host.ssh,
      ],
      { stdio: "ignore", windowsHide: true },
    );
    try {
      await waitForTunnel(this.netImpl, host.localPort, child);
    } catch (error) {
      try {
        child.kill();
      } catch {
        /* best effort cleanup */
      }
      throw error;
    }
    const base = `http://127.0.0.1:${host.localPort}`;
    this.tunnels.set(host.name, child);
    return base;
  }

  #origin(host) {
    return host.url ? assertLoopbackMcpUrl(host.url) : `http://127.0.0.1:${host.localPort}`;
  }

  async #ensureRoute(host) {
    if (host.url || this.tunnels.has(host.name) || this.preopenedHosts.has(host.name)) return;
    const port =
      host.port ??
      (await diagnose(this.diagnostic, host.name, "runtime_metadata", () =>
        this.#remotePort(host),
      ));
    await diagnose(this.diagnostic, host.name, "ssh_forward", () =>
      this.#openConfiguredTunnel(host, port),
    );
  }

  async connect(hostName, scope = "read", minimumAccess = "read-only") {
    if (scope !== "read")
      throw new FleetTransportError("read-only transport rejects execution scopes");
    const host = safeHostEntry(this.#hosts(), hostName);
    const base = this.#origin(host);
    const selected = await diagnose(
      this.diagnostic,
      host.name,
      "credential",
      async () => {
        let selected;
        try {
          selected = selectExistingSession(
            this.#sessionCache(),
            host.name,
            base,
            scope,
            this.now(),
            minimumAccess,
          );
        } catch (error) {
          if (
            !host.existingTokenFile ||
            sessionRank(minimumAccess) > 1 ||
            !String(error.message).startsWith("no unexpired existing")
          )
            throw error;
          selected = await this.#existingFileSession(host, base, scope);
        }
        return selected;
      },
      (s) => ({
        credential_expires_at: s.expiresAt,
        credential_source: s.cacheKey ? "cache" : "existing_file",
      }),
    );
    await this.#ensureRoute(host);
    const client = new McpClient(`${base}/mcp`, selected.token, this.fetchImpl);
    try {
      await diagnose(this.diagnostic, host.name, "mcp_initialize", () => client.initialize());
    } catch (error) {
      this.runtimePortCache?.delete(this.#runtimePortKey(host));
      await client.dispose();
      throw error;
    }
    this.clients.add(client);
    const handle = client.readSession(scope, {
      host: host.name,
      base,
      runtimeAccess: selected.runtimeAccess,
      scopes: selected.scopes,
      expiresAt: selected.expiresAt,
    });
    return Object.freeze({
      ...handle,
      ...Object.fromEntries(
        ["searchThreads", "readThread", "listProjects", "listThreads"].map((name) => [
          name,
          (args) =>
            diagnose(this.diagnostic, host.name, "native_read", () => handle[name](args), {
              native_operation: name,
            }),
        ]),
      ),
    });
  }

  async close() {
    await Promise.all([...this.clients].map((client) => client.dispose()));
    this.clients.clear();
    for (const child of this.tunnels.values()) {
      try {
        child.kill();
      } catch {
        /* best effort cleanup */
      }
    }
    this.tunnels.clear();
  }
}
