// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ServerResponse } from "node:http";
import type { JWTVerifyGetKey } from "jose";
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { localhostHostValidation } from "@modelcontextprotocol/node";
import { SharingRequests } from "./sharing-requests.mjs";
import { Collaboration, targetArgs } from "./collaboration.mjs";

const fail = (reason) => Object.assign(new Error(reason), { reason });
const security = {
  "cache-control": "no-store",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
};
const assets = new Map(
  [
    ["/collaborate/", ["text/html; charset=utf-8", "collaboration.html"]],
    ["/collaborate/app.js", ["text/javascript; charset=utf-8", "collaboration-ui.mjs"]],
    ["/collaborate/app.css", ["text/css; charset=utf-8", "collaboration.css"]],
  ].map(([path, [mime, file]]) => [
    path,
    { mime, body: readFileSync(new URL(file, import.meta.url)) },
  ]),
);
async function boundedJson(response, max = 65536) {
  let size = 0;
  const chunks = [];
  for await (const chunk of response.body) {
    size += chunk.length;
    if (size > max) throw fail("body_too_large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString());
}

export function accessIdentity({
  keySet,
  fetchImpl = fetch,
}: { keySet?: JWTVerifyGetKey; fetchImpl?: typeof fetch } = {}) {
  const keys = new Map();
  return async (
    token,
    c,
  ): Promise<{ subject: string; email: string; expiresAt: number; identity_scope?: string }> => {
    try {
      if (typeof token !== "string" || token.length > 16384) throw fail("authentication_required");
      let jwks = keySet ?? keys.get(c.issuer);
      if (!jwks) {
        jwks = createRemoteJWKSet(new URL(c.issuer + "/cdn-cgi/access/certs"));
        keys.set(c.issuer, jwks);
      }
      const { payload } = await jwtVerify(token, jwks, {
        issuer: c.issuer,
        audience: c.audience,
        algorithms: ["RS256"],
        requiredClaims: ["exp", "sub", "email", "type"],
      });
      if (
        payload.type !== "app" ||
        typeof payload.sub !== "string" ||
        !payload.sub ||
        typeof payload.email !== "string" ||
        payload.common_name
      )
        throw fail("authentication_required");
      const response = await fetchImpl(c.issuer + "/cdn-cgi/access/get-identity", {
        headers: { cookie: "CF_Authorization=" + token },
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw fail("authentication_required");
      const identity = await boundedJson(response);
      // Access documents its signed app-token email as IdP-verified. Require
      // the matching independently resolved identity and exact configured Entra
      // provider; do not infer authority from arbitrary custom verification claims.
      if (
        identity.service_token_status ||
        identity.service_token_id ||
        identity.user_uuid !== payload.sub ||
        identity.email !== payload.email ||
        identity.idp?.id !== c.identityProviderId ||
        identity.idp?.type !== "azureAD"
      )
        throw fail("authentication_required");
      return { subject: payload.sub, email: payload.email, expiresAt: payload.exp * 1000 };
    } catch {
      throw fail("authentication_required");
    }
  };
}

export function collaborationServer(
  bridge,
  { authenticate = accessIdentity(), intervalMs = 5000 } = {},
) {
  const service = new Collaboration({
    policy: bridge.policy,
    store: bridge.store,
    reader: bridge.fleetReads,
    commands: bridge.commands,
  });
  const sharing = new SharingRequests(bridge);
  const host = localhostHostValidation(),
    streams = new Set<ServerResponse>(),
    perUser = new Map();
  let stopping = false;
  const json = (res, status, data) => {
    res.writeHead(status, { ...security, "content-type": "application/json" });
    res.end(JSON.stringify(data));
  };
  const server = createServer(async (req, res) => {
    try {
      if (!host(req, res)) return;
      const c = service.config(),
        url = new URL(req.url, "http://127.0.0.1");
      if (!url.pathname.startsWith("/collaborate/")) return json(res, 404, { reason: "not_found" });
      if (req.headers["sec-fetch-site"] === "cross-site") throw fail("forbidden");
      const user = await authenticate(req.headers["cf-access-jwt-assertion"], c);
      if (stopping) {
        res.destroy();
        return;
      }
      const live = () => {
        if (stopping) throw fail("server_stopping");
        const next = service.config();
        if (
          user.expiresAt <= Date.now() ||
          next.issuer !== c.issuer ||
          next.audience !== c.audience ||
          next.identityProviderId !== c.identityProviderId ||
          next.origin !== c.origin
        )
          throw fail("authentication_required");
      };
      live();
      user.identity_scope = service.identityScope();
      service.identity(user);
      if (req.method === "GET" && assets.has(url.pathname)) {
        const a = assets.get(url.pathname);
        res.writeHead(200, { ...security, "content-type": a.mime });
        res.end(a.body);
        return;
      }
      const p = Object.fromEntries(url.searchParams);
      if (req.method === "GET") {
        if (url.pathname === "/collaborate/api/sharing-request")
          return json(res, 200, sharing.review(user, p.request_id));
        if (url.pathname === "/collaborate/api/me") return json(res, 200, service.identity(user));
        if (url.pathname === "/collaborate/api/threads")
          return json(res, 200, { threads: service.list(user) });
        if (url.pathname === "/collaborate/api/admin")
          return json(res, 200, service.administration(user, targetArgs.parse(p)));
        if (url.pathname === "/collaborate/api/messages")
          return json(res, 200, { messages: service.messages(user, p) });
        if (url.pathname === "/collaborate/api/receipt")
          return json(res, 200, await service.receipt(user, p));
        if (url.pathname === "/collaborate/api/view") {
          const data = await service.view(user, p);
          live();
          return json(res, 200, data);
        }
        if (url.pathname === "/collaborate/api/stream") {
          const target = targetArgs.parse(p);
          service.grant(user, target);
          if (streams.size >= 32 || (perUser.get(user.subject) ?? 0) >= 2)
            throw fail("stream_limit");
          res.writeHead(200, {
            ...security,
            "content-type": "text/event-stream",
            "x-accel-buffering": "no",
          });
          res.flushHeaders();
          streams.add(res);
          perUser.set(user.subject, (perUser.get(user.subject) ?? 0) + 1);
          let timer,
            ended = false;
          const started = Date.now();
          const stop = () => {
            if (ended) return;
            ended = true;
            clearTimeout(timer);
            streams.delete(res);
            perUser.set(user.subject, Math.max(0, (perUser.get(user.subject) ?? 1) - 1));
            res.end();
          };
          res.on("close", stop);
          const tick = async () => {
            if (ended || stopping || res.writableEnded || res.destroyed) return stop();
            try {
              live();
              service.grant(user, target);
              if (Date.now() - started >= 120000 || res.writableLength > 262144) return stop();
              const data = await service.view(user, target);
              live();
              if (ended) return;
              res.write(
                "event: snapshot\ndata: " +
                  JSON.stringify({
                    ...data,
                    messages: service.messages(user, target),
                    ...(service.admin(user)
                      ? { invitations: service.invitations(user, target) }
                      : {}),
                  }) +
                  "\n\n",
              );
            } catch (e) {
              if (!ended && !stopping && !res.writableEnded && !res.destroyed)
                res.write(
                  "event: unavailable\ndata: " +
                    JSON.stringify({
                      reason: e.reason === "forbidden" ? "access_revoked" : "source_unavailable",
                    }) +
                    "\n\n",
                );
              return stop();
            }
            if (!ended) timer = setTimeout(tick, intervalMs);
          };
          void tick();
          return;
        }
      }
      if (req.method === "POST") {
        if (
          req.headers.origin !== c.origin ||
          req.headers["x-t3-collaboration"] !== "1" ||
          req.headers["content-type"] !== "application/json"
        )
          throw fail("forbidden");
        if (Number(req.headers["content-length"]) > 16384) throw fail("body_too_large");
        const body = await boundedJson({ body: req.iterator({ destroyOnReturn: false }) }, 16384);
        live();
        let data;
        if (url.pathname === "/collaborate/api/sharing-decisions")
          data = await sharing.decide(user, body);
        else if (url.pathname === "/collaborate/api/grants")
          data = await service.setGrant(user, body);
        else if (url.pathname === "/collaborate/api/invitations")
          data = await service.invite(user, body);
        else if (url.pathname === "/collaborate/api/invitations/claim")
          data = await service.claim(user, body);
        else if (url.pathname === "/collaborate/api/invitations/revoke")
          data = service.revokeInvitation(user, body);
        else if (url.pathname === "/collaborate/api/messages")
          data = await service.propose(user, body);
        else if (url.pathname === "/collaborate/api/decisions")
          data = await service.decide(user, body);
        else return json(res, 404, { reason: "not_found" });
        return json(res, 200, data);
      }
      json(res, 404, { reason: "not_found" });
    } catch (e) {
      if (res.headersSent) {
        res.end();
        return;
      }
      const reason =
        e.name === "ZodError" || e instanceof SyntaxError
          ? "invalid_request"
          : (e.reason ?? "source_unavailable");
      if (reason === "body_too_large") {
        res.setHeader("connection", "close");
        req.resume();
      }
      const known = [
        "authentication_required",
        "sharing_disabled",
        "forbidden",
        "permissions_changed",
        "invalid_request",
        "body_too_large",
        "invalid_expiry",
        "identity_not_seen",
        "invitation_unavailable",
        "grant_already_exists",
        "revision_conflict",
        "idempotency_conflict",
        "not_found",
        "pending_limit",
        "stream_limit",
      ];
      json(
        res,
        reason === "authentication_required"
          ? 401
          : reason === "body_too_large"
            ? 413
            : reason === "source_unavailable"
              ? 503
              : 403,
        { reason: known.includes(reason) ? reason : "source_unavailable", safe_to_resend: false },
      );
    }
  });
  const managed = server as typeof server & { stopStreams(): void };
  managed.stopStreams = () => {
    stopping = true;
    for (const res of streams) res.end();
  };
  server.requestTimeout = 30000;
  server.headersTimeout = 10000;
  return managed;
}
