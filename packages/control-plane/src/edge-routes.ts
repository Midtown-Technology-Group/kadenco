// SPDX-License-Identifier: AGPL-3.0-or-later
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { httpServer } from "../../../dist/server.mjs";
import { collaborationServer } from "../../../dist/collaboration-http.mjs";
import { gateEdgeMutations } from "./mutation-gate.ts";
import type { Bridge } from "../../../dist/bridge.mjs";
/** Role authentication, pending questions, Access JWT and guest capabilities stay
 * in their existing service. No principal, tool name or credential is forwarded
 * from an agent-controlled generic RPC. One fenced edge owns encrypted local state. */
export function composeEdgeRoutes(
  bridge: Bridge,
  refreshLease: () => Promise<void>,
  authenticate?: Parameters<typeof collaborationServer>[1],
  coordinate?: Parameters<typeof gateEdgeMutations>[1],
) {
  bridge = gateEdgeMutations(
    bridge,
    coordinate ??
      (async () => {
        throw Error("central_coordinator_required");
      }),
  );
  const guarded = (inner: Server) => {
    const outer = createServer((req: IncomingMessage, res: ServerResponse) => {
      void refreshLease()
        .then(() => {
          inner.emit("request", req, res);
        })
        .catch(() => {
          req.resume();
          res.writeHead(503, { "content-type": "application/json" });
          res.end(JSON.stringify({ reason: "edge_lease_unavailable", safe_to_resend: false }));
        });
    });
    return { server: outer, inner };
  };
  return {
    mcp: guarded(httpServer(bridge)),
    collaboration: guarded(collaborationServer(bridge, authenticate)),
  };
}
