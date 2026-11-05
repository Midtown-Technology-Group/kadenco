// SPDX-License-Identifier: AGPL-3.0-or-later
import { randomUUID } from "node:crypto";
import type { Store } from "../../../dist/store.mjs";
import type { Grant } from "./authorization.ts";
import { HostConnector, ConnectorInbox } from "./host-connector.ts";
import { consumeHostReference } from "./host-execution.ts";
import type { LinkFrame } from "./host-links.ts";

/** Composition for an existing host lifecycle's cycle hook. No independent
 * scheduler, listener, credentials or fleet-wide singleton lease. The bootstrap
 * must supply services restricted to this original host and CURRENT authority. */
export function createHostLocalConnector(
  input: Omit<
    Parameters<typeof consumeHostReference>[0],
    "frame" | "connection" | "generation" | "grant"
  > & {
    store: Store;
    grant(frame: LinkFrame): Promise<Grant>;
  },
) {
  const connection = randomUUID();
  const inbox = new ConnectorInbox(input.store, input.host);
  const call = (op: string, p: object) => input.call(op, { epoch: input.epoch, ...p });
  const connector = new HostConnector(input.host, connection, inbox, call);
  let busy = false,
    closed = false;
  return {
    connection,
    async cycle() {
      if (closed) return { state: "closed" };
      if (busy) return { state: "busy" };
      busy = true;
      try {
        const page = await connector.tick();
        if (page.state !== "page_committed") return page;
        const session = await call("link_status", { host: input.host, connection });
        if (!session.active || !Number.isSafeInteger(session.generation)) return { state: "held" };
        // Bounded work per host; completed references never dispatch again.
        const pending = (input.store.all("connector_reference") as LinkFrame[])
          .filter((r) => !input.store.get("connector_settled", r.request_id))
          .sort((a, b) => a.sequence - b.sequence);
        const after = input.store.get("connector_drain", input.host)?.after ?? 0;
        const frames = [
          ...pending.filter((r) => r.sequence > after),
          ...pending.filter((r) => r.sequence <= after),
        ].slice(0, 4);
        let settled = 0;
        for (const frame of frames) {
          if (closed) break;
          const result = await consumeHostReference({
            ...input,
            connection,
            generation: Number(session.generation),
            frame,
            grant: () => input.grant(frame),
          });
          if (["recorded", "receipted"].includes(result.state)) {
            input.store.insert("connector_settled", frame.request_id, {
              request_id: frame.request_id,
            });
            settled++;
          }
          input.store.put("connector_drain", input.host, { after: frame.sequence });
        }
        return { state: "cycle_complete", examined: frames.length, settled };
      } finally {
        busy = false;
      }
    },
    close() {
      closed = true;
    },
  };
}
