// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Store } from "../../../dist/store.mjs";
import { hostLinkLimits, linkFrame, linkUuid, type LinkFrame } from "./host-links.ts";

/** Metadata inbox only. No native execution function, timer, listener, remote
 * credential or production startup is installed by importing this module. */
export class ConnectorInbox {
  private store: Store;
  readonly host: string;
  constructor(store: Store, host: string) {
    this.store = store;
    this.host = host;
    if (typeof host !== "string" || !host.length || host.length > 200)
      throw Error("host_identity_mismatch");
    const durability = store.db.prepare("PRAGMA synchronous").get();
    if (!durability || ![2, 3].includes(Number(durability.synchronous)))
      throw Error("durable_inbox_required");
    store.transaction(() => {
      const old = store.get("connector_host", "identity");
      if (old && old.host !== host) throw Error("host_identity_mismatch");
      store.insert("connector_host", "identity", { host, cursor: 0 });
    });
  }
  cursor(): number {
    return this.store.get("connector_host", "identity").cursor;
  }
  accept(items: unknown[], next: number, refused: unknown[] = []) {
    if (
      items.length + refused.length > hostLinkLimits.page ||
      !Number.isSafeInteger(next) ||
      Buffer.byteLength(JSON.stringify({ items, refused })) > hostLinkLimits.pageBytes
    )
      throw Error("invalid_connector_page");
    const frames = items.map(linkFrame);
    const refusals = refused.map((value) => {
      const r = value as { sequence: number; reason: string };
      if (
        !r ||
        Object.keys(r).some((k) => !["sequence", "reason"].includes(k)) ||
        !Number.isSafeInteger(r.sequence) ||
        r.sequence < 1 ||
        r.reason !== "forbidden"
      )
        throw Error("invalid_connector_page");
      return r;
    });
    const entries = [...frames, ...refusals].sort((a, b) => a.sequence - b.sequence);
    this.store.transaction(() => {
      let cursor = this.cursor();
      for (const frame of entries) {
        if (!("host" in frame)) {
          if (frame.sequence <= cursor) throw Error("cursor_mismatch");
          const count = this.store.db
            .prepare(
              "SELECT COUNT(*) AS n FROM records WHERE kind IN ('connector_reference','connector_refusal')",
            )
            .get();
          if (!count || Number(count.n) >= hostLinkLimits.history)
            throw Error("local_backpressure");
          this.store.insert("connector_refusal", String(frame.sequence), frame);
          cursor = frame.sequence;
          continue;
        }
        if (frame.host !== this.host || frame.sequence <= cursor)
          throw Error("host_identity_mismatch");
        const old = this.store.get("connector_reference", frame.request_id);
        if (old && JSON.stringify(old) !== JSON.stringify(frame))
          throw Error("immutable_reference");
        if (!old) {
          const count = this.store.db
            .prepare(
              "SELECT COUNT(*) AS n FROM records WHERE kind IN ('connector_reference','connector_refusal')",
            )
            .get();
          if (
            !count ||
            !Number.isSafeInteger(Number(count.n)) ||
            Number(count.n) >= hostLinkLimits.history
          )
            throw Error("local_backpressure");
          this.store.insert("connector_reference", frame.request_id, frame);
        }
        cursor = frame.sequence;
      }
      if (next !== cursor) throw Error("cursor_mismatch");
      this.store.put("connector_host", "identity", { host: this.host, cursor });
    });
  }
  read(requestId: string): LinkFrame | undefined {
    return this.store.get("connector_reference", requestId);
  }
}
export class HostConnector {
  private generation?: number;
  private opening = false;
  private held = false;
  private busy = false;
  readonly host: string;
  readonly connection: string;
  private inbox: ConnectorInbox;
  private call: (op: string, p: object) => Promise<Record<string, unknown>>;
  constructor(
    host: string,
    connection: string,
    inbox: ConnectorInbox,
    call: (op: string, p: object) => Promise<Record<string, unknown>>,
  ) {
    this.host = host;
    this.connection = connection;
    this.inbox = inbox;
    this.call = call;
    linkUuid(connection);
    if (inbox.host !== host) throw Error("host_identity_mismatch");
  }
  /** Caller schedules bounded ticks independently for each local host. HTTP is
   * supplied by the existing centralTransport; uncertainty never calls execute. */
  async tick() {
    if (this.busy) return { state: "busy" };
    if (this.held) return { state: "held" };
    this.busy = true;
    const base = { host: this.host, connection: this.connection };
    const checked = (r: Record<string, unknown>) => {
      if (r.reason !== undefined) throw Error(String(r.reason));
      if (
        r.host !== this.host ||
        r.connection !== this.connection ||
        !Number.isSafeInteger(r.generation) ||
        Number(r.generation) < 1 ||
        (this.generation !== undefined && r.generation !== this.generation)
      )
        throw Error("connector_identity_mismatch");
      return r;
    };
    try {
      if (this.generation === undefined) {
        if (this.opening) {
          const status = await this.call("link_status", base);
          if (status.reason !== undefined) throw Error(String(status.reason));
          if (
            status.host !== this.host ||
            (status.connection !== undefined && status.connection !== this.connection)
          )
            throw Error("connector_identity_mismatch");
          if (status.connection === this.connection && status.active === false)
            throw Error("fenced");
          if (status.active === true) this.generation = Number(checked(status).generation);
        }
        if (this.generation === undefined) {
          this.opening = true;
          // Connectivity registration is idempotent under this exact UUID.
          // This never retries a native command or revives a retired session.
          const opened = await this.call("link_open", base);
          if (opened.reason === "fenced") return { state: "reconcile" };
          this.generation = Number(checked(opened).generation);
        }
      }
      checked(await this.call("link_renew", { ...base, generation: this.generation }));
      const page = checked(
        await this.call("link_page", {
          ...base,
          generation: this.generation,
          after: this.inbox.cursor(),
        }),
      );
      if (
        page.generation !== this.generation ||
        !Array.isArray(page.items) ||
        typeof page.next !== "number" ||
        typeof page.more !== "boolean" ||
        (page.refused !== undefined && !Array.isArray(page.refused)) ||
        (!page.items.length && !(page.refused as unknown[] | undefined)?.length && page.more)
      )
        throw Error("connector_identity_mismatch");
      this.inbox.accept(page.items, page.next, page.refused as unknown[] | undefined);
      // Ack only after durable local commit. A lost ack is never a native resend.
      const ack = await this.call("link_ack", {
        ...base,
        generation: this.generation,
        after: page.next,
      });
      if (ack.reason !== undefined) throw Error(String(ack.reason));
      if (
        ack.host !== this.host ||
        !Number.isSafeInteger(ack.acknowledged) ||
        Number(ack.acknowledged) < page.next
      )
        throw Error("connector_identity_mismatch");
      return {
        state: "page_committed",
        cursor: this.inbox.cursor(),
        received: page.items.length,
        more: page.more,
      };
    } catch (error) {
      if (
        [
          "fenced",
          "forbidden",
          "connector_identity_mismatch",
          "host_identity_mismatch",
          "cursor_mismatch",
          "immutable_reference",
          "invalid_connector_page",
          "invalid_request",
          "connector_history_full",
          "local_backpressure",
        ].includes(error instanceof Error ? error.message : "")
      ) {
        this.held = true;
        return { state: "held" };
      }
      return { state: "reconcile" };
    } finally {
      this.busy = false;
    }
  }
}
