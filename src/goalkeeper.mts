// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import type { Store } from "./store.mjs";

const targetSchema = z
  .object({
    host: z.string().min(1).max(100),
    thread_id: z.string().min(1).max(2048),
    source_run_id: z.string().min(1).max(2048),
  })
  .strict();
export type GoalkeeperTarget = z.infer<typeof targetSchema>;
export type GoalkeeperState = {
  host: string;
  thread_id: string;
  latest_run_id: string | null;
  latest_status: string | null;
  active: boolean | null;
  queued: boolean | null;
  pending_request: boolean | null;
  pending_question: boolean | null;
  stopped: boolean | null;
  snoozed: boolean | null;
  unavailable: boolean | null;
  authorized: boolean;
  authorization_revision: string | null;
  work_remaining: boolean | null;
};
type Stage =
  | "prepared"
  | "dispatched"
  | "accepted_queued"
  | "observed_running"
  | "completed"
  | "refused"
  | "uncertain";
type Candidate = GoalkeeperTarget & {
  owner: string;
  request_id: string;
  state: Stage;
  observed_stage: Stage | null;
  created_at: number;
  authorization_revision: string | null;
  reason: string | null;
  run_id: string | null;
};
export type GoalkeeperReceipt = GoalkeeperTarget & {
  owner: string;
  request_id: string;
  stage: "accepted_queued" | "observed_running" | "completed" | "refused";
  run_id: string | null;
};
export type GoalkeeperPorts = {
  read(owner: string, target: GoalkeeperTarget): Promise<GoalkeeperState>;
  send(
    owner: string,
    target: GoalkeeperTarget & { request_id: string; message: string },
    beforeDispatch: () => Promise<void>,
  ): Promise<GoalkeeperReceipt>;
  receipt(owner: string, requestId: string): Promise<GoalkeeperReceipt | null>;
  // Trusted native adapter capabilities, never caller-supplied booleans.
  preservesStopThroughSubmission: boolean;
  enforcesContinuationEntry: boolean;
  checkpoint(): Promise<void>;
};
export const GOALKEEPER_COOLDOWN_MS = 15 * 60 * 1000;
export const GOALKEEPER_INSTRUCTION =
  "Recheck the current owner thread state, latest user instructions and authorization before doing anything. Do nothing if paused, stopped, snoozed, superseded, already covered, awaiting a native question or required approval, or no authorized work remains. Otherwise continue only the already-authorized Kadenco work. This message grants no new scope, external commitment, access, spending, runtime change or permission to bypass a human control. Do not create another continuation for a no-op or the same blocker.";
const hash = (v: unknown) => createHash("sha256").update(JSON.stringify(v)).digest("hex");
const failure = (reason: string) => Object.assign(Error(reason), { reason });
const identity = (owner: string, t: GoalkeeperTarget) =>
  hash([owner, t.host, t.thread_id, t.source_run_id]);
const lane = (owner: string, t: GoalkeeperTarget) => hash([owner, t.host, t.thread_id]);
const immutable = new Set<Stage>(["completed", "refused"]);

/** No timer, monitor, autonomous task selection or native queue guarantee.
 * Production capabilities remain false until a real stop/entry contract exists.
 * Atomic claims cover one existing Store/active writer, not independent replicas. */
export class Goalkeeper {
  constructor(
    readonly store: Store,
    readonly ports: GoalkeeperPorts,
    readonly now = Date.now,
  ) {}
  private audit(c: Candidate, outcome: string) {
    this.store.audit("goalkeeper." + outcome, c.request_id, c.state);
  }
  private get(owner: string, input: GoalkeeperTarget): Candidate {
    const t = targetSchema.parse(input),
      c = this.store.get("goalkeeper", identity(owner, t));
    if (
      !c ||
      c.owner !== owner ||
      c.host !== t.host ||
      c.thread_id !== t.thread_id ||
      c.source_run_id !== t.source_run_id
    )
      throw failure("goalkeeper_identity_mismatch");
    return c;
  }
  private update(
    c: Candidate,
    state: Stage,
    reason: string | null = null,
    run_id = c.run_id,
    expected?: Stage,
  ) {
    return this.store.transaction(() => {
      const latest = this.get(c.owner, {
        host: c.host,
        thread_id: c.thread_id,
        source_run_id: c.source_run_id,
      });
      if (immutable.has(latest.state)) return latest;
      if (expected && latest.state !== expected) return latest;
      if (latest.state === "observed_running" && state === "accepted_queued") return latest;
      const value = { ...latest, state, reason, run_id: run_id ?? latest.run_id };
      this.store.put("goalkeeper", identity(c.owner, c), value);
      this.audit(value, state);
      return value;
    });
  }
  prepare(owner: string, input: GoalkeeperTarget) {
    const t = targetSchema.parse(input);
    if (!owner || owner.length > 200) throw failure("goalkeeper_identity_mismatch");
    return this.store.transaction(() => {
      const id = identity(owner, t),
        old = this.store.get("goalkeeper", id);
      if (old) return old as Candidate;
      const c: Candidate = {
        ...t,
        owner,
        request_id: randomUUID(),
        state: "prepared",
        observed_stage: null,
        created_at: this.now(),
        authorization_revision: null,
        reason: null,
        run_id: null,
      };
      this.store.insert("goalkeeper", id, c);
      this.audit(c, "prepared");
      return this.store.get("goalkeeper", id) as Candidate;
    });
  }
  private check(c: Candidate, s: GoalkeeperState, entry = false) {
    if (s.host !== c.host || s.thread_id !== c.thread_id)
      throw failure("goalkeeper_identity_mismatch");
    if (!s.authorized || !s.authorization_revision)
      throw failure("goalkeeper_authority_unavailable");
    if (entry && s.authorization_revision !== c.authorization_revision)
      throw failure("goalkeeper_authority_changed");
    if (s.stopped !== false || s.snoozed !== false || s.unavailable !== false)
      throw failure("goalkeeper_stop_state_unavailable_or_set");
    if (s.pending_question !== false || s.pending_request !== false)
      throw failure("goalkeeper_pending_or_unknown_request");
    if (s.work_remaining !== true) throw failure("goalkeeper_no_authorized_work");
    if (s.queued === true) throw failure("goalkeeper_source_changed_or_busy");
    if (entry) {
      if (
        !c.run_id ||
        s.latest_run_id !== c.run_id ||
        s.latest_status !== "running" ||
        s.active !== true
      )
        throw failure("goalkeeper_source_changed");
    } else if (
      s.latest_run_id !== c.source_run_id ||
      s.latest_status !== "completed" ||
      s.active !== false
    ) {
      throw failure("goalkeeper_source_changed_or_busy");
    }
    // queued:null is consciously best effort; it never means an empty queue.
  }
  private async read(c: Candidate) {
    try {
      return await this.ports.read(c.owner, {
        host: c.host,
        thread_id: c.thread_id,
        source_run_id: c.source_run_id,
      });
    } catch {
      throw failure("goalkeeper_read_unavailable");
    }
  }
  async dispatch(owner: string, input: GoalkeeperTarget) {
    let c = this.get(owner, input);
    if (c.state !== "prepared") return this.reconcile(owner, input);
    let snapshot: GoalkeeperState;
    try {
      snapshot = await this.read(c);
      this.check(c, snapshot);
    } catch (e) {
      return this.update(
        c,
        "refused",
        e.reason ?? "goalkeeper_read_unavailable",
        c.run_id,
        "prepared",
      );
    }
    if (!this.ports.preservesStopThroughSubmission || !this.ports.enforcesContinuationEntry)
      return {
        ...c,
        blocked: "native_stop_preservation_and_entry_gate_unavailable",
        unattended_dispatch_enabled: false,
      };
    const admitted = this.store.transaction(() => {
      c = this.get(owner, input);
      if (c.state !== "prepared") return false;
      const k = lane(owner, c),
        clock = this.store.get("goalkeeper_clock", k),
        now = this.now();
      if (clock && (now < clock.observed || now - clock.attempted < GOALKEEPER_COOLDOWN_MS))
        return false;
      // An unbound prior outcome cannot exclude self-triggered or covered work.
      if (clock && !clock.run_id) return false;
      // A goalkeeper's own completion cannot form an endless automatic chain.
      if (
        clock?.run_id === c.source_run_id &&
        clock.authorization_revision === snapshot.authorization_revision
      )
        return false;
      this.store.put("goalkeeper_clock", k, {
        observed: now,
        attempted: now,
        request_id: c.request_id,
        run_id: null,
        authorization_revision: snapshot.authorization_revision,
      });
      c = { ...c, state: "dispatched", authorization_revision: snapshot.authorization_revision };
      this.store.put("goalkeeper", identity(owner, c), c);
      this.audit(c, "dispatched");
      return true;
    });
    if (!admitted)
      return {
        ...this.get(owner, input),
        blocked: "cooldown_clock_or_existing_claim",
        unattended_dispatch_enabled: false,
      };
    // From this point a crash is uncertain even if it occurred before actual IO.
    try {
      await this.ports.checkpoint();
    } catch {
      return this.update(c, "uncertain", "goalkeeper_checkpoint_unavailable");
    }
    const guard = async () => {
      const candidate = this.get(owner, input);
      if (!["dispatched", "uncertain"].includes(candidate.state))
        throw failure("goalkeeper_already_covered");
      const current = await this.read(c);
      this.check(c, current);
      if (current.authorization_revision !== c.authorization_revision)
        throw failure("goalkeeper_authority_changed");
    };
    try {
      await guard();
      const receipt = await this.ports.send(
        owner,
        { ...input, request_id: c.request_id, message: GOALKEEPER_INSTRUCTION },
        guard,
      );
      return this.applyReceipt(c, receipt);
    } catch {
      // The adapter may have submitted before failing: no blind retry, even for
      // an apparent guard/transport exception. Only exact receipts can resolve it.
      const current = this.get(owner, input);
      if (["accepted_queued", "observed_running", "completed", "refused"].includes(current.state))
        return current;
      return this.update(c, "uncertain", "goalkeeper_submission_uncertain");
    }
  }
  private applyReceipt(c: Candidate, r: GoalkeeperReceipt) {
    return this.store.transaction(() => {
      c = this.get(c.owner, {
        host: c.host,
        thread_id: c.thread_id,
        source_run_id: c.source_run_id,
      });
      if (immutable.has(c.state)) return c;
      const write = (
        state: Stage,
        reason: string | null,
        observed = c.observed_stage,
        run = c.run_id,
      ) => {
        const value = { ...c, state, reason, observed_stage: observed, run_id: run };
        this.store.put("goalkeeper", identity(c.owner, c), value);
        this.audit(value, state);
        return value;
      };
      if (
        r.owner !== c.owner ||
        r.request_id !== c.request_id ||
        r.host !== c.host ||
        r.thread_id !== c.thread_id ||
        r.source_run_id !== c.source_run_id ||
        !["accepted_queued", "observed_running", "completed", "refused"].includes(r.stage) ||
        (["observed_running", "completed"].includes(r.stage) && !r.run_id)
      )
        return write("uncertain", "goalkeeper_receipt_identity_mismatch");
      if (c.run_id && r.run_id && c.run_id !== r.run_id)
        return write("uncertain", "goalkeeper_receipt_identity_mismatch");
      if (c.observed_stage === "observed_running" && r.stage === "accepted_queued") return c;
      const value = write(r.stage, null, r.stage, r.run_id ?? c.run_id);
      if (r.run_id) {
        const k = lane(c.owner, c),
          clock = this.store.get("goalkeeper_clock", k);
        if (clock?.request_id === c.request_id)
          this.store.put("goalkeeper_clock", k, { ...clock, run_id: r.run_id });
      }
      return value;
    });
  }
  async reconcile(owner: string, input: GoalkeeperTarget) {
    const c = this.get(owner, input);
    if (c.state === "prepared" || immutable.has(c.state)) return c;
    try {
      const r = await this.ports.receipt(owner, c.request_id);
      return r
        ? this.applyReceipt(c, r)
        : this.update(c, "uncertain", "goalkeeper_receipt_unavailable");
    } catch {
      return this.update(c, "uncertain", "goalkeeper_receipt_unavailable");
    }
  }
  async enter(owner: string, input: GoalkeeperTarget, requestId: string) {
    if (!this.ports.enforcesContinuationEntry)
      return { may_continue: false, reason: "goalkeeper_entry_gate_unavailable" };
    const c = this.get(owner, input);
    if (c.request_id !== requestId || !["accepted_queued", "observed_running"].includes(c.state))
      return { may_continue: false, reason: "goalkeeper_entry_identity_or_state" };
    try {
      this.check(c, await this.read(c), true);
      return { may_continue: true, scope: "existing_authorized_kadenco_work_only" };
    } catch {
      this.update(c, "refused", "goalkeeper_entry_refused");
      return { may_continue: false, reason: "goalkeeper_entry_refused" };
    }
  }
}
