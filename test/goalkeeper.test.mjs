// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawn } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { Store } from "../dist/store.mjs";
import { Goalkeeper, GOALKEEPER_COOLDOWN_MS, GOALKEEPER_INSTRUCTION } from "../dist/goalkeeper.mjs";
import { Commands } from "../dist/commands.mjs";

const target = {
  host: "fixture-host",
  thread_id: "fixture-thread",
  source_run_id: "completed-source",
};
function fixture(t) {
  const store = new Store(":memory:", randomBytes(32));
  t.after(() => store.close());
  let now = 1000000,
    sends = 0,
    reads = 0,
    receipt = null;
  const state = {
    host: target.host,
    thread_id: target.thread_id,
    latest_run_id: target.source_run_id,
    latest_status: "completed",
    active: false,
    queued: null,
    pending_request: false,
    pending_question: false,
    stopped: false,
    snoozed: false,
    unavailable: false,
    authorized: true,
    authorization_revision: "approved-goal-v1",
    work_remaining: true,
  };
  const ports = {
    preservesStopThroughSubmission: true,
    enforcesContinuationEntry: true,
    async checkpoint() {},
    async read() {
      reads++;
      return { ...state };
    },
    async send(owner, p, guard) {
      await guard();
      sends++;
      receipt = {
        ...target,
        source_run_id: p.source_run_id,
        owner,
        request_id: p.request_id,
        stage: "accepted_queued",
        run_id: "nudge-run",
      };
      return receipt;
    },
    async receipt() {
      return receipt;
    },
  };
  const g = new Goalkeeper(store, ports, () => now);
  return {
    g,
    store,
    ports,
    state,
    counts: () => ({ sends, reads }),
    setNow: (v) => (now = v),
    setReceipt: (r) => (receipt = r),
    receipt: () => receipt,
    prepare: () => g.prepare("owner", target),
  };
}
test("duplicate completion and concurrent async dispatch share one candidate and one send", async (t) => {
  const f = fixture(t),
    a = f.prepare();
  assert.equal(f.prepare().request_id, a.request_id);
  await Promise.all([f.g.dispatch("owner", target), f.g.dispatch("owner", target)]);
  assert.equal(f.counts().sends, 1);
  assert.equal(f.store.all("goalkeeper").length, 1);
});
test("atomic file-backed claims converge across separate processes and survive restart before send", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "goalkeeper-claims-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "state.db"),
    key = randomBytes(32),
    initial = new Store(path, key);
  initial.close();
  const code = `import {Store} from ${JSON.stringify(new URL("../dist/store.mjs", import.meta.url).href)};import {Goalkeeper} from ${JSON.stringify(new URL("../dist/goalkeeper.mjs", import.meta.url).href)};const s=new Store(process.argv[1],Buffer.from(process.argv[2],'hex'));console.log(new Goalkeeper(s,{}).prepare('owner',${JSON.stringify(target)}).request_id);s.close();`;
  const run = () =>
    new Promise((resolve, reject) => {
      const p = spawn(
        process.execPath,
        ["--input-type=module", "-e", code, path, key.toString("hex")],
        { windowsHide: true },
      );
      let out = "",
        err = "";
      p.stdout.on("data", (x) => (out += x));
      p.stderr.on("data", (x) => (err += x));
      p.on("error", reject);
      p.on("exit", (c) => (c === 0 ? resolve(out.trim()) : reject(Error(err))));
    });
  const ids = await Promise.all([run(), run(), run()]);
  assert.equal(new Set(ids).size, 1);
  const reopened = new Store(path, key);
  try {
    assert.equal(new Goalkeeper(reopened, {}).prepare("owner", target).request_id, ids[0]);
    const f = fixture(t);
    assert.equal(
      (await new Goalkeeper(reopened, f.ports).dispatch("owner", target)).request_id,
      ids[0],
    );
    assert.equal(f.counts().sends, 1);
  } finally {
    reopened.close();
  }
});
test("Store installs its existing busy timeout before WAL initialization waits on another opener", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "goalkeeper-open-lock-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, "locked.db"),
    key = randomBytes(32),
    holder = new DatabaseSync(path);
  holder.exec("CREATE TABLE fixture(id INTEGER); BEGIN EXCLUSIVE");
  const code = `import {Store} from ${JSON.stringify(new URL("../dist/store.mjs", import.meta.url).href)};process.stdout.write('opening\\n');const s=new Store(process.argv[1],Buffer.from(process.argv[2],'hex'));s.close();`;
  let release;
  try {
    await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        ["--input-type=module", "-e", code, path, key.toString("hex")],
        { windowsHide: true },
      );
      let err = "",
        scheduled = false;
      child.stderr.on("data", (x) => (err += x));
      child.stdout.on("data", () => {
        if (!scheduled) {
          scheduled = true;
          release = setTimeout(() => holder.exec("COMMIT"), 100);
        }
      });
      child.on("error", reject);
      child.on("exit", (status) => (status === 0 ? resolve() : reject(Error(err))));
    });
  } finally {
    clearTimeout(release);
    try {
      holder.exec("ROLLBACK");
    } catch {}
    holder.close();
  }
});
for (const point of [
  "immediately-before-submit",
  "immediately-after-submit",
  "accepted-response-lost",
])
  test(`crash window ${point} never resends and reconciles only the stable receipt`, async (t) => {
    const f = fixture(t),
      c = f.prepare();
    let native = 0;
    f.ports.send = async (owner, p) => {
      if (point !== "immediately-before-submit") {
        native++;
        f.setReceipt({
          ...target,
          owner,
          request_id: p.request_id,
          stage: "accepted_queued",
          run_id: "nudge-run",
        });
      }
      throw Error("fixture lost response, secret must not leak");
    };
    assert.equal((await f.g.dispatch("owner", target)).state, "uncertain");
    const restarted = new Goalkeeper(f.store, f.ports, () => 1000000);
    const r = await restarted.dispatch("owner", target);
    assert.equal(r.request_id, c.request_id);
    assert.equal(native, point === "immediately-before-submit" ? 0 : 1);
    assert.equal(r.state, point === "immediately-before-submit" ? "uncertain" : "accepted_queued");
  });
test("persisted dispatched intent with no receipt remains uncertain after reconstruction", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.ports.checkpoint = async () => {
    throw Error("fixture crash after intent");
  };
  assert.equal((await f.g.dispatch("owner", target)).state, "uncertain");
  assert.equal(
    (await new Goalkeeper(f.store, f.ports).dispatch("owner", target)).state,
    "uncertain",
  );
  assert.equal(f.counts().sends, 0);
});
test("accepted, observed running, and completed receipts stay distinct and terminal state never regresses", async (t) => {
  const f = fixture(t);
  f.prepare();
  assert.equal((await f.g.dispatch("owner", target)).state, "accepted_queued");
  f.setReceipt({ ...f.receipt(), stage: "observed_running" });
  assert.equal((await f.g.reconcile("owner", target)).state, "observed_running");
  f.setReceipt({ ...f.receipt(), stage: "accepted_queued" });
  assert.equal((await f.g.reconcile("owner", target)).state, "observed_running");
  f.setReceipt({ ...f.receipt(), stage: "completed" });
  assert.equal((await f.g.reconcile("owner", target)).state, "completed");
  f.setReceipt(null);
  assert.equal((await f.g.reconcile("owner", target)).state, "completed");
  assert.equal(f.counts().sends, 1);
});
test("a delayed duplicate preflight failure cannot refuse an already accepted candidate", async (t) => {
  const f = fixture(t);
  f.prepare();
  let release;
  const waiting = new Promise((resolve) => (release = resolve));
  let n = 0;
  f.ports.read = async () => {
    if (++n === 1) {
      await waiting;
      throw Error("late read outage");
    }
    return { ...f.state };
  };
  const delayed = f.g.dispatch("owner", target);
  assert.equal((await f.g.dispatch("owner", target)).state, "accepted_queued");
  release();
  assert.equal((await delayed).state, "accepted_queued");
  assert.equal(f.counts().sends, 1);
});
for (const [name, patch] of Object.entries({
  "delayed completion after later run": { latest_run_id: "later" },
  "active run": { active: true },
  "unknown active state": { active: null },
  "known queued work": { queued: true },
  "pending native request": { pending_request: true },
  "native question": { pending_question: true },
  "approval pending": { pending_request: true },
  "stop before dispatch": { stopped: true },
  "snooze before dispatch": { snoozed: true },
  "unknown stop": { stopped: null },
  "unknown snooze": { snoozed: null },
  "archived or settled": { unavailable: true },
  "expired authority": { authorized: false },
  "withdrawn authority": { authorization_revision: null },
  "no work": { work_remaining: false },
  "unknown goal work": { work_remaining: null },
  "wrong host": { host: "foreign" },
  "wrong thread": { thread_id: "foreign" },
}))
  test(`suppresses ${name}`, async (t) => {
    const f = fixture(t);
    f.prepare();
    Object.assign(f.state, patch);
    assert.equal((await f.g.dispatch("owner", target)).state, "refused");
    assert.equal(f.counts().sends, 0);
  });
test("incomplete public queue visibility remains explicitly best effort", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.state.queued = null;
  assert.equal((await f.g.dispatch("owner", target)).state, "accepted_queued");
  assert.equal(f.state.queued, null);
});
test("fresh read catches a competing run before send", async (t) => {
  const f = fixture(t);
  f.prepare();
  let n = 0;
  f.ports.read = async () => ({ ...f.state, ...(++n > 1 ? { latest_run_id: "manual-run" } : {}) });
  assert.equal((await f.g.dispatch("owner", target)).state, "refused");
  assert.equal(f.counts().sends, 0);
});
test("authority withdrawn between admission and final read cannot dispatch", async (t) => {
  const f = fixture(t);
  f.prepare();
  let reads = 0;
  f.ports.read = async () => ({ ...f.state, authorized: ++reads === 1 });
  assert.equal((await f.g.dispatch("owner", target)).state, "refused");
  assert.equal(f.counts().sends, 0);
});
for (const cause of ["new-run", "authority", "read-outage", "stop", "snooze"])
  test(`definite local guard refusal releases only its lane claim after cooldown: ${cause}`, async (t) => {
    const f = fixture(t),
      first = f.prepare();
    let reads = 0;
    f.ports.read = async () => {
      if (++reads === 2) {
        if (cause === "read-outage") throw Error("fixture outage");
        return {
          ...f.state,
          ...(cause === "new-run"
            ? { latest_run_id: "manual-run" }
            : cause === "authority"
              ? { authorized: false }
              : cause === "stop"
                ? { stopped: true }
                : { snoozed: true }),
        };
      }
      return { ...f.state };
    };
    const refused = await f.g.dispatch("owner", target);
    assert.equal(refused.state, "refused");
    assert.equal(refused.request_id, first.request_id);
    assert.equal(f.counts().sends, 0);
    const next = { ...target, source_run_id: "later-completed" };
    f.state.latest_run_id = next.source_run_id;
    const later = f.g.prepare("owner", next);
    f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS - 1);
    assert.ok((await f.g.dispatch("owner", next)).blocked);
    f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS);
    assert.equal((await f.g.dispatch("owner", next)).state, "accepted_queued");
    assert.equal(f.counts().sends, 1);
    assert.equal(f.g.prepare("owner", target).request_id, first.request_id);
    assert.notEqual(later.request_id, first.request_id);
  });
test("guard failure inside ports.send stays ambiguous and cannot release the lane", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.ports.send = async (_owner, _p, guard) => {
    f.state.stopped = true;
    await guard();
    throw Error("unreachable");
  };
  assert.equal((await f.g.dispatch("owner", target)).state, "uncertain");
  const next = { ...target, source_run_id: "later-completed" };
  Object.assign(f.state, { stopped: false, latest_run_id: next.source_run_id });
  f.g.prepare("owner", next);
  f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS);
  assert.ok((await f.g.dispatch("owner", next)).blocked);
});
test("an older accepted receipt after a running receipt outage cannot erase running evidence", async (t) => {
  const f = fixture(t);
  f.prepare();
  await f.g.dispatch("owner", target);
  f.setReceipt({ ...f.receipt(), stage: "observed_running" });
  await f.g.reconcile("owner", target);
  const r = { ...f.receipt(), stage: "accepted_queued" };
  f.setReceipt(null);
  assert.equal((await f.g.reconcile("owner", target)).state, "uncertain");
  f.setReceipt(r);
  const recovered = await f.g.reconcile("owner", target);
  assert.equal(recovered.state, "uncertain");
  assert.equal(recovered.observed_stage, "observed_running");
});
for (const flag of ["stopped", "snoozed"])
  test(`native fixture preserves ${flag} during read-to-send race and continuation entry`, async (t) => {
    const f = fixture(t);
    f.prepare();
    let effects = 0;
    f.ports.send = async (owner, p, guard) => {
      await guard();
      f.state[flag] = true;
      if (f.state[flag]) throw Error("fixture native preservation");
      effects++;
      return {
        ...target,
        owner,
        request_id: p.request_id,
        stage: "accepted_queued",
        run_id: "nudge-run",
      };
    };
    await f.g.dispatch("owner", target);
    assert.equal(effects, 0);
    const h = fixture(t);
    h.prepare();
    const c = await h.g.dispatch("owner", target);
    h.state.latest_run_id = "nudge-run";
    h.state.latest_status = "running";
    h.state.active = true;
    h.state[flag] = true;
    assert.equal((await h.g.enter("owner", target, c.request_id)).may_continue, false);
  });
for (const patch of [
  { authorized: false },
  { authorization_revision: "narrowed" },
  { work_remaining: false },
  { latest_run_id: "superseded" },
  { pending_request: true },
  { stopped: null },
  { snoozed: null },
])
  test(`entry rechecks narrowed/cancelled/superseded/no-work state ${JSON.stringify(patch)}`, async (t) => {
    const f = fixture(t);
    f.prepare();
    const c = await f.g.dispatch("owner", target);
    Object.assign(
      f.state,
      { latest_run_id: "nudge-run", latest_status: "running", active: true },
      patch,
    );
    assert.equal((await f.g.enter("owner", target, c.request_id)).may_continue, false);
  });
test("cooldown boundary, clock rollback, and own no-op completion cannot create a chain", async (t) => {
  const f = fixture(t);
  f.prepare();
  await f.g.dispatch("owner", target);
  const next = { ...target, source_run_id: "manual-new-source" };
  f.state.latest_run_id = next.source_run_id;
  f.g.prepare("owner", next);
  f.setNow(999999);
  assert.ok((await f.g.dispatch("owner", next)).blocked);
  f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS - 1);
  assert.ok((await f.g.dispatch("owner", next)).blocked);
  f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS);
  await f.g.dispatch("owner", next);
  assert.equal(f.counts().sends, 2);
  const own = { ...target, source_run_id: "nudge-run" };
  f.g.prepare("owner", own);
  f.state.latest_run_id = own.source_run_id;
  f.setNow(1000000 + 2 * GOALKEEPER_COOLDOWN_MS);
  assert.ok((await f.g.dispatch("owner", own)).blocked);
  assert.equal(f.counts().sends, 2);
});
test("read and receipt outages never become retries or completion evidence", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.ports.read = async () => {
    throw Error("private read error");
  };
  assert.equal((await f.g.dispatch("owner", target)).state, "refused");
  assert.equal(f.counts().sends, 0);
  const h = fixture(t);
  h.prepare();
  await h.g.dispatch("owner", target);
  h.ports.receipt = async () => {
    throw Error("private receipt error");
  };
  assert.equal((await h.g.dispatch("owner", target)).state, "uncertain");
  assert.equal(h.counts().sends, 1);
});
test("an accepted but unbound run suspends further automatic candidates", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.ports.send = async (owner, p) => ({
    ...target,
    owner,
    request_id: p.request_id,
    stage: "accepted_queued",
    run_id: null,
  });
  await f.g.dispatch("owner", target);
  const next = { ...target, source_run_id: "unverified-later-source" };
  f.state.latest_run_id = next.source_run_id;
  f.g.prepare("owner", next);
  f.setNow(1000000 + GOALKEEPER_COOLDOWN_MS);
  assert.ok((await f.g.dispatch("owner", next)).blocked);
});
for (const [field, value] of Object.entries({
  owner: "foreign",
  host: "foreign",
  thread_id: "foreign",
  source_run_id: "foreign",
  request_id: "foreign",
  run_id: "foreign",
}))
  test(`mismatched receipt ${field} refuses adoption`, async (t) => {
    const f = fixture(t);
    f.prepare();
    await f.g.dispatch("owner", target);
    f.setReceipt({ ...f.receipt(), [field]: value });
    assert.equal((await f.g.reconcile("owner", target)).state, "uncertain");
    assert.equal(f.counts().sends, 1);
  });
test("missing native stop preservation/entry support disables unattended dispatch", async (t) => {
  const f = fixture(t);
  f.prepare();
  f.ports.preservesStopThroughSubmission = false;
  assert.equal((await f.g.dispatch("owner", target)).unattended_dispatch_enabled, false);
  assert.equal(f.counts().sends, 0);
});
test("entry admits only its bound running continuation and authorized work", async (t) => {
  const f = fixture(t);
  f.prepare();
  const c = await f.g.dispatch("owner", target);
  Object.assign(f.state, { latest_run_id: "nudge-run", latest_status: "running", active: true });
  assert.equal((await f.g.enter("owner", target, c.request_id)).may_continue, true);
  assert.equal((await f.g.enter("owner", target, "foreign-request")).may_continue, false);
});
test("a run queued after the final read remains a race, and entry suppresses already-covered work", async (t) => {
  const f = fixture(t);
  f.prepare();
  let substantive = 0;
  const original = f.ports.send;
  f.ports.send = async (owner, p, guard) => {
    await guard();
    f.state.latest_run_id = "competing-manual-run";
    return original(owner, p, async () => {});
  };
  const c = await f.g.dispatch("owner", target);
  assert.equal(c.state, "accepted_queued");
  Object.assign(f.state, {
    latest_run_id: "nudge-run",
    latest_status: "running",
    active: true,
    work_remaining: false,
  });
  if ((await f.g.enter("owner", target, c.request_id)).may_continue) substantive++;
  assert.equal(substantive, 0);
});
test("audit is per-request fixed-field metadata and instruction grants no expanded scope", async (t) => {
  const f = fixture(t),
    c = f.prepare();
  f.ports.send = async () => {
    throw Error("TOKEN-private-user-message");
  };
  await f.g.dispatch("owner", target);
  const audit = f.store.db.prepare("SELECT action,subject,outcome FROM audit").all();
  assert.ok(audit.every((x) => x.subject === c.request_id));
  assert.equal(JSON.stringify(audit).includes("TOKEN"), false);
  assert.match(GOALKEEPER_INSTRUCTION, /stopped, snoozed/);
  assert.match(GOALKEEPER_INSTRUCTION, /grants no new scope/);
});
test("existing Commands integration stays disabled and adds no monitor or manual continuation hook", async (t) => {
  const f = fixture(t),
    commands = new Commands({ store: f.store, policy: () => ({ principals: [] }), reader: {} });
  assert.equal(commands.goalkeeper.ports.preservesStopThroughSubmission, false);
  assert.equal(commands.goalkeeper.ports.enforcesContinuationEntry, false);
  assert.equal(f.store.all("subscription").length, 0);
  assert.equal(f.store.all("command").length, 0);
});
