// SPDX-License-Identifier: AGPL-3.0-or-later
/** Inert operation adapter. Callers supply authenticated transport and a durable journal.
 * No timers, credentials, native routes or production startup are installed here. */
export type Command = { request_id: string; epoch: number; host: string; thread_id: string };
export type Outcome = { state: "observed" | "unknown"; evidence: string };
export interface AttemptJournal {
  // Atomic insert-if-absent, persisted before any begin request. Never expire attempts.
  reserve(id: string): Promise<boolean>;
  finish(id: string, outcome: Outcome): Promise<void>;
}
export interface EdgePorts {
  call(op: string, body: object): Promise<Record<string, unknown>>;
  journal: AttemptJournal;
  // Must independently enforce operation/project/provider/run/grant bindings.
  validate(command: Command): Promise<void>;
  execute(command: Command): Promise<Outcome>;
  // Read-only native reconciliation; never submit from this method.
  observe(command: Command): Promise<Outcome>;
}
export async function consume(command: Command, ports: EdgePorts) {
  const base = { request_id: command.request_id, epoch: command.epoch };
  // Claim is effect-free and revalidates originating authority in the DO.
  // Pending receipts are deliberately invisible to unassigned executors.
  await ports.validate(command);
  const claimed = await ports.call("claim", { ...base, lease_ms: 10000 });
  if (claimed.claimed === false && ["uncertain", "receipted"].includes(String(claimed.state))) {
    const prior = await ports.call("receipt", { request_id: command.request_id });
    if (prior.state === "receipted") return { state: "receipted", receipt: prior.receipt };
    return { state: "reconcile", outcome: await ports.observe(command) };
  }
  if (claimed.claimed !== true || !Number.isSafeInteger(claimed.generation))
    return { state: "blocked" };
  if (claimed.host !== command.host || claimed.thread !== command.thread_id)
    return { state: "blocked" };
  const binding = { ...base, generation: claimed.generation };
  // A lost begin response cannot be retried, even after consumer reconstruction.
  if (!(await ports.journal.reserve(command.request_id)))
    return { state: "reconcile", outcome: await ports.observe(command) };
  await ports.validate(command);
  let permit: Record<string, unknown>;
  try {
    permit = await ports.call("begin", binding);
  } catch {
    return { state: "reconcile", outcome: await ports.observe(command) };
  }
  if (
    permit.may_attempt !== true ||
    permit.request_id !== command.request_id ||
    permit.generation !== claimed.generation
  )
    return { state: "blocked" };
  let outcome: Outcome;
  try {
    outcome = await ports.execute(command);
  } catch {
    outcome = { state: "unknown", evidence: "execution_response_unavailable" };
  }
  await ports.journal.finish(command.request_id, outcome);
  if (outcome.state === "unknown") return { state: "reconcile", outcome };
  // An uncertain receipt write is reconciled on reconnect; never repeat execute.
  try {
    await ports.call("record_receipt", { ...binding, receipt: outcome });
  } catch {
    return { state: "reconcile", outcome };
  }
  return { state: "recorded", outcome };
}
