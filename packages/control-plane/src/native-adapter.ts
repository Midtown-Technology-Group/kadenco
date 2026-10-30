// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Envelope } from "./authorization.ts";
import type { Outcome } from "./edge.ts";
import { continueArgs, answerArgs } from "../../../dist/commands.mjs";
import { createArgs } from "../../../dist/creation.mjs";
import { standardSpeedArgs } from "../../../dist/thread-settings.mjs";
/** Existing sidecar services remain the enforcement boundary: grants, budgets,
 * provider/runtime ceilings, approvals, exact drift and stable native IDs. */
export interface SidecarServices {
  followup?(
    owner: string,
    input: { session_id: string; run_id: string; request_id: string },
  ): Promise<unknown>;
  followupReceipt?(owner: string, request_id: string): Promise<unknown>;
  continue(owner: string, input: ReturnType<typeof continueArgs.parse>): Promise<unknown>;
  answer?(owner: string, input: ReturnType<typeof answerArgs.parse>): Promise<unknown>;
  creation: { create(owner: string, input: ReturnType<typeof createArgs.parse>): Promise<unknown> };
  settings: {
    standard(owner: string, input: ReturnType<typeof standardSpeedArgs.parse>): Promise<unknown>;
    receipt?(
      owner: string,
      input: { host: string; thread_id: string; request_id: string },
    ): unknown;
  };
  receipt(owner: string, input: { request_id: string }): Promise<unknown>;
}
export async function dispatchExisting(e: Envelope, services: SidecarServices): Promise<Outcome> {
  const target = { host: e.host, thread_id: e.thread_id, request_id: e.request_id };
  let result: unknown;
  if (e.kind === "continue")
    result = await services.continue(
      e.principal,
      continueArgs.parse({
        ...target,
        source_run_id: e.run,
        message: e.payload.text,
        execution: "allow_new_turn",
      }),
    );
  else if (e.kind === "answer") {
    if (!services.answer) throw Error("answer_service_required");
    result = await services.answer(
      e.principal,
      answerArgs.parse({
        ...target,
        native_request_id: e.payload.native_request_id,
        answers: e.payload.answers,
      }),
    );
  } else if (e.kind === "create")
    result = await services.creation.create(
      e.principal,
      createArgs.parse({
        host: e.host,
        project_id: e.project,
        provider_instance_id: e.provider,
        request_id: e.request_id,
        title: e.payload.title,
        message: e.payload.text,
        model: e.payload.model,
        options: e.payload.options,
        runtime_mode: e.payload.runtime_mode,
        execution: "allow_new_thread",
      }),
    );
  else if (e.kind === "settings_standard")
    result = await services.settings.standard(
      e.principal,
      standardSpeedArgs.parse({
        ...target,
        speed: "standard",
        expected_fingerprint: e.payload.expected_fingerprint,
      }),
    );
  else if (e.kind === "verify_result") {
    if (!services.followup || e.payload.action !== "verify_result")
      throw Error("dedicated_followup_service_required");
    result = await services.followup(e.principal, {
      session_id: String(e.payload.session_id),
      run_id: String(e.payload.run_id),
      request_id: e.request_id,
    });
  } else throw Error("webhook_uses_existing_outbox_not_native_adapter");
  // A service response is evidence, never proof of agent completion.
  if (!result || typeof result !== "object")
    return { state: "unknown", evidence: "unclassified_native_result" };
  const r = result as Record<string, unknown>;
  if (
    r.native_submitted !== true &&
    r.submission !== "rejected" &&
    r.state !== "verified" &&
    r.state !== "rejected" &&
    !(r.state === "noop" && r.reason === "already_standard" && !r.submitted_at) &&
    !(e.kind === "verify_result" && r.status === "accepted" && typeof r.messageId === "string")
  )
    return { state: "unknown", evidence: JSON.stringify(r) };
  return { state: "observed", evidence: JSON.stringify(r) };
}
export async function reconcileExisting(e: Envelope, services: SidecarServices): Promise<Outcome> {
  const r =
    e.kind === "verify_result"
      ? await services.followupReceipt?.(e.principal, e.request_id)
      : e.kind === "settings_standard"
        ? await services.settings.receipt?.(e.principal, {
            host: e.host,
            thread_id: e.thread_id,
            request_id: e.request_id,
          })
        : await services.receipt(e.principal, { request_id: e.request_id });
  if (!r || typeof r !== "object") return { state: "unknown", evidence: "no_owned_record" };
  const record = r as Record<string, unknown>;
  return {
    state:
      record.native_submitted === true ||
      record.submission === "rejected" ||
      record.state === "verified"
        ? "observed"
        : "unknown",
    evidence: JSON.stringify(r),
  };
}
