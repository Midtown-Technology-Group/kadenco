// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  seal,
  validateOperation,
  consumeAuthorized,
  type Envelope,
  type Grant,
} from "./authorization.ts";
import type { AttemptJournal, Outcome } from "./edge.ts";
import { continueArgs, answerArgs } from "../../../dist/commands.mjs";
import { createArgs } from "../../../dist/creation.mjs";
import { standardSpeedArgs } from "../../../dist/thread-settings.mjs";
import { isDeepStrictEqual } from "node:util";
import type { MutationKind } from "./mutation-gate.ts";
/** Operator-owned exact binding resolver. It must use current existing grants and
 * native projection; missing mappings deny. No credential is accepted in input. */
export function centralCoordinator(ports: {
  epoch: number;
  key: Buffer;
  journal: AttemptJournal;
  ownerCall: (owner: string, op: string, p: object) => Promise<Record<string, unknown>>;
  executorCall: (op: string, p: object) => Promise<Record<string, unknown>>;
  bind: (
    kind: MutationKind,
    owner: string,
    input: unknown,
  ) => Promise<{ envelope: Envelope; grant: Grant }>;
  currentGrant: (e: Envelope) => Promise<Grant>;
  observe: (e: Envelope) => Promise<Outcome>;
  now?: () => number;
}) {
  return async (
    kind: MutationKind,
    owner: string,
    input: unknown,
    execute: () => Promise<unknown>,
  ) => {
    const { envelope: e, grant } = await ports.bind(kind, owner, input),
      raw = input as { request_id?: unknown; host?: unknown; thread_id?: unknown };
    const now = ports.now ?? Date.now;
    if (
      e.principal !== owner ||
      e.kind !== kind ||
      e.request_id !== raw.request_id ||
      (kind !== "verify_result" && e.host !== raw.host) ||
      (!["create", "verify_result"].includes(kind) && e.thread_id !== raw.thread_id)
    )
      throw Error("binding_mismatch");
    let expected: Record<string, unknown>;
    if (kind === "continue") {
      const p = continueArgs.parse(input);
      if (e.run !== p.source_run_id) throw Error("binding_mismatch");
      expected = { text: p.message };
    } else if (kind === "create") {
      const p = createArgs.parse(input);
      if (e.project !== p.project_id || e.provider !== p.provider_instance_id || e.run !== null)
        throw Error("binding_mismatch");
      expected = {
        text: p.message,
        title: p.title,
        model: p.model,
        options: p.options,
        runtime_mode: p.runtime_mode,
      };
    } else if (kind === "settings_standard") {
      const p = standardSpeedArgs.parse(input);
      expected = { speed: p.speed, expected_fingerprint: p.expected_fingerprint };
    } else if (kind === "verify_result") {
      const p = input as { session_id: string; run_id: string; action: string; request_id: string };
      if (
        Object.keys(p).some((k) => !["session_id", "run_id", "action", "request_id"].includes(k)) ||
        typeof p.session_id !== "string" ||
        !p.session_id ||
        p.session_id.length > 100 ||
        typeof p.run_id !== "string" ||
        !p.run_id ||
        p.run_id.length > 2048 ||
        p.action !== "verify_result" ||
        e.run !== p.run_id
      )
        throw Error("binding_mismatch");
      expected = { session_id: p.session_id, run_id: p.run_id, action: "verify_result" };
    } else {
      const p = answerArgs.parse(input);
      expected = { native_request_id: p.native_request_id, answers: p.answers };
    }
    if (!isDeepStrictEqual(expected, e.payload)) throw Error("binding_mismatch");
    const digest = validateOperation(e, grant, now());
    const reserved = await ports.ownerCall(owner, "reserve", {
      epoch: ports.epoch,
      request_id: e.request_id,
      host: e.host,
      thread_id: e.thread_id,
      kind: e.kind,
      payload_sha256: digest,
      binding: {
        project: e.project,
        provider: e.provider,
        run: e.run,
        grant: e.grant,
        revision: e.revision,
        expires: e.expires,
      },
    });
    if (reserved.id !== e.request_id) throw Error("central_reservation_denied");
    const result = await consumeAuthorized(
      seal(e, ports.key),
      ports.key,
      () => ports.currentGrant(e),
      now,
      ports.epoch,
      {
        journal: ports.journal,
        call: ports.executorCall,
        async validate() {},
        async execute() {
          const r = await execute();
          if (!r || typeof r !== "object")
            return { state: "unknown", evidence: "unclassified_native_result" };
          const v = r as Record<string, unknown>;
          return {
            state:
              v.native_submitted === true ||
              v.submission === "rejected" ||
              v.state === "verified" ||
              v.state === "rejected" ||
              (v.state === "noop" && v.reason === "already_standard" && !v.submitted_at) ||
              (kind === "verify_result" &&
                v.status === "accepted" &&
                typeof v.messageId === "string")
                ? "observed"
                : "unknown",
            evidence: JSON.stringify(r),
          };
        },
        observe: () => ports.observe(e),
      },
    );
    const receipt =
      (result as { outcome?: Outcome; receipt?: Outcome }).outcome ??
      (result as { receipt?: Outcome }).receipt;
    if (receipt?.state === "observed") return JSON.parse(receipt.evidence);
    return {
      request_id: e.request_id,
      submission: "outcome_unknown",
      safe_to_resend: false,
      central_state: result.state,
    };
  };
}
