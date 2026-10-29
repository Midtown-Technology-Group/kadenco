// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { z } from "zod";
import type { Commands } from "./commands.mjs";
const id = z.string().min(1).max(2048);
export const threadOptionsArgs = z
  .object({ host: z.string().min(1).max(100), thread_id: id })
  .strict();
export const standardSpeedArgs = threadOptionsArgs
  .extend({
    request_id: z.string().uuid().toLowerCase(),
    expected_fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
    speed: z.literal("standard"),
  })
  .strict();
export const speedReceiptArgs = threadOptionsArgs
  .extend({ request_id: z.string().uuid().toLowerCase() })
  .strict();
const hash = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const fail = (reason) => Object.assign(Error(reason), { reason });
const canonical = (s) => ({
  ...s,
  options: [...(s.options ?? [])].sort((a, b) => a.id.localeCompare(b.id)),
});
const fingerprint = (host, thread, options) =>
  hash([
    host,
    thread,
    canonical(options.modelSelection),
    options.runtimeMode,
    options.interactionMode,
  ]);
const same = (a, b) => hash(canonical(a)) === hash(canonical(b));

export class ThreadSettings {
  constructor(public commands: Commands) {}
  receipt(owner, input) {
    const p = speedReceiptArgs.parse(input),
      c = this.commands;
    c.grant(owner, p.host);
    const r = c.store.get("settings_mutation", hash([owner, p.request_id]));
    if (!r || r.host !== p.host || r.thread_id !== p.thread_id) throw fail("receipt_not_found");
    const { grant } = c.grant(owner, p.host, r.before.project_id);
    if (!grant.providerInstanceIds.includes(r.before.model_selection.instanceId))
      throw fail("provider_not_authorized");
    return { ...r, current_state_checked: false, safe_to_resend: false };
  }
  async snapshot(owner, p, client) {
    const c = this.commands;
    c.reader.grant(owner, p.host);
    const data = await client.readThread(p.thread_id);
    const t = data.thread;
    if (t?.threadId !== p.thread_id || !t.projectId) throw fail("identity_mismatch");
    c.reader.grant(owner, p.host, t.projectId);
    const options = await client.currentOptions(p.thread_id);
    if (
      options?.threadId !== p.thread_id ||
      options.modelSelection?.instanceId !== t.providerInstanceId ||
      options.modelSelection?.model !== t.model
    )
      throw fail("identity_mismatch");
    if (
      !Array.isArray(options.modelSelection.options ?? []) ||
      new Set((options.modelSelection.options ?? []).map((o) => o.id)).size !==
        (options.modelSelection.options ?? []).length
    )
      throw fail("invalid_native_options");
    const catalog = await client.providerOptions(options.modelSelection.model);
    const provider = catalog.providers?.find(
      (v) => v.providerInstanceId === options.modelSelection.instanceId,
    );
    const model = provider?.models?.find((v) => v.id === options.modelSelection.model);
    const speed = model?.options?.find((v) => v.id === "serviceTier");
    const value = options.modelSelection.options?.find((v) => v.id === "serviceTier")?.value;
    const supported =
      provider?.driverKind === "codex" &&
      speed?.values?.includes("priority") &&
      speed.values.includes("default");
    const classification = supported
      ? value === "priority"
        ? "fast"
        : value === "default" || (value === undefined && speed.default === "default")
          ? "standard"
          : "unknown"
      : provider && provider.driverKind !== "codex"
        ? "unsupported"
        : "unknown";
    c.reader.grant(owner, p.host, t.projectId);
    return {
      host: p.host,
      thread_id: p.thread_id,
      project_id: t.projectId,
      model_selection: options.modelSelection,
      runtime_mode: options.runtimeMode,
      interaction_mode: options.interactionMode,
      active_run_id: t.activeRunId ?? null,
      classification,
      provider_driver: provider?.driverKind ?? null,
      speed_option: supported
        ? {
            id: "serviceTier",
            fast_value: "priority",
            standard_value: "default",
            default: speed.default ?? null,
          }
        : null,
      classification_reason: !provider
        ? "provider_metadata_unavailable"
        : !model
          ? "model_metadata_unavailable"
          : !supported
            ? "speed_not_supported"
            : classification === "unknown"
              ? "unknown_option_value"
              : null,
      standard_source: value === undefined ? "live_provider_default" : "explicit",
      fingerprint: fingerprint(p.host, p.thread_id, options),
      observed_at: new Date(c.now()).toISOString(),
      native_compare_and_swap: false,
      native_request_id_supported: false,
      changes_start_or_interrupt_turns: false,
    };
  }
  read(owner, input) {
    const p = threadOptionsArgs.parse(input),
      c = this.commands;
    c.reader.grant(owner, p.host);
    return c.reader.withHost(
      owner,
      p.host,
      undefined,
      (client) => this.snapshot(owner, p, client),
      true,
    );
  }
  async standard(owner, input) {
    const p = standardSpeedArgs.parse(input),
      c = this.commands;
    c.reader.grant(owner, p.host);
    const key = hash([owner, p.request_id]),
      identity = hash(p);
    const existing = c.store.get("settings_mutation", key);
    if (existing && existing.identity !== identity) throw fail("request_id_conflict");
    return c.reader.withHost(
      owner,
      p.host,
      undefined,
      async (client) => {
        const prior = c.store.get("settings_mutation", key);
        if (prior && prior.identity !== identity) throw fail("request_id_conflict");
        const before = await this.snapshot(owner, p, client);
        const authorize = () => {
          const { grant } = c.grant(owner, p.host, before.project_id);
          if (!grant.providerInstanceIds.includes(before.model_selection.instanceId))
            throw fail("provider_not_authorized");
        };
        authorize();
        if (prior) {
          if (
            [
              "verified",
              "noop",
              "rejected",
              "drift_after_submission",
              "observed_after_uncertainty",
            ].includes(prior.state)
          )
            return { ...prior, current: before, safe_to_resend: false };
          if (!prior.submitted_at) {
            const rejected = {
              ...prior,
              state: "rejected",
              reason: "preparation_interrupted",
              submission_not_attempted: true,
            };
            c.store.put("settings_mutation", key, rejected);
            return { ...rejected, current: before };
          }
          const observed =
            prior.expected &&
            same(before.model_selection, prior.expected) &&
            before.runtime_mode === prior.before.runtime_mode &&
            before.interaction_mode === prior.before.interaction_mode;
          const receipt = {
            ...prior,
            state: observed ? "observed_after_uncertainty" : "uncertain",
            after: before,
            safe_to_resend: false,
          };
          c.store.put("settings_mutation", key, receipt);
          return receipt;
        }
        const receipt = {
          id: key,
          request_id: p.request_id,
          owner,
          at: c.now(),
          identity,
          host: p.host,
          thread_id: p.thread_id,
          state: "stored",
          before,
          safe_to_resend: false,
          native_request_id_supported: false,
          native_compare_and_swap: false,
        };
        const save = (value) => {
          c.store.put("settings_mutation", key, value);
          c.store.audit("thread.speed", key, value.state);
          return value;
        };
        save(receipt);
        if (before.fingerprint !== p.expected_fingerprint)
          return save({ ...receipt, state: "rejected", reason: "settings_changed" });
        if (before.classification === "standard")
          return save({ ...receipt, state: "noop", reason: "already_standard", after: before });
        if (before.classification !== "fast")
          return save({ ...receipt, state: "rejected", reason: before.classification });
        const expected = {
          ...before.model_selection,
          options: before.model_selection.options.map((o) =>
            o.id === "serviceTier" ? { ...o, value: "default" } : o,
          ),
        };
        let rechecked;
        try {
          rechecked = await this.snapshot(owner, p, client);
        } catch (e) {
          save({
            ...receipt,
            state: "rejected",
            reason: e.reason ?? "preparation_failed",
            submission_not_attempted: true,
          });
          throw e;
        }
        if (rechecked.fingerprint !== before.fingerprint)
          return save({ ...receipt, state: "rejected", reason: "settings_changed" });
        try {
          authorize();
        } catch (e) {
          save({
            ...receipt,
            state: "rejected",
            reason: e.reason ?? "preparation_failed",
            submission_not_attempted: true,
          });
          throw e;
        }
        const submitted = {
          ...receipt,
          expected,
          state: "submitting",
          submitted_at: new Date(c.now()).toISOString(),
        };
        try {
          c.store.transaction(() => {
            const { grant } = c.grant(owner, p.host, before.project_id);
            const day = new Date(c.now()).toISOString().slice(0, 10);
            const used = c.store
              .commandBudgetRecords()
              .filter(
                (r) =>
                  r.owner === owner &&
                  r.host === p.host &&
                  new Date(r.at).toISOString().slice(0, 10) === day,
              ).length;
            if (Number.isFinite(grant.maxPerDay) && used >= grant.maxPerDay)
              throw fail("command_budget_exhausted");
            save(submitted);
          });
        } catch (e) {
          save({
            ...receipt,
            state: "rejected",
            reason: e.reason ?? "preparation_failed",
            submission_not_attempted: true,
          });
          throw e;
        }
        let native;
        try {
          native = await client.configure(p.thread_id, expected);
        } catch {
          return save({ ...submitted, state: "uncertain", reason: "native_outcome_unknown" });
        }
        const accepted = {
          ...submitted,
          state: "native_accepted",
          native_accepted: true,
          native_sequence: Number.isSafeInteger(native?.sequence) ? native.sequence : null,
        };
        save(accepted);
        try {
          const after = await this.snapshot(owner, p, client);
          const verified =
            same(after.model_selection, expected) &&
            before.runtime_mode === after.runtime_mode &&
            before.interaction_mode === after.interaction_mode;
          return save({
            ...accepted,
            state: verified ? "verified" : "drift_after_submission",
            after,
            active_run_id_before: before.active_run_id,
            active_run_id_after: after.active_run_id,
            active_run_speed_verified: false,
            application_scope:
              "native_thread_selection; existing_provider_turn_not_reconfigured_by_this_adapter",
          });
        } catch {
          return save({ ...accepted, state: "uncertain", reason: "readback_unavailable" });
        }
      },
      true,
    );
  }
}
