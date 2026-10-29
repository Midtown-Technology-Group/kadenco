// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import { z } from "zod";
import { scrub } from "./fleet-read.mjs";
import { readReason } from "./read-errors.mjs";

const id = z.string().trim().min(1).max(2048);
const option = z
  .object({
    id: z.string().min(1).max(100),
    value: z.union([z.string().min(1).max(200), z.boolean()]),
  })
  .strict();
export const creationOptionsArgs = z
  .object({
    host: z.string().min(1).max(100),
    project_id: id,
    model_query: z.string().trim().min(1).max(200).optional(),
  })
  .strict();
export const createArgs = z
  .object({
    host: z.string().min(1).max(100),
    project_id: id,
    title: z.string().trim().min(1).max(200),
    provider_instance_id: z.string().min(1).max(100),
    model: z.string().min(1).max(200),
    options: z.array(option).max(20),
    runtime_mode: z.enum(["approval-required", "full-access"]),
    message: z.string().trim().min(1).max(8000),
    request_id: z.string().uuid().toLowerCase(),
    execution: z.literal("allow_new_thread"),
  })
  .strict()
  .refine((p) => new Set(p.options.map((o) => o.id)).size === p.options.length, "Duplicate option");
const fail = (reason) => Object.assign(new Error(reason), { reason });
const hash = (x) => createHash("sha256").update(JSON.stringify(x)).digest("hex");
const terminal = new Set(["completed", "failed", "cancelled", "interrupted", "rolled_back"]);
const selection = (p) => ({
  instanceId: p.provider_instance_id,
  model: p.model,
  options: p.options,
});
const sameSelection = (a, b) =>
  a?.instanceId === b.instanceId &&
  a.model === b.model &&
  hash([...(a.options ?? [])].sort((x, y) => x.id.localeCompare(y.id))) ===
    hash([...b.options].sort((x, y) => x.id.localeCompare(y.id)));
const nativeThreadId = (owner, request) => {
  const s = hash(["eddie-create-thread", owner, request]);
  return (
    s.slice(0, 8) +
    "-" +
    s.slice(8, 12) +
    "-4" +
    s.slice(13, 16) +
    "-a" +
    s.slice(17, 20) +
    "-" +
    s.slice(20, 32)
  );
};

export class Creation {
  constructor(commands) {
    this.commands = commands;
  }
  grant(owner, p) {
    const { grant, route } = this.commands.grant(owner, p.host, p.project_id);
    if (p.provider_instance_id && !grant.providerInstanceIds.includes(p.provider_instance_id))
      throw fail("provider_not_authorized");
    return { grant, route };
  }
  runtimeGrant(owner, p) {
    const { grant } = this.grant(owner, p),
      runtime = grant.creationRuntime;
    if (!runtime || !runtime.allowedModes.includes(p.runtime_mode))
      throw fail("runtime_mode_not_authorized");
    return runtime;
  }
  runtimeModes(provider) {
    // Native RuntimePolicy.providerRuntimeMode and MCP resolveRuntimeMode treat
    // omitted/empty metadata as unrestricted, notably for installed Codex.
    const modes = provider.supportedRuntimeModes;
    if (modes === undefined || (Array.isArray(modes) && modes.length === 0))
      return ["approval-required", "full-access"];
    return Array.isArray(modes)
      ? modes.filter((m) => ["approval-required", "full-access"].includes(m))
      : [];
  }
  async project(owner, p, client) {
    const deadline = this.commands.now() + 20000;
    let cursor = 0;
    for (;;) {
      const page = await client.listProjects({ cursor, limit: 100 });
      this.grant(owner, p);
      if (!Array.isArray(page.projects) || page.projects.length > 100)
        throw fail("source_protocol_error");
      const matches = page.projects.filter((x) => x.id === p.project_id);
      if (matches.length === 1) return matches[0];
      if (matches.length > 1) throw fail("identity_mismatch");
      if (page.nextCursor === null) throw fail("project_not_found");
      if (!Number.isSafeInteger(page.nextCursor) || page.nextCursor <= cursor)
        throw fail("invalid_source_pagination");
      if (this.commands.now() >= deadline) throw fail("project_lookup_incomplete");
      cursor = page.nextCursor;
    }
  }
  providers(owner, p, config) {
    const { grant } = this.grant(owner, p);
    if (!Array.isArray(config?.providers)) throw fail("source_protocol_error");
    return config.providers.filter(
      (x) =>
        grant.providerInstanceIds.includes(x.instanceId) &&
        ["codex", "claudeAgent", "opencode", "pi"].includes(x.driver) &&
        x.enabled === true &&
        x.installed === true &&
        x.availability !== "unavailable" &&
        x.status !== "error" &&
        config.settings?.projectSettingsOverrides?.[p.project_id]?.providerInstances?.[x.instanceId]
          ?.enabled !== false,
    );
  }
  validate(owner, p, config) {
    const providers = this.providers(owner, p, config),
      matches = providers.filter((x) => x.instanceId === p.provider_instance_id);
    if (matches.length !== 1) throw fail("provider_not_authorized");
    const provider = matches[0],
      models = provider.models?.filter((x) => x.slug === p.model);
    if (models?.length !== 1) throw fail("model_not_available");
    this.runtimeGrant(owner, p);
    if (!this.runtimeModes(provider).includes(p.runtime_mode))
      throw fail("runtime_mode_unavailable");
    const descriptors = models[0].capabilities?.optionDescriptors ?? [];
    for (const o of p.options) {
      const d = descriptors.find((x) => x.id === o.id);
      if (
        !d ||
        !(
          (d.type === "boolean" && typeof o.value === "boolean") ||
          (d.type === "select" && d.options?.some((x) => x.id === o.value))
        )
      )
        throw fail("invalid_model_option");
    }
    return provider;
  }
  async options(owner, input) {
    const p = creationOptionsArgs.parse(input),
      { route } = this.grant(owner, p),
      c = this.commands;
    return c.reader.withHost(owner, p.host, p.project_id, async (client) => {
      const project = await this.project(owner, p, client);
      return c.session(
        { ...route, readOnly: true, audit: (...a) => c.store.audit(...a) },
        async (call) => {
          const config = await call(client.base, "server.getConfig", {}),
            providers = this.providers(owner, p, config);
          const runtime = this.grant(owner, p).grant.creationRuntime;
          return {
            host: p.host,
            project_id: p.project_id,
            project_title: scrub(project.title),
            runtime_modes: runtime?.allowedModes ?? [],
            default_runtime_mode: runtime?.defaultMode ?? null,
            runtime_policy_configured: !!runtime,
            workspace: "project_root",
            preflight_only: true,
            providers: providers.map((x) => {
              const models = (x.models ?? []).filter(
                (m) => !p.model_query || m.slug.toLowerCase().includes(p.model_query.toLowerCase()),
              );
              return {
                provider_instance_id: x.instanceId,
                driver: x.driver,
                runtime_modes: this.runtimeModes(x).filter((m) =>
                  runtime?.allowedModes.includes(m),
                ),
                models: models.slice(0, 100).map((m) => ({
                  model: m.slug,
                  name: scrub(m.name),
                  options: m.capabilities?.optionDescriptors ?? [],
                })),
                models_truncated: models.length > 100,
              };
            }),
            instruction:
              "Choose exact host/project/provider/model/options and explicitly include runtime_mode. Prefer default_runtime_mode only when authorized and supported by the selected provider; never silently substitute a mode. No access or task authority is granted by discovery. create_thread requires owner-authorized work and execution=allow_new_thread. Only existing registered project roots are supported. Runtime policy affects new threads only and never grants external service/human approvals.",
          };
        },
      );
    });
  }
  existing(owner, p) {
    this.grant(owner, p);
    const r = this.commands.store.get("command", p.request_id);
    if (!r) return null;
    if (r.owner !== owner) throw fail("forbidden");
    if (r.digest !== hash({ kind: "create", ...p })) throw fail("idempotency_conflict");
    return r;
  }
  output(r, extra = {}) {
    return {
      ...this.commands.output(r),
      project_id: r.projectId,
      title: r.title,
      model_selection: selection(r),
      runtime_mode: r.runtime_mode ?? "approval-required",
      observed_runtime_mode: r.observedRuntimeMode ?? null,
      runtime_matches_request:
        r.observedRuntimeMode === undefined
          ? null
          : r.observedRuntimeMode === (r.runtime_mode ?? "approval-required"),
      workspace: "project_root",
      create_submission: r.createSubmission,
      start_submission: r.startSubmission,
      create_sequence: r.createSequence ?? null,
      thread_observed: r.threadObserved === true,
      run_bound: !!r.runId,
      safe_to_resend: false,
      ...extra,
      acknowledgement_support:
        "existing_exact_thread_bound_caller_only; host-wide passive caller does not expose delivery acknowledgement",
      instruction:
        "Creation, initial message acceptance, exact native readback, caller acknowledgement and completion are separate. Partial or uncertain requests are never automatically resumed or resent. Reconcile this exact UUID; do not create a replacement request or substitute the latest run.",
    };
  }
  update(owner, p, patch) {
    const c = this.commands;
    return c.store.transaction(() => {
      this.grant(owner, p);
      const r = this.existing(owner, p);
      if (!r) throw fail("identity_mismatch");
      Object.assign(r, patch);
      c.store.put("command", p.request_id, r);
      return r;
    });
  }
  verify(p, r, projection, { initial = false } = {}) {
    const t = projection?.thread;
    if (t?.id !== r.thread_id || t.projectId !== p.project_id) throw fail("identity_mismatch");
    if (
      initial &&
      (t.title !== p.title ||
        t.archivedAt ||
        t.deletedAt ||
        t.runtimeMode !== p.runtime_mode ||
        t.interactionMode !== "default" ||
        t.branch != null ||
        t.worktreePath != null ||
        !sameSelection(t.modelSelection, selection(p)))
    )
      throw fail("identity_mismatch");
  }
  async create(owner, input) {
    const p = createArgs.parse(input),
      c = this.commands,
      old = this.existing(owner, p);
    if (old) return this.output(old);
    this.runtimeGrant(owner, p);
    return c.reader.withHost(owner, p.host, p.project_id, async (client) => {
      const old = this.existing(owner, p);
      if (old) return this.output(old);
      await this.project(owner, p, client);
      const { route } = this.grant(owner, p);
      return c.session(
        {
          ...route,
          audit: (...a) => c.store.audit(...a),
          authorizeDispatch: () => this.runtimeGrant(owner, p),
        },
        async (call) => {
          this.validate(owner, p, await call(client.base, "server.getConfig", {}));
          const reservation = c.store.transaction(() => {
            const old = this.existing(owner, p);
            if (old) return { existing: old };
            const { grant } = this.grant(owner, p),
              day = new Date(c.now()).toISOString().slice(0, 10);
            if (
              grant.maxPerDay !== null &&
              c.store
                .all("command")
                .filter(
                  (r) =>
                    r.owner === owner &&
                    r.host === p.host &&
                    new Date(r.at).toISOString().slice(0, 10) === day,
                ).length >= grant.maxPerDay
            )
              throw fail("command_budget_exhausted");
            const suffix = hash(["eddie-create-thread", owner, p.request_id]);
            const r = {
              ...p,
              owner,
              kind: "create",
              projectId: p.project_id,
              thread_id: nativeThreadId(owner, p.request_id),
              digest: hash({ kind: "create", ...p }),
              at: c.now(),
              createCommandId: "command:eddie-create:" + suffix,
              commandId: "command:eddie-start:" + suffix,
              messageId: "message:eddie-start:" + suffix,
              createSubmission: "outcome_unknown",
              startSubmission: "not_attempted",
              submission: "not_attempted",
              executionAuthorization: {
                scope: "host_provider_grant",
                providerInstanceId: p.provider_instance_id,
                model: p.model,
                runtimeMode: p.runtime_mode,
                runtimeAuthorization: this.runtimeGrant(owner, p).authorization,
                expiresAt: grant.expiresAt,
                maxPerDay: grant.maxPerDay,
              },
            };
            if (!c.store.insert("command", p.request_id, r)) throw fail("request_in_progress");
            c.store.audit(
              "creation.stored",
              p.request_id,
              owner + ":" + p.host + ":" + p.project_id,
            );
            return { record: r };
          });
          if (reservation.existing) return this.output(reservation.existing);
          let r = reservation.record;
          try {
            this.runtimeGrant(owner, p);
            const created = await call(client.base, "orchestration.dispatchCommand", {
              type: "thread.create",
              createdBy: "agent",
              creationSource: "mcp",
              commandId: r.createCommandId,
              threadId: r.thread_id,
              projectId: p.project_id,
              title: p.title,
              modelSelection: selection(p),
              runtimeMode: p.runtime_mode,
              interactionMode: "default",
              branch: null,
              worktreePath: null,
            });
            if (!Number.isSafeInteger(created?.sequence) || created.sequence < 0)
              throw fail("native_outcome_unknown");
            r = this.update(owner, p, {
              createSubmission: "accepted",
              createSequence: created.sequence,
            });
            const projection = await call(client.base, "orchestration.getThreadProjection", {
              threadId: r.thread_id,
            });
            this.verify(p, r, projection, { initial: true });
            // Recheck catalog/expiry after creation and before execution. A failure
            // here leaves a visible, unstarted thread; never hide it or recreate it.
            this.validate(owner, p, await call(client.base, "server.getConfig", {}));
            r = this.update(owner, p, {
              threadObserved: true,
              startSubmission: "outcome_unknown",
              submission: "outcome_unknown",
            });
            const started = await call(client.base, "orchestration.dispatchCommand", {
              type: "message.dispatch",
              createdBy: "agent",
              creationSource: "mcp",
              commandId: r.commandId,
              threadId: r.thread_id,
              messageId: r.messageId,
              text:
                p.message +
                "\n\n[Eddie creation request_id: " +
                p.request_id +
                ". Preserve task and approval boundaries.]",
              attachments: [],
              modelSelection: selection(p),
              dispatchMode: { type: "start_immediately" },
            });
            if (!Number.isSafeInteger(started?.sequence) || started.sequence < 0)
              throw fail("native_outcome_unknown");
            r = this.update(owner, p, {
              startSubmission: "accepted",
              submission: "accepted",
              sequence: started.sequence,
            });
          } catch (e) {
            // No retry at either mutation boundary. Do not overwrite observations
            // or acknowledgements recorded by a concurrent receipt reader.
            const reason = [
              "native_rejected",
              "provider_not_authorized",
              "forbidden",
              "identity_mismatch",
              "model_not_available",
              "invalid_model_option",
              "runtime_mode_unavailable",
              "runtime_mode_not_authorized",
            ].includes(e.reason)
              ? e.reason
              : "native_outcome_unknown";
            const latest = c.store.get("command", p.request_id),
              stage = latest.startSubmission === "not_attempted" ? "create" : "start";
            if (!["forbidden", "provider_not_authorized"].includes(reason))
              r = this.update(owner, p, {
                failureReason: reason,
                ...(reason === "native_rejected"
                  ? stage === "create"
                    ? {
                        createSubmission:
                          latest.createSubmission === "accepted" ? "accepted" : "rejected",
                      }
                    : { startSubmission: "rejected", submission: "rejected" }
                  : {}),
              });
            else {
              c.store.audit("creation.denied_after_reservation", p.request_id, reason);
              throw fail(reason);
            }
          }
          c.store.audit(
            "creation.submitted",
            p.request_id,
            r.createSubmission + ":" + r.startSubmission,
          );
          return this.output(r, { failure_reason: r.failureReason ?? null });
        },
      );
    });
  }
  async receipt(owner, r) {
    const c = this.commands,
      p = createArgs.parse({
        ...Object.fromEntries(Object.keys(createArgs.shape ?? {}).map((k) => [k, r[k]])),
        runtime_mode: r.runtime_mode ?? "approval-required",
      });
    // Zod refinements retain the object shape. Only original request arguments
    // enter the digest; generated thread/message identity is never caller input.
    this.grant(owner, p);
    const { route } = this.grant(owner, p),
      revision = r.creationObservationRevision ?? 0;
    try {
      return await c.reader.withHost(owner, r.host, r.projectId, (client) =>
        c.session(
          { ...route, readOnly: true, audit: (...a) => c.store.audit(...a) },
          async (call) => {
            const projection = await call(client.base, "orchestration.getThreadProjection", {
              threadId: r.thread_id,
            });
            this.verify(p, r, projection);
            this.grant(owner, p);
            const matches = (projection.runs ?? []).filter(
              (x) => x.userMessageId === r.messageId || (r.runId && x.id === r.runId),
            );
            if (
              matches.length > 1 ||
              (matches[0]?.userMessageId && matches[0].userMessageId !== r.messageId) ||
              (r.runId && matches[0] && r.runId !== matches[0].id)
            )
              throw fail("identity_mismatch");
            const run = matches[0];
            if (run?.modelSelection && !sameSelection(run.modelSelection, selection(p)))
              throw fail("identity_mismatch");
            const message = (projection.messages ?? []).find((x) => x.id === r.messageId),
              result =
                run && terminal.has(run.status)
                  ? projection.messages
                      ?.filter((m) => m.runId === run.id && m.role === "assistant")
                      .at(-1)?.text
                  : undefined;
            const regressive = run && terminal.has(r.runStatus) && !terminal.has(run.status);
            let fresh = !!run && !regressive,
              resultFresh = typeof result === "string" && fresh;
            const current = c.store.transaction(() => {
              this.grant(owner, p);
              const latest = c.store.get("command", r.request_id);
              if (
                latest?.owner !== owner ||
                latest.thread_id !== r.thread_id ||
                latest.digest !== r.digest
              )
                throw fail("forbidden");
              if ((latest.creationObservationRevision ?? 0) !== revision) {
                fresh = false;
                resultFresh = false;
                return latest;
              }
              if (latest.runId && run && latest.runId !== run.id) throw fail("identity_mismatch");
              latest.threadObserved = true;
              latest.createSubmission = "accepted";
              latest.observedRuntimeMode = projection.thread.runtimeMode;
              if (run || message) {
                latest.startSubmission = "accepted";
                latest.submission = "accepted";
              }
              if (fresh) {
                latest.runId = run.id;
                latest.runStatus = run.status;
                latest.runObservedAt = c.now();
              }
              if (resultFresh) {
                latest.result = scrub(result).slice(0, 4000);
                latest.resultObservedAt = c.now();
              }
              latest.creationObservationRevision = revision + 1;
              c.store.put("command", r.request_id, latest);
              c.store.audit("creation.observed", r.request_id, run?.status ?? "thread_only");
              return latest;
            });
            return this.output(current, {
              ...c.observedOutput(current, {
                source_status: regressive ? "regressive_projection" : "available",
                fresh,
                result_fresh: resultFresh,
                native_message_status: message ? "observed" : "not_in_projection",
              }),
              model_selection: selection(current),
              create_submission: current.createSubmission,
              start_submission: current.startSubmission,
              thread_observed: current.threadObserved === true,
            });
          },
        ),
      );
    } catch (e) {
      this.grant(owner, p);
      if (e.reason === "identity_mismatch" || e.reason === "forbidden") throw e;
      const current = c.store.get("command", r.request_id);
      if (current?.owner !== owner) throw fail("forbidden");
      return this.output(current, {
        ...c.observedOutput(current, { source_status: "unavailable", source_error: readReason(e) }),
        model_selection: selection(current),
        create_submission: current.createSubmission,
        start_submission: current.startSubmission,
        thread_observed: current.threadObserved === true,
      });
    }
  }
}
