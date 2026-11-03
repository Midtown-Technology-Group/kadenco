// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from "node:crypto";
import type { Bridge } from "../../../dist/bridge.mjs";
import type { NativeRecord } from "../../../dist/contracts.mjs";
import { continueArgs, answerArgs } from "../../../dist/commands.mjs";
import { createArgs, nativeThreadId } from "../../../dist/creation.mjs";
import { standardSpeedArgs } from "../../../dist/thread-settings.mjs";
import { projectNativeGrant } from "./grant-projection.ts";
import { authorizeBinding, type OperationBinding } from "./binding.ts";
import { validateOperation, type Envelope, type Grant } from "./authorization.ts";
import type { MutationKind } from "./mutation-gate.ts";
import { reconcileExisting, type SidecarServices } from "./native-adapter.ts";
import { eventTarget } from "./event-target.ts";
const hash = (value: unknown) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const text = (value: unknown): string =>
  typeof value === "string" && value.length > 0 && value.length <= 2048
    ? value
    : (() => {
        throw Error("native_binding_unavailable");
      })();

/** Runtime bindings use the original grant and native projection methods. They
 * perform reads only; centralCoordinator invokes the unchanged native service.
 * A duplicate can use its owned durable reservation when the source is offline.
 * Missing legacy binding evidence denies rather than guessing or submitting. */
export function existingBindings(
  bridge: Bridge,
  options: {
    fleet: string;
    observationOwner: string;
    serviceExpiresAt: number;
    now?: () => number;
  },
) {
  options = Object.freeze({ ...options });
  const now = options.now ?? Date.now;
  if (
    !options.fleet ||
    !options.observationOwner ||
    !Number.isSafeInteger(options.serviceExpiresAt) ||
    options.serviceExpiresAt <= now()
  )
    throw Error("binding_configuration_required");
  const commands = () =>
    bridge.commands ??
    (() => {
      throw Error("commands_required");
    })();
  const commandScope = (owner: string, host: string) => {
    const scope = projectNativeGrant(bridge.policy(), owner, host, "command", undefined, now());
    return { ...scope, expires: Math.min(scope.expires, options.serviceExpiresAt) };
  };
  const verification = (owner: string, sessionId: string) => {
    const session = bridge.grant(owner, sessionId),
      g = session.followup;
    if (
      !g?.dedicated ||
      g.action !== "verify_result" ||
      g.expiresAt <= now() ||
      bridge.backend.supportsFollowup === false
    )
      throw Error("followup_not_authorized");
    const p = bridge.policy();
    return {
      session,
      expires: Math.min(g.expiresAt, options.serviceExpiresAt),
      grant: hash([
        "existing-verification-v1",
        owner,
        session,
        p.source ?? null,
        p.localClient ?? null,
        p.fleetHelperPath ?? null,
        p.fleetRead?.hosts.find((h) => h.name === session.host) ?? null,
      ]),
    };
  };
  const grantFor = (e: Envelope): Grant => {
    if (e.fleet !== options.fleet) throw Error("binding_mismatch");
    let grant: string, expires: number;
    if (e.kind === "verify_result") {
      const v = verification(e.principal, text(e.payload.session_id));
      if (
        e.host !== v.session.host ||
        e.thread_id !== v.session.threadId ||
        e.provider !== v.session.followup!.providerInstanceId
      )
        throw Error("binding_mismatch");
      ({ grant, expires } = v);
    } else {
      const s = commandScope(e.principal, e.host);
      commands().grant(e.principal, e.host, e.project);
      authorizeBinding(e, [], now(), { host: e.host, purpose: "command", grants: [s] });
      ({ grant, expires } = s);
    }
    const { request_id: _request, kind: _kind, payload: _payload, ...binding } = e;
    return { ...binding, grant, expires, revision: 1, revoked: false, kinds: [e.kind] };
  };
  const nativeContext = async (kind: "continue" | "answer", owner: string, p: NativeRecord) => {
    const c = commands(),
      { route } = c.grant(owner, p.host);
    return c.reader.withHost(owner, p.host, undefined, (client: NativeRecord) =>
      c.session(
        { ...route, readOnly: true },
        async (call: (base: string, tag: string, input: object) => Promise<NativeRecord>) => {
          const projection = await call(client.base, "orchestration.getThreadProjection", {
            threadId: p.thread_id,
          });
          const { projectId, grant } = c.validateProjection(owner, p, projection);
          let run: NativeRecord | undefined;
          if (kind === "continue")
            run = projection.runs?.find((r: NativeRecord) => r.id === p.source_run_id);
          else {
            const request = projection.runtimeRequests?.find(
              (r: NativeRecord) => r.id === p.native_request_id,
            );
            if (
              !request ||
              request.kind !== "user_input" ||
              request.status !== "pending" ||
              request.responseCapability?.type !== "live"
            )
              throw Error("live_request_required");
            const node = projection.nodes?.find((n: NativeRecord) => n.id === request.nodeId);
            run = projection.runs?.find((r: NativeRecord) => r.id === node?.runId);
          }
          if (!run) throw Error("source_run_not_found");
          const selection = c.provider(projection, run, grant);
          return {
            project: text(projectId),
            provider: text(selection.instanceId),
            run: text(run.id),
          };
        },
      ),
    );
  };
  const bind = async (kind: MutationKind, owner: string, input: unknown) => {
    let host: string, thread: string, project: string, provider: string, run: string | null;
    let request: string, payload: Envelope["payload"], grant: string, expires: number;
    if (kind === "verify_result") {
      const p = input as { session_id: string; run_id: string; request_id: string; action: string };
      if (
        !p ||
        p.action !== "verify_result" ||
        Object.keys(p).some((k) => !["session_id", "run_id", "request_id", "action"].includes(k))
      )
        throw Error("binding_mismatch");
      const v = verification(owner, text(p.session_id));
      host = v.session.host;
      thread = v.session.threadId;
      run = text(p.run_id);
      request = text(p.request_id);
      const old = bridge.store.get("followup", hash([owner, request]));
      if (old && (old.owner !== owner || old.sessionId !== p.session_id || old.runId !== run))
        throw Error("idempotency_conflict");
      const source = await bridge.read(owner, p.session_id);
      if (
        !old &&
        (source.thread?.activeRunId ||
          source.thread?.latestRunId !== run ||
          !source.recentRuns?.some(
            (r: NativeRecord) => r.runId === run && r.status === "completed",
          ) ||
          source.thread?.providerInstanceId !== v.session.followup!.providerInstanceId ||
          source.thread?.model !== v.session.followup!.model ||
          source.thread?.runtimeMode !== "approval-required")
      )
        throw Error("followup_boundary_denied");
      project = text(source.thread?.projectId);
      provider = text(v.session.followup!.providerInstanceId);
      ({ grant, expires } = v);
      payload = { session_id: p.session_id, run_id: run, action: "verify_result" };
    } else {
      const c = commands();
      if (kind === "create") {
        const p = createArgs.parse(input);
        host = p.host;
        project = p.project_id;
        provider = p.provider_instance_id;
        run = null;
        request = p.request_id;
        const old = c.store.get("command", request);
        if (old) {
          c.creation.existing(owner, p);
          thread = text(old.thread_id);
        } else {
          c.creation.runtimeGrant(owner, p);
          const { route } = c.creation.grant(owner, p);
          await c.reader.withHost(owner, host, project, async (client: NativeRecord) => {
            await c.creation.project(owner, p, client);
            return c.session(
              { ...route, readOnly: true },
              async (call: (base: string, tag: string, input: object) => Promise<NativeRecord>) =>
                c.creation.validate(owner, p, await call(client.base, "server.getConfig", {})),
            );
          });
          // Same stable native identity used by the original Creation service.
          thread = nativeThreadId(owner, request);
        }
        payload = {
          text: p.message,
          title: p.title,
          model: p.model,
          options: p.options,
          runtime_mode: p.runtime_mode,
        };
      } else if (kind === "settings_standard") {
        const p = standardSpeedArgs.parse(input);
        host = p.host;
        thread = p.thread_id;
        request = p.request_id;
        const old = c.store.get("settings_mutation", hash([owner, request]));
        if (old && old.identity !== hash(p)) throw Error("request_id_conflict");
        const before = old
          ? c.settings.receipt(owner, { host, thread_id: thread, request_id: request }).before
          : await c.settings.read(owner, { host, thread_id: thread });
        project = text(before.project_id);
        provider = text(before.model_selection?.instanceId);
        run = before.active_run_id == null ? null : text(before.active_run_id);
        payload = { speed: p.speed, expected_fingerprint: p.expected_fingerprint };
      } else {
        const p = kind === "continue" ? continueArgs.parse(input) : answerArgs.parse(input);
        host = p.host;
        thread = p.thread_id;
        request = p.request_id;
        const old = c.store.get("command", request);
        if (old) {
          c.existing(owner, p, kind);
          project = text(old.projectId);
          provider = text(old.executionAuthorization?.providerInstanceId);
          run = text(old.sourceRunId);
        } else ({ project, provider, run } = await nativeContext(kind, owner, p));
        payload =
          kind === "continue"
            ? { text: (p as ReturnType<typeof continueArgs.parse>).message }
            : {
                native_request_id: (p as ReturnType<typeof answerArgs.parse>).native_request_id,
                answers: (p as ReturnType<typeof answerArgs.parse>).answers,
              };
      }
      const s = commandScope(owner, host);
      ({ grant, expires } = s);
    }
    const envelope: Envelope = {
      fleet: options.fleet,
      principal: owner,
      host,
      thread_id: thread,
      project,
      provider,
      run,
      request_id: request,
      payload,
      kind,
      grant,
      revision: 1,
      expires,
    };
    const authority = grantFor(envelope);
    validateOperation(envelope, authority, now());
    return { envelope, grant: authority };
  };
  const services: SidecarServices = {
    continue: (owner, p) => commands().continue(owner, p),
    answer: (owner, p) => commands().answer(owner, p),
    creation: { create: (owner, p) => commands().creation.create(owner, p) },
    settings: {
      standard: (owner, p) => commands().settings.standard(owner, p),
      receipt: (owner, p) => commands().settings.receipt(owner, p),
    },
    receipt: (owner, p) => commands().receipt(owner, p),
    followup: (owner, p) => bridge.followup(owner, p),
    followupReceipt: async (owner, request) => {
      const r = bridge.store.get("followup", hash([owner, request]));
      if (!r || r.owner !== owner || r.requestId !== request) return undefined;
      bridge.grant(owner, r.sessionId);
      return r;
    },
  };
  return {
    bind,
    currentGrant: async (e: Envelope) => grantFor(e),
    observe: (e: Envelope) => reconcileExisting(e, services),
    observationBinding(subscription: Record<string, unknown>, event?: unknown): OperationBinding {
      if (subscription.owner !== options.observationOwner)
        throw Error("observation_owner_mismatch");
      const { host, thread } = eventTarget(bridge, subscription, event);
      const data = (event as { data: NativeRecord }).data;
      if (subscription.name === "t3.fleet.activity")
        bridge.fleetEvents.grant(
          options.observationOwner,
          host,
          data.project_id,
          data.provider_instance_id,
        );
      else if (subscription.name === "t3.thread.activity") bridge.lanes.authorize(subscription);
      else if (subscription.name === "t3.eddie.requested") {
        bridge.exchanges.inbox(options.observationOwner, subscription.inboxId);
        const r = bridge.store.get("exchange", data.request_id);
        if (
          !r ||
          r.reviewer !== options.observationOwner ||
          r.host !== host ||
          r.thread_id !== thread ||
          !["pending", "read"].includes(bridge.exchanges.status(r))
        )
          throw Error("forbidden");
        const caller = bridge.exchanges.caller(r.caller);
        if (caller.reviewer !== r.reviewer || caller.host !== host || caller.threadId !== thread)
          throw Error("forbidden");
      }
      const scope = projectNativeGrant(
        bridge.policy(),
        options.observationOwner,
        host,
        "observation",
        options.serviceExpiresAt,
        now(),
      );
      const project =
        data.project_id ??
        (scope.projects === null ? "__authorized_host_observation__" : undefined);
      const binding = {
        project: text(project),
        provider: "__observation__",
        run: null,
        grant: scope.grant,
        revision: scope.revision,
        expires: scope.expires,
      };
      authorizeBinding(binding, [], now(), { host, purpose: "observation", grants: [scope] });
      return binding;
    },
  };
}
