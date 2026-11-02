// SPDX-License-Identifier: AGPL-3.0-or-later
export type OperationBinding = {
  project: string;
  provider: string;
  run: string | null;
  grant: string;
  revision: number;
  expires: number;
};
/** A projection of one existing native grant, never an agent-supplied grant.
 * Fingerprint/revision bind the complete original authority. Actual project,
 * provider and run remain exact on each reservation and native service call. */
export type NativeGrantScope = {
  host: string;
  purpose: "command" | "observation";
  grant: string;
  revision: number;
  expires: number;
  projects: string[] | null;
  providers: string[] | null;
};
export function nativeGrantScope(value: unknown): NativeGrantScope {
  const s = value as NativeGrantScope;
  const list = (v: unknown, limit: number) =>
    v === null ||
    (Array.isArray(v) &&
      v.length > 0 &&
      v.length <= limit &&
      new Set(v).size === v.length &&
      v.every((x) => typeof x === "string" && x.length > 0 && x.length <= 2048));
  if (
    !s ||
    typeof s !== "object" ||
    Array.isArray(s) ||
    Object.keys(s).some(
      (k) =>
        !["host", "purpose", "grant", "revision", "expires", "projects", "providers"].includes(k),
    ) ||
    typeof s.host !== "string" ||
    !s.host ||
    s.host.length > 100 ||
    !["command", "observation"].includes(s.purpose) ||
    typeof s.grant !== "string" ||
    !/^[a-f0-9]{64}$/.test(s.grant) ||
    !Number.isSafeInteger(s.revision) ||
    s.revision < 1 ||
    !Number.isSafeInteger(s.expires) ||
    !list(s.projects, 100) ||
    !list(s.providers, 20) ||
    (s.purpose === "command" && s.providers === null)
  )
    throw Error("invalid_request");
  return s;
}
export function tightensNativeGrant(next: NativeGrantScope, prior: NativeGrantScope) {
  const subset = (n: string[] | null, p: string[] | null) =>
    p === null || (n !== null && n.every((x) => p.includes(x)));
  return (
    next.host === prior.host &&
    next.purpose === prior.purpose &&
    next.grant === prior.grant &&
    next.revision === prior.revision &&
    next.expires <= prior.expires &&
    subset(next.projects, prior.projects) &&
    subset(next.providers, prior.providers)
  );
}
export function operationBinding(value: unknown): OperationBinding {
  const b = value as OperationBinding;
  if (
    !b ||
    Object.keys(b).some(
      (k) => !["project", "provider", "run", "grant", "revision", "expires"].includes(k),
    ) ||
    [b.project, b.provider, b.grant].some(
      (v) => typeof v !== "string" || !v.length || v.length > 2048,
    ) ||
    (b.run !== null && (typeof b.run !== "string" || !b.run.length)) ||
    !Number.isSafeInteger(b.revision) ||
    b.revision < 1 ||
    !Number.isSafeInteger(b.expires)
  )
    throw Error("invalid_request");
  return b;
}
export function authorizeBinding(
  binding: OperationBinding,
  scopes: OperationBinding[] | undefined,
  now: number,
  native?: { host: string; purpose: NativeGrantScope["purpose"]; grants?: NativeGrantScope[] },
) {
  if (
    binding.expires <= now ||
    !(
      scopes?.some(
        (s) =>
          s.project === binding.project &&
          s.provider === binding.provider &&
          s.run === binding.run &&
          s.grant === binding.grant &&
          s.revision === binding.revision &&
          s.expires >= binding.expires &&
          s.expires > now,
      ) ||
      native?.grants?.some(
        (s) =>
          s.host === native.host &&
          s.purpose === native.purpose &&
          s.grant === binding.grant &&
          s.revision === binding.revision &&
          s.expires >= binding.expires &&
          s.expires > now &&
          (s.projects === null || s.projects.includes(binding.project)) &&
          (s.providers === null || s.providers.includes(binding.provider)),
      )
    )
  )
    throw Error("forbidden");
}
