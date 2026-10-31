// SPDX-License-Identifier: AGPL-3.0-or-later
export type OperationBinding = {
  project: string;
  provider: string;
  run: string | null;
  grant: string;
  revision: number;
  expires: number;
};
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
) {
  if (
    binding.expires <= now ||
    !scopes?.some(
      (s) =>
        s.project === binding.project &&
        s.provider === binding.provider &&
        s.run === binding.run &&
        s.grant === binding.grant &&
        s.revision === binding.revision &&
        s.expires >= binding.expires &&
        s.expires > now,
    )
  )
    throw Error("forbidden");
}
