// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
export type MutationKind = "continue" | "create" | "settings_standard" | "answer" | "verify_result";
/** The coordinator must perform central reservation, current-policy validation and
 * durable journal protocol before invoking execute. Never exposed as remote RPC. */
export function gateEdgeMutations(
  bridge: Bridge,
  coordinate: (
    kind: MutationKind,
    owner: string,
    input: unknown,
    execute: () => Promise<unknown>,
  ) => Promise<unknown>,
): Bridge {
  const commands = bridge.commands;

  const wrap = (object: object, mutations: Record<string, MutationKind>) =>
    new Proxy(object, {
      get(target, key) {
        const value = Reflect.get(target, key);
        if (typeof value !== "function") return value;
        const kind = mutations[String(key)];
        return kind
          ? (owner: string, input: unknown, ...rest: unknown[]) =>
              coordinate(kind, owner, input, () =>
                Promise.resolve(value.call(target, owner, input, ...rest)),
              )
          : value.bind(target);
      },
    });
  const guarded = commands
    ? new Proxy(commands, {
        get(target, key) {
          if (key === "creation") return wrap(target.creation, { create: "create" });
          if (key === "settings") return wrap(target.settings, { standard: "settings_standard" });
          const value = Reflect.get(target, key);
          if (typeof value !== "function") return value;
          const kind = ({ continue: "continue", answer: "answer" } as Record<string, MutationKind>)[
            String(key)
          ];
          return kind
            ? (owner: string, input: unknown, ...rest: unknown[]) =>
                coordinate(kind, owner, input, () =>
                  Promise.resolve(value.call(target, owner, input, ...rest)),
                )
            : value.bind(target);
        },
      })
    : undefined;
  return new Proxy(bridge, {
    get(target, key) {
      if (key === "commands") return guarded;
      if (key === "followup")
        return (owner: string, input: unknown) =>
          coordinate("verify_result", owner, input, () => target.followup(owner, input as never));
      const value = Reflect.get(target, key);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
