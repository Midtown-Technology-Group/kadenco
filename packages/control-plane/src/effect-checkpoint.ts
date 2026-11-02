// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Bridge } from "../../../dist/bridge.mjs";
/** Persist the original service's already-reserved command immediately before
 * its native transport call. Preserve original authorizeDispatch and callback
 * options; this hook adds no native operation or authority. */
export function checkpointNativeEffects(bridge: Bridge, checkpoint: () => Promise<void>) {
  const commands = bridge.commands,
    session = commands?.session,
    backend = bridge.backend;
  if (commands && session)
    commands.session = (route, fn, options) =>
      session.call(
        commands,
        route,
        (call: (base: string, tag: string, payload: unknown) => Promise<unknown>) =>
          fn(async (base: string, tag: string, payload: unknown) => {
            if (tag === "orchestration.dispatchCommand") await checkpoint();
            return call(base, tag, payload);
          }),
        options,
      );
  bridge.backend = new Proxy(backend, {
    get(target, property) {
      const value = Reflect.get(target, property);
      if (property === "followup")
        return async (...args: Parameters<typeof backend.followup>) => {
          await checkpoint();
          return target.followup(...args);
        };
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return () => {
    if (commands && session) commands.session = session;
    bridge.backend = backend;
  };
}
