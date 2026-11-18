// SPDX-License-Identifier: AGPL-3.0-or-later
// One bounded exit path for the edge process. Signals and lease loss share it:
// the highest requested code wins (75 lease loss over 0 signal), cleanup runs
// once, cleanup failures are reported without their text, the state key is
// always zeroed, and a stalled cleanup cannot keep the process alive past the
// deadline.
export function exitController({
  shutdown,
  zero,
  exit = (code) => process.exit(code),
  report = (value) => console.error(JSON.stringify(value)),
  timeoutMs = 10000,
}) {
  let code = 0;
  let exiting;
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    try {
      zero();
    } finally {
      exit(code);
    }
  };
  return (requested) => {
    if (requested > code) code = requested;
    return (exiting ??= (async () => {
      const deadline = setTimeout(() => {
        report({ event: "edge_shutdown_timeout", local_fallback: false });
        finish();
      }, timeoutMs);
      try {
        await shutdown();
      } catch {
        report({ event: "edge_shutdown_failed", local_fallback: false });
      } finally {
        clearTimeout(deadline);
        finish();
      }
    })());
  };
}
