// SPDX-License-Identifier: AGPL-3.0-or-later
// The Fetch standard's "bad ports" that Node's fetch refuses outright. Hosts
// whose ephemeral range starts low (some Windows machines start at 1024) can
// hand these out from listen(0), which made fetch-based tests fail at random.
// https://fetch.spec.whatwg.org/#bad-port
export const FETCH_BLOCKED_PORTS = new Set([
  1719, 1720, 1723, 2049, 3659, 4045, 4190, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669,
  6679, 6697, 10080,
]);

/** listen(0) on loopback, re-binding until the port is one fetch can reach. */
export async function listenLoopback(server, host = "127.0.0.1") {
  for (;;) {
    await new Promise((resolve) => server.listen(0, host, resolve));
    if (!FETCH_BLOCKED_PORTS.has(server.address().port)) return server;
    await new Promise((resolve) => server.close(resolve));
  }
}
