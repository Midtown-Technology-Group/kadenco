#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Read-only acceptance check against an installed Kadenco: fetches the owner's
// /status and exits 0 only when every journey has fresh, verified evidence.
// It never starts T3 work, sends events or changes state. The bearer is read
// from KADENCO_STATUS_TOKEN or, when that is unset, from stdin.
//   exit 0 = ok, 1 = degraded/unverified/down, 2 = unreachable or refused
const url = process.env.KADENCO_STATUS_URL ?? "http://127.0.0.1:41880/status";
const json = process.argv.includes("--json");

async function bearer() {
  if (process.env.KADENCO_STATUS_TOKEN) return process.env.KADENCO_STATUS_TOKEN.trim();
  if (process.stdin.isTTY) return "";
  const parts = [];
  for await (const chunk of process.stdin) parts.push(chunk);
  return Buffer.concat(parts).toString("utf8").trim();
}

const token = await bearer();
if (!token) {
  console.error("status-check: set KADENCO_STATUS_TOKEN or pipe the owner bearer on stdin");
  process.exit(2);
}
let response;
try {
  response = await fetch(url, {
    headers: { authorization: `Bearer ${token}` },
    signal: AbortSignal.timeout(10000),
  });
} catch (error) {
  console.error(
    `status-check: ${url} unreachable (${error?.cause?.code ?? error?.name ?? "error"})`,
  );
  process.exit(2);
}
if (response.status !== 200) {
  console.error(`status-check: ${url} answered HTTP ${response.status}`);
  process.exit(2);
}
let s;
try {
  s = await response.json();
} catch {
  s = undefined;
}
// Validate every field the exit code and summary depend on, and recompute
// `overall` from its inputs; a report that disagrees with itself is not trusted.
const JOURNEY = ["verified", "stale", "failing", "unverified"];
const LEASE = ["held", "renewal_failing", "lost", "unknown", "not_applicable"];
const expected = (lease, states) =>
  lease === "lost"
    ? "down"
    : lease === "unknown" || lease === "renewal_failing" || states.includes("failing")
      ? "degraded"
      : states.every((x) => x === "verified")
        ? "ok"
        : "unverified";
const journeyStates = [s?.journeys?.ask_eddie?.state, s?.journeys?.event_delivery?.state];
// Every rendered journey must be an object with a known state, and any attempt
// diagnostic it carries must name a request and a stage.
const attempt = (x) =>
  x === undefined ||
  x === null ||
  (typeof x === "object" &&
    typeof x.request_id === "string" &&
    typeof x.stage_reached === "string");
const journeysValid = () =>
  typeof s?.journeys === "object" &&
  s.journeys !== null &&
  Object.values(s.journeys).every(
    (j) =>
      typeof j === "object" &&
      j !== null &&
      JOURNEY.includes(j.state) &&
      attempt(j.stuck) &&
      attempt(j.latest),
  );
// Present and string-or-null; nested objects are checked only when present.
const text = (v) => v === null || typeof v === "string";
const nested = (obj, key) => obj === undefined || obj === null || text(obj[key]);
const leaseFits = (mode, lease) =>
  (mode === "standalone" && lease === "not_applicable") ||
  (mode === "central_edge" && lease !== "not_applicable");
if (
  s?.schema !== 1 ||
  !journeysValid() ||
  !leaseFits(s.runtime?.mode, s.runtime?.lease?.state) ||
  typeof s.build !== "object" ||
  s.build === null ||
  !text(s.build.package_version) ||
  !text(s.build.source_commit) ||
  !nested(s.runtime?.lease?.last_failure, "reason") ||
  !nested(s.runtime?.central, "release_version") ||
  !journeyStates.every((x) => JOURNEY.includes(x)) ||
  !LEASE.includes(s.runtime?.lease?.state) ||
  !Array.isArray(s.hosts) ||
  !s.hosts.every((h) => typeof h?.host === "string") ||
  s.overall !== expected(s.runtime.lease.state, journeyStates)
) {
  console.error(`status-check: ${url} returned an incomplete or unrecognised status body`);
  process.exit(2);
}
if (json) console.log(JSON.stringify(s, null, 2));
else {
  const lease = s.runtime?.lease ?? {};
  console.log(`overall      ${s.overall}`);
  console.log(
    `build        ${s.build?.package_version ?? "unknown"} source ${s.build?.source_commit?.slice(0, 12) ?? "unknown"}`,
  );
  console.log(
    `runtime      ${s.runtime?.mode} lease ${lease.state}` +
      (s.runtime?.central ? ` central ${s.runtime.central.release_version ?? "unknown"}` : "") +
      (lease.last_failure
        ? ` (last failure ${lease.last_failure.reason} at ${lease.last_failure.at})`
        : ""),
  );
  for (const [name, j] of Object.entries(s.journeys ?? {})) {
    const at = j.last_verified?.acknowledged_at ?? j.last_acknowledged_at ?? "never";
    const stuck = j.stuck
      ? `; stuck: ${j.stuck.request_id} at ${j.stuck.stage_reached}`
      : j.latest
        ? `; latest attempt at ${j.latest.stage_reached}`
        : "";
    console.log(`${name.padEnd(12)} ${j.state} (last verified ${at}${stuck})`);
  }
  for (const h of s.hosts ?? [])
    console.log(
      `host ${h.host.padEnd(7)} ${h.last_outcome}${h.last_reason ? ` ${h.last_reason}` : ""} at ${h.last_observed_at ?? "never"}`,
    );
}
// exitCode (not exit()) lets a large --json report finish writing to a pipe.
process.exitCode = s.overall === "ok" ? 0 : 1;
