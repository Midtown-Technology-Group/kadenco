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
const s = await response.json();
if (json) console.log(JSON.stringify(s, null, 2));
else {
  const lease = s.runtime?.lease ?? {};
  console.log(`overall      ${s.overall}`);
  console.log(
    `build        ${s.build?.package_version ?? "unknown"} source ${s.build?.source_commit?.slice(0, 12) ?? "unknown"}`,
  );
  console.log(
    `runtime      ${s.runtime?.mode} lease ${lease.state}` +
      (lease.last_failure
        ? ` (last failure ${lease.last_failure.reason} at ${lease.last_failure.at})`
        : ""),
  );
  for (const [name, j] of Object.entries(s.journeys ?? {})) {
    const at = j.last_verified?.acknowledged_at ?? j.last_acknowledged_at ?? "never";
    const stuck =
      j.latest && j.state === "failing" ? `; latest stuck at ${j.latest.stage_reached}` : "";
    console.log(`${name.padEnd(12)} ${j.state} (last verified ${at}${stuck})`);
  }
  for (const h of s.hosts ?? [])
    console.log(
      `host ${h.host.padEnd(7)} ${h.last_outcome}${h.last_reason ? ` ${h.last_reason}` : ""} at ${h.last_observed_at ?? "never"}`,
    );
}
process.exit(s.overall === "ok" ? 0 : 1);
