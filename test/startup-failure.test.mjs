// SPDX-License-Identifier: AGPL-3.0-or-later
import { test } from "node:test";
import assert from "node:assert/strict";
import { startupFailure } from "../packages/control-plane/operator/startup-failure.mjs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
test("startup refusals preserve static failure classes and never expose private error text", () => {
  const known = startupFailure(Error("central_transport_uncertain"));
  assert.equal(known.reason, "central_transport_uncertain");
  assert.equal(known.local_fallback, false);
  const secret = Object.assign(
    Error("fetch https://private.invalid/?token=fixture-private-marker"),
    { code: "ENOENT" },
  );
  const r = startupFailure(secret);
  assert.equal(r.reason, "unclassified_startup_failure");
  assert.equal(r.error_code, "ENOENT");
  assert.match(r.fingerprint, /^[a-f0-9]{64}$/);
  assert.equal(JSON.stringify(r).includes("fixture-private-marker"), false);
  assert.deepEqual(startupFailure(secret), r);
  assert.equal(
    startupFailure({ message: "fixture-private-marker", code: "fixture-private-marker" })
      .error_code,
    null,
  );
});
test(
  "Windows supervisor drains bounded stderr and exposes only reconstructed refusal fields",
  { skip: process.platform !== "win32" },
  () => {
    const helper = fileURLToPath(
      new URL("../packages/control-plane/operator/startup-diagnostics.ps1", import.meta.url),
    );
    const result = execFileSync(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        `
    . '${helper.replaceAll("'", "''")}'
    $capture=New-Object Kadenco.StartupCapture
    $line=@{event='startup_refused';reason='central_transport_uncertain';fingerprint=('a'*64);local_fallback=$false;private='fixture-secret'}|ConvertTo-Json -Compress
    $bytes=[Text.Encoding]::UTF8.GetBytes(('x'*100000)+"\n"+$line+"\n")
    $inputStream=New-Object IO.MemoryStream(,$bytes)
    $null=$inputStream.CopyToAsync($capture).GetAwaiter().GetResult()
    if($capture.Snapshot().Length -ne 8192){throw 'capture_not_bounded'}
    $startup=Get-KadencoStartupFailure $capture
    $runtime=[Text.Encoding]::UTF8.GetBytes("\n"+(@{event='edge_checkpoint_failure';reason='central_refused';local_fallback=$false;private='fixture-secret'}|ConvertTo-Json -Compress)+"\n")
    $capture.Write($runtime,0,$runtime.Length)
    @{startup=$startup;runtime=(Get-KadencoStartupFailure $capture)}|ConvertTo-Json -Compress
  `,
      ],
      { encoding: "utf8", windowsHide: true },
    );
    const combined = JSON.parse(result);
    const value = combined.startup;
    assert.equal(value.reason, "central_transport_uncertain");
    assert.equal(JSON.stringify(value).includes("fixture-secret"), false);
    assert.deepEqual(Object.keys(value).sort(), [
      "event",
      "fingerprint",
      "local_fallback",
      "reason",
    ]);
    assert.deepEqual(combined.runtime, {
      event: "edge_checkpoint_failure",
      reason: "central_refused",
      local_fallback: false,
    });
  },
);
