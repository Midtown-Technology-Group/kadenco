# SPDX-License-Identifier: AGPL-3.0-or-later
# kadenco-edge-mint: pairs with kadenco-edge-windows.sh. Runs every 5 minutes as
# the T3 owner (user-level scheduled task, no elevation; Windows PowerShell 5.1
# or 7). Issues two 15-minute eddie-t3-delivery T3 sessions (read; read+operate)
# for the Kadenco central edge and copies T3's runtime metadata into $dir. Create $dir with inheritance
# removed and access only for the owner, SYSTEM, Administrators and the edge's
# local SSH account (read). Never logs the token.
# --- configuration -----------------------------------------------------------
$dir = 'C:\Users\OWNER\.local\share\kadenco-edge'
$log = 'C:\Users\OWNER\.local\share\kadenco-edge-mint\mint.log'
$runtimeFile = 'C:\Users\OWNER\.t3\userdata\server-runtime.json'
$t3 = 'C:\Users\OWNER\.local\bin\t3.cmd'   # owner's T3 CLI shim (a .cmd: PowerShell
                                            # does not capture the GUI executable's output)
$baseDir = 'C:/Users/OWNER/.t3'
# --- end configuration -------------------------------------------------------
$ErrorActionPreference = 'Stop'
function Log([string]$m) { Add-Content -Path $log -Value ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK'), $m) }
function Write-Atomic([string]$name, [string]$text) {
  $path = Join-Path $dir $name; $tmp = "$path.tmp"
  [IO.File]::WriteAllText($tmp, $text, (New-Object Text.UTF8Encoding($false)))
  Move-Item -Force -LiteralPath $tmp -Destination $path
}
New-Item -ItemType Directory -Force (Split-Path -Parent $log) | Out-Null
try {
  # The output directory carries the restricted ACL; it is created at setup.
  if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw 'mint directory missing; see linux-edge.md' }
  if ((Get-Item $log -ErrorAction SilentlyContinue).Length -gt 1MB) { Move-Item -Force $log "$log.1" }
  $runtime = [IO.File]::ReadAllText($runtimeFile)
  $port = ($runtime | ConvertFrom-Json).port
  if (-not ($port -is [long] -or $port -is [int]) -or $port -lt 1 -or $port -gt 65535) { throw 'runtime port invalid' }
  Write-Atomic 'runtime.json' $runtime

  # One session per scope the edge requests, so a read-only request never
  # receives operate authority.
  foreach ($kind in @(@{ file = 'delivery-read.json'; scopes = @('--scope', 'orchestration:read') },
                      @{ file = 'delivery.json'; scopes = @('--scope', 'orchestration:read', '--scope', 'orchestration:operate') })) {
    $out = & $t3 auth session issue --base-dir $baseDir @($kind.scopes) --ttl 15m `
      --subject eddie-t3-delivery --label 'Eddie T3 private delivery' --json 2>$null
    if ($LASTEXITCODE) { throw "issue exit $LASTEXITCODE" }
    $text = ($out | Out-String).Trim()
    $issued = $text | ConvertFrom-Json
    if (-not $issued.sessionId -or -not $issued.token -or $issued.subject -ne 'eddie-t3-delivery') { throw 'issue output invalid' }
    Write-Atomic $kind.file $text
  }
  Log "ok expires=$($issued.expiresAt) port=$port"
} catch {
  Log ('FAILED ' + ($_.Exception.Message -replace '[A-Za-z0-9_-]{40,}', '<redacted>'))
  exit 1
}
