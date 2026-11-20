# SPDX-License-Identifier: AGPL-3.0-or-later
[CmdletBinding(DefaultParameterSetName='Call')]
param(
    [Parameter(Mandatory)][string]$CredentialFile,
    [Parameter(Mandatory,ParameterSetName='Call')][ValidateSet('ask','get','ack_reply','ack_delivery','conversation','capabilities')][string]$Mode,
    [Parameter(Mandatory,ParameterSetName='Call')][string]$RequestFile,
    [Parameter(Mandatory,ParameterSetName='Mcp')][switch]$Mcp,
    [string]$NodePath = 'node'
)
$ErrorActionPreference = 'Stop'
$credential = Import-Clixml -LiteralPath $CredentialFile
if ($credential.ExpiresAt -le [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()) { throw 'Caller enrollment expired.' }
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Token)
try {
    $env:EDDIE_T3_CALLER_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $env:EDDIE_T3_CALLER_ENDPOINT = $credential.Endpoint
    if ($Mcp) { & $NodePath (Join-Path $PSScriptRoot 'caller-mcp.mjs') }
    else { & $NodePath (Join-Path $PSScriptRoot 'caller.mjs') $Mode (Resolve-Path -LiteralPath $RequestFile).Path }
    if ($LASTEXITCODE -ne 0) { throw 'Eddie request did not succeed. No automatic retry or T3 execution was requested.' }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    Remove-Item Env:EDDIE_T3_CALLER_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:EDDIE_T3_CALLER_ENDPOINT -ErrorAction SilentlyContinue
    $credential = $null
}
