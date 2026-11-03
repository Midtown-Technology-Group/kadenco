# SPDX-License-Identifier: AGPL-3.0-or-later
# Drain all output, retain the last 8 KiB in memory, and expose only validated
# fixed fields. Never persist raw child output (it can contain credentials).
if (-not ('Kadenco.StartupCapture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
namespace Kadenco {
  public sealed class StartupCapture : Stream {
    private readonly byte[] bytes = new byte[8192];
    private int count;
    public string Snapshot() { lock(bytes) { return Encoding.UTF8.GetString(bytes,0,count); } }
    public override void Write(byte[] b,int o,int n) {
      lock(bytes) {
        if(n>=bytes.Length) {
          Buffer.BlockCopy(b,o+n-bytes.Length,bytes,0,bytes.Length);
          count=bytes.Length;
        } else {
          int drop=Math.Max(0,count+n-bytes.Length);
          if(drop>0) {
            Buffer.BlockCopy(bytes,drop,bytes,0,count-drop);
            count-=drop;
          }
          Buffer.BlockCopy(b,o,bytes,count,n);
          count+=n;
        }
      }
    }
    public override bool CanRead { get { return false; } }
    public override bool CanSeek { get { return false; } }
    public override bool CanWrite { get { return true; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override void Flush() {}
    public override int Read(byte[] b,int o,int n) { throw new NotSupportedException(); }
    public override long Seek(long o,SeekOrigin s) { throw new NotSupportedException(); }
    public override void SetLength(long n) { throw new NotSupportedException(); }
  }
}
'@
}
function Get-KadencoStartupFailure($Capture) {
    if (-not $Capture) { return $null }
    $lines=$Capture.Snapshot() -split "`n"; [array]::Reverse($lines)
    foreach ($line in $lines) {
        if ($line.Length -gt 1024) { continue }
        try { $value=$line|ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($value.event -ceq 'edge_checkpoint_failure' -and $value.local_fallback -eq $false -and $value.reason -cin @('transport_uncertain','central_refused','state_conflict','record_limit','unknown')) { return @{event='edge_checkpoint_failure';reason=$value.reason;local_fallback=$false} }
        if ($value.event -ceq 'edge_lease_failure' -and $value.local_fallback -eq $false -and $value.reason -cin @('transport_uncertain','fenced','refused','invalid_lease')) { return @{event='edge_lease_failure';reason=$value.reason;local_fallback=$false} }
        if ($value.event -cne 'startup_refused' -or $value.local_fallback -ne $false -or
            $value.reason -cnotmatch '^[a-z_]{1,80}$' -or $value.fingerprint -cnotmatch '^[a-f0-9]{64}$') { continue }
        # Reconstruct a strict subset even if the child emits arbitrary fields.
        $reason='unclassified_startup_failure'; if($value.reason -cin @('central_transport_uncertain','edge_lease_unavailable','replica_inventory_changed','replica_central_unavailable','historical_state_overlap','production_state_directory_changed','bootstrap_runtime_configuration_required','invalid_edge_identity','replica_record_exceeds_central_limit','replica_record_too_large')){$reason=$value.reason}
        return @{event='startup_refused';reason=$reason;fingerprint=$value.fingerprint;local_fallback=$false}
    }
    return $null
}
