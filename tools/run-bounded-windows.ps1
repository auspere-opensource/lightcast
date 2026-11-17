<#
.SYNOPSIS
  Run a command on Windows inside a Job Object with a hard memory, process-count and time ceiling.

.DESCRIPTION
  The Job Object is enforced by the kernel for the command and every process it starts:
  JobMemoryLimit caps committed memory for the whole tree, ActiveProcessLimit caps concurrent
  processes, and KILL_ON_JOB_CLOSE ends the tree if this script exits. A wall-clock timeout
  terminates the job.

.EXAMPLE
  powershell -NoProfile -File tools\run-bounded-windows.ps1 -MemoryMB 12288 -MaxProcs 256 -TimeoutSec 1800 -Command "cargo test --release -j 8"

.NOTES
  The command is ONE string: Windows PowerShell's -File treats any bare argument beginning with '-'
  (including '--' and '--release') as a parameter name. It is split on spaces, so arguments must
  not contain spaces.
#>
param(
  [Parameter(Mandatory = $true)][int]$MemoryMB,
  [Parameter(Mandatory = $true)][int]$MaxProcs,
  [Parameter(Mandatory = $true)][int]$TimeoutSec,
  [Parameter(Mandatory = $true)][string]$Command
)
$ErrorActionPreference = 'Stop'
# A [string] parameter stays a string even when assigned an array, so split into a new variable.
$argv = @($Command -split '\s+' | Where-Object { $_ -ne '' })
if ($argv.Count -eq 0) { Write-Error 'usage: run-bounded-windows.ps1 -MemoryMB N -MaxProcs N -TimeoutSec N -Command "COMMAND ARGS"'; exit 2 }

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class BoundedJob {
  [StructLayout(LayoutKind.Sequential)] struct BASIC { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
  [StructLayout(LayoutKind.Sequential)] struct IO { public ulong a, b, c, d, e, f; }
  [StructLayout(LayoutKind.Sequential)] struct EXTENDED { public BASIC Basic; public IO Io; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateJobObject(IntPtr a, string n);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr j, int c, ref EXTENDED i, int l);
  [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr j, int c, ref EXTENDED i, int l, IntPtr r);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool AssignProcessToJobObject(IntPtr j, IntPtr p);
  [DllImport("kernel32.dll", SetLastError = true)] public static extern bool TerminateJobObject(IntPtr j, uint code);
  const uint ACTIVE_PROCESS = 0x8, JOB_MEMORY = 0x200, KILL_ON_CLOSE = 0x2000;
  public static IntPtr Create(ulong memBytes, uint procs) {
    IntPtr j = CreateJobObject(IntPtr.Zero, null);
    if (j == IntPtr.Zero) throw new System.ComponentModel.Win32Exception();
    var info = new EXTENDED();
    info.Basic.LimitFlags = ACTIVE_PROCESS | JOB_MEMORY | KILL_ON_CLOSE;
    info.Basic.ActiveProcessLimit = procs;
    info.JobMemoryLimit = new UIntPtr(memBytes);
    if (!SetInformationJobObject(j, 9, ref info, Marshal.SizeOf(typeof(EXTENDED)))) throw new System.ComponentModel.Win32Exception();
    return j;
  }
  public static ulong PeakMB(IntPtr j) {
    var info = new EXTENDED();
    QueryInformationJobObject(j, 9, ref info, Marshal.SizeOf(typeof(EXTENDED)), IntPtr.Zero);
    return info.PeakJobMemoryUsed.ToUInt64() / 1048576UL;
  }
}
'@

$job = [BoundedJob]::Create([uint64]$MemoryMB * 1MB, [uint32]$MaxProcs)
$exe = $argv[0]
$rest = if ($argv.Count -gt 1) { $argv[1..($argv.Count - 1)] } else { @() }
$resolved = (Get-Command $exe -ErrorAction Stop).Source
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $resolved
$psi.Arguments = ($rest | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ } }) -join ' '
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
# Children started before assignment would escape the job; cargo starts none within this window,
# and every process it starts afterwards inherits the job.
if (-not [BoundedJob]::AssignProcessToJobObject($job, $p.Handle)) { $p.Kill(); throw 'could not assign the process to the job object' }

$sw = [System.Diagnostics.Stopwatch]::StartNew()
if (-not $p.WaitForExit($TimeoutSec * 1000)) {
  [BoundedJob]::TerminateJobObject($job, 124) | Out-Null
  [Console]::Error.WriteLine("run-bounded-windows: ${TimeoutSec}s timeout; job terminated")
  exit 124
}
$p.WaitForExit()
$code = $p.ExitCode
[Console]::Error.WriteLine("run-bounded-windows: exit $code, peak $([BoundedJob]::PeakMB($job)) MB, $([int]$sw.Elapsed.TotalSeconds)s (limits: $MemoryMB MB, $MaxProcs processes, ${TimeoutSec}s)")
exit $code
