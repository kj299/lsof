<#
.SYNOPSIS
    Oracle-substitution differential for winlsof sockets (Windows-only capture).

.DESCRIPTION
    The C `lsof` cannot run on Windows, so there is no same-binary oracle. This
    script substitutes the OS's own socket table: it stands up deterministic,
    self-owned fixtures (a loopback TCP listener, an established loopback pair,
    and a bound UDP socket), captures winlsof's `-i -J` view AND the equivalent
    Get-NetTCPConnection / Get-NetUDPEndpoint view, and hands both to the
    portable comparator (oracle_diff.py), which fails on any unledgered set
    divergence. Scoping to this process's pid and to the fixture ports makes the
    gate deterministic -- no dependence on whatever else the machine is doing.

    Only built-in cmdlets + `python` are used (no Sysinternals, no elevation, no
    third-party GitHub Actions), so it runs on a stock windows-latest runner.

.PARAMETER Bin
    Path to the lsof.exe under test (a CI build or a release binary).

.PARAMETER Python
    Python launcher (default: python).

.PARAMETER TimeoutSec
    Hard timeout for the winlsof invocation (a regressed hang fails fast).

.EXAMPLE
    pwsh winlsof/differential/capture.ps1 -Bin winlsof/target/release/lsof.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bin,
    [string]$Python = 'python',
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path $Bin)) { throw "lsof.exe not found: $Bin" }
$Bin = (Resolve-Path $Bin).Path
$self = $PID
$work = Join-Path $env:TEMP ("winlsof_diff_{0}" -f $self)
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "winlsof socket oracle-substitution differential" -ForegroundColor Cyan
Write-Host "Binary : $Bin"
Write-Host "PID    : $self"

# --- fixtures owned by THIS process -----------------------------------------
# A TCP listener, an established loopback pair (exercises the remote-address /
# state path where fidelity bugs hide), and a bound UDP socket.
$loop = [Net.IPAddress]::Loopback
$listener = [Net.Sockets.TcpListener]::new($loop, 0)
$listener.Start()
$lport = ([Net.IPEndPoint]$listener.LocalEndpoint).Port

$client = [Net.Sockets.TcpClient]::new()
$client.Connect($loop, $lport)
$server = $listener.AcceptTcpClient()
$cport = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Port

$udp = [Net.Sockets.UdpClient]::new(0, [Net.Sockets.AddressFamily]::InterNetwork)
$uport = ([Net.IPEndPoint]$udp.Client.LocalEndPoint).Port

$ports = @($lport, $cport, $uport)
Write-Host ("Fixtures: TCP listen={0}  established={0}<->{1}  UDP={2}" -f $lport, $cport, $uport)

$rc = 3
try {
    # --- capture winlsof's view (bounded, so a hang can't wedge CI) ---------
    $wlJson = Join-Path $work 'winlsof.json'
    $errTmp = Join-Path $work 'winlsof.err'
    $p = Start-Process -FilePath $Bin -ArgumentList @('-nP', '-i', '-J') -NoNewWindow -PassThru `
        -RedirectStandardOutput $wlJson -RedirectStandardError $errTmp
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        throw "winlsof -i -J hung > ${TimeoutSec}s (liveness regression)"
    }

    # --- capture the OS oracle for this pid ---------------------------------
    $rows = New-Object System.Collections.Generic.List[object]
    Get-NetTCPConnection -OwningProcess $self -ErrorAction SilentlyContinue | ForEach-Object {
        $rows.Add([pscustomobject]@{
            proto       = 'TCP'
            family      = $(if ($_.LocalAddress -match ':') { 'IPv6' } else { 'IPv4' })
            local_addr  = $_.LocalAddress
            local_port  = [int]$_.LocalPort
            remote_addr = $_.RemoteAddress
            remote_port = [int]$_.RemotePort
            state       = "$($_.State)"
            pid         = [int]$_.OwningProcess
        })
    }
    Get-NetUDPEndpoint -OwningProcess $self -ErrorAction SilentlyContinue | ForEach-Object {
        $rows.Add([pscustomobject]@{
            proto       = 'UDP'
            family      = $(if ($_.LocalAddress -match ':') { 'IPv6' } else { 'IPv4' })
            local_addr  = $_.LocalAddress
            local_port  = [int]$_.LocalPort
            remote_addr = $null
            remote_port = $null
            state       = $null
            pid         = [int]$_.OwningProcess
        })
    }
    $oracleJson = Join-Path $work 'oracle.json'
    # -Depth so nested nulls survive; -AsArray keeps a single row a JSON list.
    ConvertTo-Json -InputObject $rows.ToArray() -Depth 4 -AsArray | Set-Content -LiteralPath $oracleJson -Encoding utf8

    # --- diff -----------------------------------------------------------------
    $ledger = Join-Path $here 'ledger.json'
    $scope = ($ports | ForEach-Object { "$_" }) -join ','
    Write-Host "`nComparing winlsof's socket set to the OS oracle (scope: pid=$self ports=$scope)`n"
    & $Python (Join-Path $here 'oracle_diff.py') `
        --winlsof-json $wlJson --oracle $oracleJson --ledger $ledger `
        --scope-pid $self --scope-ports $scope
    $rc = $LASTEXITCODE
}
finally {
    try { $server.Dispose() } catch {}
    try { $client.Dispose() } catch {}
    try { $listener.Stop() } catch {}
    try { $udp.Dispose() } catch {}
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

if ($rc -ne 0) { Write-Host "`nDIFFERENTIAL FAILED (exit $rc)" -ForegroundColor Red }
else { Write-Host "`nDIFFERENTIAL OK" -ForegroundColor Green }
exit $rc
