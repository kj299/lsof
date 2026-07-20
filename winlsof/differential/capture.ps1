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

    Exit codes mirror oracle_diff.py: 0 = ok, 1 = socket-set divergence,
    2 = infra (a fixture/capture problem -- NOT a winlsof verdict).

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
# python's non-zero exit is DATA (the differential verdict), not a terminating
# error -- pwsh 7.3+ would otherwise throw past the $rc capture below.
$PSNativeCommandUseErrorActionPreference = $false

if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "capture.ps1 needs PowerShell 7+ (pwsh); found $($PSVersionTable.PSVersion). CI pins shell: pwsh."
}

$EXIT_INFRA = 2
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not (Test-Path $Bin)) { throw "lsof.exe not found: $Bin" }
$Bin = (Resolve-Path $Bin).Path
$self = $PID
$work = Join-Path $env:TEMP ("winlsof_diff_{0}" -f $self)
New-Item -ItemType Directory -Force -Path $work | Out-Null

Write-Host "winlsof socket oracle-substitution differential" -ForegroundColor Cyan
Write-Host "Binary : $Bin"
Write-Host "PID    : $self"

# Get-Net* are CIM/WMI-backed and can transiently return nothing on a loaded
# runner. Retry a few times; an empty result there would otherwise make our own
# held-open fixtures look like winlsof "extras". Return $null only if it never
# yields rows, so the caller can classify it as infra rather than a divergence.
function Get-OracleRows {
    param([scriptblock]$Cmd, [string]$Label)
    for ($i = 1; $i -le 3; $i++) {
        try {
            $r = @(& $Cmd)
            if ($r.Count -gt 0) { return $r }
        } catch {
            Write-Host ("  {0}: attempt {1} failed: {2}" -f $Label, $i, $_.Exception.Message) -ForegroundColor Yellow
        }
        Start-Sleep -Milliseconds 300
    }
    return $null
}

$listener = $client = $server = $udp = $null
$rc = $EXIT_INFRA
try {
    # --- fixtures owned by THIS process (inside try, so a setup throw still
    #     hits the finally that disposes them) --------------------------------
    $loop = [Net.IPAddress]::Loopback
    $listener = [Net.Sockets.TcpListener]::new($loop, 0)
    $listener.Start()
    $lport = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect($loop, $lport)                      # blocking -> ESTABLISHED
    $server = $listener.AcceptTcpClient()
    $cport = ([Net.IPEndPoint]$client.Client.LocalEndPoint).Port
    $udp = [Net.Sockets.UdpClient]::new(0, [Net.Sockets.AddressFamily]::InterNetwork)
    $uport = ([Net.IPEndPoint]$udp.Client.LocalEndPoint).Port
    $ports = @($lport, $cport, $uport)
    # NB: covers LISTEN + ESTABLISHED + UDP over IPv4 loopback. IPv6 and
    # non-ESTABLISHED-state fixtures are a documented follow-up (README).
    Write-Host ("Fixtures: TCP listen={0}  established={0}<->{1}  UDP={2}" -f $lport, $cport, $uport)

    # --- capture winlsof's view (bounded; a hang fails fast as infra) --------
    $wlJson = Join-Path $work 'winlsof.json'
    $errTmp = Join-Path $work 'winlsof.err'
    $p = Start-Process -FilePath $Bin -ArgumentList @('-nP', '-i', '-J') -NoNewWindow -PassThru `
        -RedirectStandardOutput $wlJson -RedirectStandardError $errTmp
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        Write-Host "INFRA: winlsof -i -J hung > ${TimeoutSec}s (liveness regression)" -ForegroundColor Red
        exit $EXIT_INFRA
    }
    if ($p.ExitCode -ne 0) {
        Write-Host ("INFRA: winlsof exited {0}; stderr follows" -f $p.ExitCode) -ForegroundColor Red
        Get-Content -LiteralPath $errTmp -ErrorAction SilentlyContinue | Write-Host
        exit $EXIT_INFRA
    }

    # --- capture the OS oracle for this pid (retry transient CIM failures) ----
    $tcp = Get-OracleRows -Label 'Get-NetTCPConnection' -Cmd { Get-NetTCPConnection -OwningProcess $self }
    $udpRows = Get-OracleRows -Label 'Get-NetUDPEndpoint' -Cmd { Get-NetUDPEndpoint -OwningProcess $self }
    if ($null -eq $tcp -or $null -eq $udpRows) {
        Write-Host "INFRA: OS oracle capture returned nothing after retries (transient CIM/WMI)" -ForegroundColor Red
        exit $EXIT_INFRA
    }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($c in $tcp) {
        $rows.Add([pscustomobject]@{
            proto = 'TCP'
            family = $(if ($c.LocalAddress -match ':') { 'IPv6' } else { 'IPv4' })
            local_addr = "$($c.LocalAddress)"; local_port = [int]$c.LocalPort
            remote_addr = "$($c.RemoteAddress)"; remote_port = [int]$c.RemotePort
            state = "$($c.State)"; pid = [int]$c.OwningProcess
        })
    }
    foreach ($u in $udpRows) {
        $rows.Add([pscustomobject]@{
            proto = 'UDP'
            family = $(if ($u.LocalAddress -match ':') { 'IPv6' } else { 'IPv4' })
            local_addr = "$($u.LocalAddress)"; local_port = [int]$u.LocalPort
            remote_addr = $null; remote_port = $null
            state = $null; pid = [int]$u.OwningProcess
        })
    }

    # --- fixture-present floor: our own sockets MUST show up in the oracle, or
    #     the capture is broken (empty/partial) -- classify as infra, never let
    #     a missing oracle masquerade as a winlsof divergence. -----------------
    $oraclePorts = @($rows | ForEach-Object { $_.local_port })
    foreach ($fp in $ports) {
        if ($oraclePorts -notcontains $fp) {
            Write-Host ("INFRA: fixture port {0} absent from the OS oracle capture" -f $fp) -ForegroundColor Red
            exit $EXIT_INFRA
        }
    }

    $oracleJson = Join-Path $work 'oracle.json'
    ConvertTo-Json -InputObject $rows.ToArray() -Depth 4 -AsArray | Set-Content -LiteralPath $oracleJson -Encoding utf8

    # --- diff (comparator classifies: 0 ok / 1 divergence / 2 infra) ---------
    $ledger = Join-Path $here 'ledger.json'
    $scope = ($ports | ForEach-Object { "$_" }) -join ','
    Write-Host "`nComparing winlsof's socket set to the OS oracle (scope: pid=$self ports=$scope)`n"
    & $Python (Join-Path $here 'oracle_diff.py') `
        --winlsof-json $wlJson --oracle $oracleJson --ledger $ledger `
        --scope-pid $self --scope-ports $scope
    $rc = $LASTEXITCODE
}
finally {
    foreach ($d in @($server, $client, $udp)) { if ($null -ne $d) { try { $d.Dispose() } catch {} } }
    if ($null -ne $listener) { try { $listener.Stop() } catch {} }
    Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

switch ($rc) {
    0       { Write-Host "`nDIFFERENTIAL OK" -ForegroundColor Green }
    2       { Write-Host "`nINFRA FAILURE (capture/fixture, not a winlsof divergence)" -ForegroundColor Yellow }
    default { Write-Host "`nDIFFERENTIAL FAILED (exit $rc)" -ForegroundColor Red }
}
exit $rc
