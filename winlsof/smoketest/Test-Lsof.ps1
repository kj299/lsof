<#
.SYNOPSIS
    Quick, self-contained smoke test for a winlsof lsof.exe binary.

.DESCRIPTION
    A portable sanity check for any lsof.exe (a downloaded release, a CI
    artifact, a local build) - no repo, no Rust toolchain, no Sysinternals
    required. Stands up two fixtures owned by this PowerShell process (a held-
    open temp file and a loopback TCP listener), then runs the binary across a
    representative set of options and asserts observable behavior. Each run is
    bounded by a timeout so a regressed hang fails fast instead of freezing.

    For the full ~37-case validation (pipes, mapped files, WOW64 cwd, modules,
    Restart Manager, every output format, and a handle64 oracle cross-check),
    use Invoke-WinlsofSmokeTest.ps1 -Binary <path> instead.

.PARAMETER Bin
    Path to the lsof.exe to test.

.EXAMPLE
    .\Test-Lsof.ps1 -Bin $env:USERPROFILE\Downloads\lsof.exe
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Bin,
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Continue'
if (-not (Test-Path $Bin)) { throw "lsof.exe not found: $Bin" }
$Bin = (Resolve-Path $Bin).Path
$self = $PID
$script:pass = 0
$script:fail = 0

# Run lsof with a hard timeout; capture stdout/stderr/exit. Caching $p.Handle
# keeps .ExitCode readable after a -PassThru process exits (a PS quirk).
function Invoke-Bin {
    param([string[]]$LsofArgs)
    $o = [IO.Path]::GetTempFileName()
    $e = [IO.Path]::GetTempFileName()
    $p = Start-Process -FilePath $Bin -ArgumentList $LsofArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $o -RedirectStandardError $e
    $null = $p.Handle
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        try { [void]$p.WaitForExit(5000) } catch {}
        $hung = $true
    }
    else { $hung = $false }
    $out = [string](Get-Content -LiteralPath $o -Raw -ErrorAction SilentlyContinue)
    $err = [string](Get-Content -LiteralPath $e -Raw -ErrorAction SilentlyContinue)
    Remove-Item $o, $e -Force -ErrorAction SilentlyContinue
    [pscustomobject]@{
        Out  = $out
        Err  = $err
        Exit = $(if ($hung) { $null } else { $p.ExitCode })
        Hung = $hung
    }
}

function Test-That {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    if ($Ok) { Write-Host ("  [PASS] {0} {1}" -f $Name, $Detail) -ForegroundColor Green; $script:pass++ }
    else { Write-Host ("  [FAIL] {0} {1}" -f $Name, $Detail) -ForegroundColor Red; $script:fail++ }
}

Write-Host "winlsof quick smoke test" -ForegroundColor Cyan
Write-Host "Binary : $Bin"
Write-Host "PID    : $self`n"

# Fixtures owned by this process, so -p <self> and -i <port> have known targets.
$tmp = Join-Path $env:TEMP ("lsoftest_{0}.dat" -f $self)
$fs = [IO.File]::Open($tmp, 'Create', 'ReadWrite', 'Read')
$fs.Write([byte[]](1..32), 0, 32); $fs.Flush()
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port

try {
    $r = Invoke-Bin @('-v')
    Test-That 'version banner'        ($r.Out -match 'winlsof') "exit=$($r.Exit)"

    $r = Invoke-Bin @('-h')
    Test-That 'help / usage'          (($r.Out -match 'USAGE') -and ($r.Out -match '-i'))

    $r = Invoke-Bin @('-Z')
    Test-That 'bad option -> nonzero' (($r.Exit -ne $null) -and ($r.Exit -ne 0))

    $r = Invoke-Bin @('-t')
    Test-That 'terse PID list'        ($r.Out -match "(?m)^\d+\s*$")

    $r = Invoke-Bin @('-p', "$self")
    Test-That 'own held file listed'  ($r.Out -match "lsoftest_$self")

    $r = Invoke-Bin @('-p', "$self")
    Test-That 'USER column present'   ($r.Out -match [regex]::Escape($env:USERNAME))

    $r = Invoke-Bin @('-nP', "-iTCP:$port")
    $sockOk = ($r.Out -match ":$port") -and ($r.Out -match 'LISTEN') -and ($r.Out -match "(?m)\b$self\b")
    Test-That 'listening socket + PID' $sockOk "port=$port"

    $r = Invoke-Bin @('-nP', "-iTCP:$port", '-J')
    Test-That 'JSON output shape'     ($r.Out.TrimStart().StartsWith('{') -and ($r.Out -match '"protocol":"TCP"'))

    $r = Invoke-Bin @('-nP', '-i')
    Test-That 'system sockets run'    ($r.Exit -eq 0)

    $r = Invoke-Bin @('-nP', '-iTCP', '-Fpn')
    Test-That 'field output (-F)'     ($r.Out -match "(?m)^p\d+")
}
finally {
    $fs.Dispose()
    $listener.Stop()
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}

$total = $script:pass + $script:fail
Write-Host ("`nResult: PASS={0}  FAIL={1}  (total {2})" -f $script:pass, $script:fail, $total)
$color = if ($script:fail -gt 0) { 'Red' } else { 'Green' }
$msg = if ($script:fail -gt 0) { 'Some checks failed.' } else { 'All checks passed.' }
Write-Host $msg -ForegroundColor $color
exit ([int]($script:fail -gt 0))
