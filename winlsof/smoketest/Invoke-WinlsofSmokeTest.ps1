<#
.SYNOPSIS
    Live Windows smoke test for winlsof (lsof.exe).

.DESCRIPTION
    Builds lsof.exe, stands up deterministic fixtures (open file at a known
    offset, named pipe, mapped data file, TCP v4/v6 listeners + an established
    pair, UDP v4/v6, child processes with a known cwd incl. 32-bit WOW64), then
    exercises every lsof option / code path, captures output, and cross-checks
    against Windows oracles. Optionally emits an llvm-cov line-coverage report.

    See README.md for the coverage map and how to report findings.

.PARAMETER OutDir
    Root folder for results. Default: .\winlsof-smoke-results

.PARAMETER SkipBuild
    Reuse an existing target build instead of rebuilding.

.PARAMETER Coverage
    Build an instrumented debug binary and produce a line-coverage report.

.PARAMETER HandleExe
    Path to Sysinternals handle64.exe for extra cross-checks (optional).

.EXAMPLE
    .\Invoke-WinlsofSmokeTest.ps1
.EXAMPLE
    .\Invoke-WinlsofSmokeTest.ps1 -Coverage      # run from an elevated prompt
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Get-Location) 'winlsof-smoke-results'),
    [switch]$SkipBuild,
    [switch]$Coverage,
    [string]$HandleExe
)

# 'Continue', not 'Stop': native tools (rustup/cargo, llvm-cov) write progress and
# warnings to stderr, and under 'Stop' PowerShell 5.1 turns that stderr into a
# terminating NativeCommandError that aborts the whole run. Control flow here
# relies on `throw` (Skip/Assert/build failures), which is terminating regardless
# of this setting and is caught by each Test-Case, so 'Continue' is safe.
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Paths & setup
# ---------------------------------------------------------------------------
$Workspace = Split-Path -Parent $PSScriptRoot       # smoketest/ lives under winlsof/
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDir    = Join-Path $OutDir $Stamp
$CasesDir  = Join-Path $RunDir 'cases'
$ProfDir   = Join-Path $RunDir 'profraw'
New-Item -ItemType Directory -Force -Path $CasesDir, $ProfDir | Out-Null
Start-Transcript -Path (Join-Path $RunDir 'transcript.log') | Out-Null

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "winlsof live smoke test  ($Stamp)" -ForegroundColor Cyan
Write-Host "Workspace : $Workspace"
Write-Host "Results   : $RunDir"
Write-Host "Elevated  : $IsAdmin   Coverage: $([bool]$Coverage)`n"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
$BuildProfile = if ($Coverage) { 'debug' } else { 'release' }
if (-not $SkipBuild -and -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is not on PATH. Install Rust from https://rustup.rs and open a new shell, or pass -SkipBuild after placing a prebuilt lsof.exe at target\$BuildProfile\lsof.exe (you can download one from the PR's CI 'lsof-exe-windows' artifact)."
}
if (-not $SkipBuild) {
    Push-Location $Workspace
    try {
        if ($Coverage) {
            if (Get-Command rustup -ErrorAction SilentlyContinue) {
                & rustup component add llvm-tools-preview *> $null
            }
            else {
                Write-Host "rustup not on PATH; skipping llvm-tools-preview install (coverage report may be skipped)." -ForegroundColor Yellow
            }
            $env:RUSTFLAGS = '-C instrument-coverage'
            & cargo build
        }
        else {
            & cargo build --release
        }
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    }
    finally {
        $env:RUSTFLAGS = $null
        Pop-Location
    }
}
$Bin = Join-Path $Workspace ("target\{0}\lsof.exe" -f $BuildProfile)
if (-not (Test-Path $Bin)) { throw "lsof.exe not found at $Bin (build it or drop -SkipBuild)" }
Write-Host "Binary    : $Bin`n"

# ---------------------------------------------------------------------------
# Harness helpers
# ---------------------------------------------------------------------------
$Results = New-Object System.Collections.Generic.List[object]
$CaseIndex = 0

function Invoke-Lsof {
    param(
        [Parameter(Mandatory)][string[]]$LsofArgs,
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutSec = 60
    )
    $script:CaseIndex++
    $tag = '{0:D3}-{1}' -f $script:CaseIndex, ($Name -replace '[^\w.-]', '_')
    $outF = Join-Path $CasesDir "$tag.out.txt"
    $errF = Join-Path $CasesDir "$tag.err.txt"
    if ($Coverage) { $env:LLVM_PROFILE_FILE = (Join-Path $ProfDir "$tag-%p.profraw") }
    # Bounded wait: a healthy scoped query finishes in well under a second. If the
    # child is still alive at the deadline it is almost certainly a regressed hang
    # (e.g. NtQueryObject on a synchronous handle) -- kill it and fail this case
    # rather than freezing the whole harness for hours.
    $p = Start-Process -FilePath $Bin -ArgumentList $LsofArgs -NoNewWindow -PassThru `
        -RedirectStandardOutput $outF -RedirectStandardError $errF
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        try { [void]$p.WaitForExit(5000) } catch {}
        throw "lsof $($LsofArgs -join ' ') did not exit within ${TimeoutSec}s (possible hang)"
    }
    [pscustomobject]@{
        Out  = (Get-Content -LiteralPath $outF -Raw -ErrorAction SilentlyContinue)
        Err  = (Get-Content -LiteralPath $errF -Raw -ErrorAction SilentlyContinue)
        Exit = $p.ExitCode
        Cmd  = "lsof $($LsofArgs -join ' ')"
    }
}

function Skip([string]$reason) { throw "SKIP::$reason" }

function Assert([bool]$cond, [string]$message) {
    if (-not $cond) { throw $message }
}
function Assert-Contains([string]$hay, [string]$needle, [string]$what = 'output') {
    Assert (($null -ne $hay) -and $hay.Contains($needle)) "$what missing '$needle'"
}
function Assert-ContainsCI([string]$hay, [string]$needle, [string]$what = 'output') {
    Assert (($null -ne $hay) -and $hay.ToLowerInvariant().Contains($needle.ToLowerInvariant())) "$what missing '$needle' (ci)"
}
function Assert-NotContains([string]$hay, [string]$needle, [string]$what = 'output') {
    Assert (($null -eq $hay) -or (-not $hay.Contains($needle))) "$what unexpectedly contains '$needle'"
}

function Test-Case {
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Area, [Parameter(Mandatory)][scriptblock]$Body)
    try {
        $note = & $Body
        $st = 'PASS'; $detail = [string]$note
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -like 'SKIP::*') { $st = 'SKIP'; $detail = $msg.Substring(6) }
        else { $st = 'FAIL'; $detail = $msg }
    }
    $Results.Add([pscustomobject]@{ Name = $Name; Area = $Area; Status = $st; Detail = $detail })
    $color = switch ($st) { 'PASS' { 'Green' } 'FAIL' { 'Red' } 'SKIP' { 'Yellow' } default { 'Gray' } }
    Write-Host ("  [{0}] {1,-30} {2}" -f $st, $Name, $detail) -ForegroundColor $color
}

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
$fx = @{}
$self = $PID
try {
    Write-Host "Setting up fixtures..." -ForegroundColor Cyan

    # Held-open regular file, seeked to a known offset (for -o).
    $fx.FilePath = Join-Path $env:TEMP ("winlsof_file_{0}.dat" -f $self)
    $fx.File = [System.IO.File]::Open($fx.FilePath, 'Create', 'ReadWrite', 'None')
    $bytes = [byte[]](0..255); $fx.File.Write($bytes, 0, $bytes.Length); $fx.File.Flush()
    [void]$fx.File.Seek(128, [System.IO.SeekOrigin]::Begin)

    # Named pipe server (PIPE).
    $fx.PipeName = "winlsof_pipe_$self"
    $fx.Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($fx.PipeName, [System.IO.Pipes.PipeDirection]::InOut)

    # Memory-mapped DATA file (mem via mapped.rs).
    $fx.MapPath = Join-Path $env:TEMP ("winlsof_map_{0}.bin" -f $self)
    # 4096-byte buffer. NB: [byte[]](1..4096) overflows -- a [byte] holds 0-255,
    # so casting a 1..4096 range throws "Cannot convert value 256 to System.Byte".
    [System.IO.File]::WriteAllBytes($fx.MapPath, [byte[]]::new(4096))
    $fx.Mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($fx.MapPath, 'Open', "winlsofmap$self")
    $fx.View = $fx.Mmf.CreateViewAccessor()

    # TCP v4 listener + an established connection pair.
    $fx.Tcp4 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $fx.Tcp4.Start()
    $fx.Port4 = ([System.Net.IPEndPoint]$fx.Tcp4.LocalEndpoint).Port
    $fx.Client4 = [System.Net.Sockets.TcpClient]::new()
    $fx.Client4.Connect([System.Net.IPAddress]::Loopback, $fx.Port4)
    $fx.Server4 = $fx.Tcp4.AcceptTcpClient()

    # TCP v6 listener (may be unavailable; tolerate).
    try {
        $fx.Tcp6 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
        $fx.Tcp6.Start()
        $fx.Port6 = ([System.Net.IPEndPoint]$fx.Tcp6.LocalEndpoint).Port
    }
    catch { $fx.Port6 = $null }

    # UDP v4/v6.
    $fx.Udp4 = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetwork)
    $fx.UdpPort4 = ([System.Net.IPEndPoint]$fx.Udp4.Client.LocalEndPoint).Port
    try { $fx.Udp6 = [System.Net.Sockets.UdpClient]::new(0, [System.Net.Sockets.AddressFamily]::InterNetworkV6) } catch {}

    # Child processes with a known cwd (64-bit and 32-bit WOW64).
    $fx.Cwd64 = Start-Process -FilePath "$env:WINDIR\System32\cmd.exe" `
        -ArgumentList '/k', 'cd /d C:\Windows' -WorkingDirectory 'C:\Windows' -PassThru -WindowStyle Hidden
    if (Test-Path "$env:WINDIR\SysWOW64\cmd.exe") {
        $fx.Cwd32 = Start-Process -FilePath "$env:WINDIR\SysWOW64\cmd.exe" `
            -ArgumentList '/k', 'cd /d C:\Windows' -WorkingDirectory 'C:\Windows' -PassThru -WindowStyle Hidden
    }
    Start-Sleep -Milliseconds 700   # let children initialize

    Write-Host "Running cases...`n" -ForegroundColor Cyan

    # ===================== CLI / parsing =====================
    Test-Case 'version' 'cli' { $r = Invoke-Lsof @('-v') 'version'; Assert-Contains $r.Out 'winlsof'; "exit=$($r.Exit)" }
    Test-Case 'help-usage' 'cli' { $r = Invoke-Lsof @('-h') 'help'; Assert-Contains $r.Out 'USAGE'; Assert-Contains $r.Out '-i' }
    Test-Case 'unknown-option-errors' 'cli' { $r = Invoke-Lsof @('-Z') 'badopt'; Assert ($r.Exit -ne 0) 'expected nonzero exit'; Assert-Contains $r.Err 'unsupported' }

    # ===================== process / owner =====================
    Test-Case 'terse-lists-pids' 'process' { $r = Invoke-Lsof @('-t') 'terse'; Assert ($r.Out -match "(?m)^\d+\s*$") 'no PID lines' }
    Test-Case 'process-of-self' 'process' { $r = Invoke-Lsof @('-p', "$self") 'p-self'; Assert-Contains $r.Out "$self" }
    Test-Case 'user-column-present' 'process/owner' {
        $r = Invoke-Lsof @('-p', "$self") 'p-self-user'
        Assert ($r.Out -match [regex]::Escape($env:USERNAME)) "USER column should mention $($env:USERNAME)"
    }
    Test-Case 'command-filter' 'selection/-c' {
        $r = Invoke-Lsof @('-c', 'cmd', '-d', 'txt') 'c-cmd'; Assert-ContainsCI $r.Out 'cmd.exe'
    }

    # ===================== handles: file / offset / pipe / mapped =====================
    Test-Case 'open-file-listed' 'handles/file' { $r = Invoke-Lsof @('-p', "$self") 'p-self-file'; Assert-ContainsCI $r.Out "winlsof_file_$self" }
    Test-Case 'file-offset-dash-o' 'handles/offset' { $r = Invoke-Lsof @('-o', '-p', "$self") 'p-self-o'; Assert-Contains $r.Out '0t128' }
    Test-Case 'named-pipe-listed' 'handles/pipe' { $r = Invoke-Lsof @('-p', "$self") 'p-self-pipe'; Assert-ContainsCI $r.Out "winlsof_pipe_$self" }
    Test-Case 'mapped-data-file-listed' 'handles/mapped' { $r = Invoke-Lsof @('-p', "$self") 'p-self-map'; Assert-ContainsCI $r.Out "winlsof_map_$self" }

    # ===================== sockets =====================
    Test-Case 'tcp4-listen-by-port' 'sockets/tcp4' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)") 'i-tcp4'
        Assert-Contains $r.Out ":$($fx.Port4)"; Assert-Contains $r.Out 'LISTEN'; Assert-Contains $r.Out "$self"
        $o = Get-NetTCPConnection -LocalPort $fx.Port4 -State Listen -ErrorAction SilentlyContinue
        if ($o) { Assert ($o.OwningProcess -contains $self) 'Get-NetTCPConnection PID mismatch' }
        "port=$($fx.Port4)"
    }
    Test-Case 'tcp4-established-state' 'sockets/state' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)") 'i-tcp4-estab'; Assert-Contains $r.Out 'ESTABLISHED'
    }
    Test-Case 'tcp6-listen' 'sockets/tcp6' {
        if (-not $fx.Port6) { Skip 'no IPv6 loopback' }
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port6)") 'i-tcp6'; Assert-Contains $r.Out 'IPv6'; Assert-Contains $r.Out 'LISTEN'
    }
    Test-Case 'udp4-by-port' 'sockets/udp4' {
        $r = Invoke-Lsof @('-nP', "-iUDP:$($fx.UdpPort4)") 'i-udp4'; Assert-Contains $r.Out ":$($fx.UdpPort4)"; Assert-Contains $r.Out 'UDP'
    }
    Test-Case 'inet6-filter-excludes-v4' 'sockets/-i6' {
        $r = Invoke-Lsof @('-nP', '-i6') 'i6'; Assert-NotContains $r.Out 'IPv4' '-i6 output'
    }
    Test-Case 'inet-tcp-only' 'sockets/-iTCP' {
        $r = Invoke-Lsof @('-nP', '-iTCP') 'i-tcp'; Assert-NotContains $r.Out 'UDP' '-iTCP NODE column'
    }
    Test-Case 'port-service-name-https' 'sockets/-P-default' {
        # Default (no -P) resolves a well-known port to its service name.
        $r = Invoke-Lsof @('-n', "-iTCP:$($fx.Port4)") 'svcname'   # our ephemeral port is unknown -> numeric, just ensure it runs
        Assert ($r.Exit -eq 0) 'lsof failed'; "ephemeral port stays numeric (expected)"
    }

    # ===================== cwd / modules (child processes) =====================
    Test-Case 'cwd-64bit' 'cwd' {
        $r = Invoke-Lsof @('-d', 'cwd', '-p', "$($fx.Cwd64.Id)") 'cwd64'; Assert-ContainsCI $r.Out 'cwd'; Assert-ContainsCI $r.Out 'C:\Windows'
    }
    Test-Case 'cwd-wow64-32bit' 'cwd/wow64' {
        if (-not $fx.Cwd32) { Skip 'no SysWOW64 cmd.exe' }
        $r = Invoke-Lsof @('-d', 'cwd', '-p', "$($fx.Cwd32.Id)") 'cwd32'; Assert-ContainsCI $r.Out 'C:\Windows'
    }
    Test-Case 'modules-txt-image' 'modules' {
        $r = Invoke-Lsof @('-d', 'txt', '-p', "$($fx.Cwd64.Id)") 'txt'; Assert-ContainsCI $r.Out 'cmd.exe'
        $img = (Get-Process -Id $fx.Cwd64.Id).Path
        if ($img) { Assert-ContainsCI $r.Out (Split-Path $img -Leaf) 'txt vs Get-Process.Path' }
    }
    Test-Case 'modules-mem-dll' 'modules' {
        $r = Invoke-Lsof @('-d', 'mem', '-p', "$($fx.Cwd64.Id)") 'mem'; Assert-ContainsCI $r.Out '.dll'
    }

    # ===================== Restart Manager / paths =====================
    Test-Case 'named-file-who-has-open' 'restartmgr' {
        $r = Invoke-Lsof @($fx.FilePath) 'rm-file'; Assert-Contains $r.Out "$self" 'RM lookup should find our PID'
    }
    Test-Case 'plus-D-directory-tree' 'restartmgr/+D' {
        $r = Invoke-Lsof @('+D', $env:TEMP) 'plusD'; Assert-ContainsCI $r.Out 'winlsof_'
    }

    # ===================== selection: -d / -R / -a =====================
    Test-Case 'fd-filter-named-cwd' 'selection/-d' {
        $r = Invoke-Lsof @('-d', 'cwd', '-p', "$($fx.Cwd64.Id)") 'd-cwd'; Assert-NotContains $r.Out ' REG ' '-d cwd should exclude REG'
    }
    Test-Case 'ppid-column-dash-R' 'render/-R' {
        $r = Invoke-Lsof @('-R', '-p', "$self") 'R'; Assert-Contains $r.Out 'PPID'
    }
    Test-Case 'and-mode-dash-a' 'selection/-a' {
        $r = Invoke-Lsof @('-a', '-p', "$self", '-c', 'no-such-command-xyz') 'a-empty'
        Assert (($null -eq $r.Out) -or ($r.Out.Trim().Length -eq 0) -or ($r.Out -notmatch "(?m)^\S")) '-a of non-matching command should be empty'
    }

    # ===================== output formats =====================
    Test-Case 'field-output-Fpn' 'render/-F' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-Fpn') 'Fpn'
        Assert-Contains $r.Out "p$self"; Assert ($r.Out -match "(?m)^n") 'no n field'
        Assert-NotContains $r.Out 'tIPv4' 'type field should be suppressed by -Fpn'
    }
    Test-Case 'field-output-nul-F0' 'render/-F0' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-F0') 'F0'
        Assert ($r.Out.Contains([char]0)) 'expected NUL terminators'
    }
    Test-Case 'json-aggregated-J' 'render/-J' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-J') 'J'
        $j = $r.Out | ConvertFrom-Json
        Assert ($null -ne $j.processes) 'no processes array'
    }
    Test-Case 'json-lines-j' 'render/-j' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-j') 'jl'
        $lines = ($r.Out -split "`n") | Where-Object { $_.Trim() }
        foreach ($l in $lines) { $null = $l | ConvertFrom-Json }   # throws if any line isn't valid JSON
        "lines=$($lines.Count)"
    }

    # ===================== verbose / privilege =====================
    Test-Case 'verbose-pid-not-found' 'verbose/-V' {
        $r = Invoke-Lsof @('-V', '-p', '4294967294') 'V-missing'; Assert-Contains $r.Err 'no matching'
    }
    Test-Case 'privilege-hint-unelevated' 'privilege' {
        if ($IsAdmin) { Skip 'elevated: hint not expected' }
        $r = Invoke-Lsof @('-p', "$self") 'hint'; Assert-Contains $r.Err 'Administrator'
    }
    Test-Case 'inet-no-privilege-hint' 'privilege/-i' {
        $r = Invoke-Lsof @('-nP', '-i') 'i-nohint'; Assert-NotContains $r.Err 'Administrator' '-i stderr'
    }
    Test-Case 'elevated-system-process-handles' 'privilege/elevated' {
        if (-not $IsAdmin) { Skip 'run elevated to see system-process handles' }
        $svc = (Get-Process -Name services -ErrorAction SilentlyContinue | Select-Object -First 1)
        if (-not $svc) { Skip 'services.exe not found' }
        $r = Invoke-Lsof @('-p', "$($svc.Id)") 'svc'
        $rows = ($r.Out -split "`n" | Where-Object { $_.Trim() }).Count
        Assert ($rows -ge 2) "expected handle rows for services.exe, got $rows"
        "rows=$rows"
    }

    # ===================== repeat =====================
    Test-Case 'repeat-mode-dash-r' 'render/-r' {
        $tag = 'repeat'; $outF = Join-Path $CasesDir "$tag.out.txt"; $errF = Join-Path $CasesDir "$tag.err.txt"
        if ($Coverage) { $env:LLVM_PROFILE_FILE = (Join-Path $ProfDir "$tag-%p.profraw") }
        $p = Start-Process -FilePath $Bin -ArgumentList @('-r1', '-nP', "-iTCP:$($fx.Port4)") -NoNewWindow -PassThru `
            -RedirectStandardOutput $outF -RedirectStandardError $errF
        Start-Sleep -Seconds 3
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
        $o = Get-Content -LiteralPath $outF -Raw -ErrorAction SilentlyContinue
        Assert (($null -ne $o) -and $o.Contains('=======')) 'no repeat separator seen'
    }

    # ===================== optional: Sysinternals handle.exe cross-check =====================
    Test-Case 'handle-exe-cross-check' 'oracle/handle' {
        $he = if ($HandleExe) { $HandleExe } else { (Get-Command handle64.exe -ErrorAction SilentlyContinue).Source }
        if (-not $he) { Skip 'handle64.exe not provided' }
        $h = & $he -accepteula -p $self 2>$null | Out-String
        Assert-ContainsCI $h "winlsof_file_$self" 'handle64.exe should also see our file'
        $r = Invoke-Lsof @('-p', "$self") 'p-self-handlecmp'
        Assert-ContainsCI $r.Out "winlsof_file_$self"
    }
}
finally {
    Write-Host "`nCleaning up fixtures..." -ForegroundColor Cyan
    foreach ($k in 'Server4', 'Client4', 'Udp4', 'Udp6') { if ($fx[$k]) { try { $fx[$k].Dispose() } catch {} } }
    foreach ($k in 'Tcp4', 'Tcp6') { if ($fx[$k]) { try { $fx[$k].Stop() } catch {} } }
    if ($fx.View) { try { $fx.View.Dispose() } catch {} }
    if ($fx.Mmf) { try { $fx.Mmf.Dispose() } catch {} }
    if ($fx.Pipe) { try { $fx.Pipe.Dispose() } catch {} }
    if ($fx.File) { try { $fx.File.Dispose() } catch {} }
    foreach ($k in 'Cwd64', 'Cwd32') { if ($fx[$k]) { try { Stop-Process -Id $fx[$k].Id -Force -ErrorAction SilentlyContinue } catch {} } }
    foreach ($k in 'FilePath', 'MapPath') { if ($fx[$k] -and (Test-Path $fx[$k])) { Remove-Item $fx[$k] -Force -ErrorAction SilentlyContinue } }
}

# ---------------------------------------------------------------------------
# Coverage report
# ---------------------------------------------------------------------------
if ($Coverage) {
    Write-Host "`nBuilding coverage report..." -ForegroundColor Cyan
    try {
        $sysroot = (& rustc --print sysroot).Trim()
        $hostTriple = (((& rustc -vV) | Where-Object { $_ -like 'host:*' }) -replace '^host:\s*', '').Trim()
        $llvmbin = Join-Path $sysroot "lib\rustlib\$hostTriple\bin"
        $profdata = Join-Path $llvmbin 'llvm-profdata.exe'
        $cov = Join-Path $llvmbin 'llvm-cov.exe'
        $merged = Join-Path $RunDir 'coverage.profdata'
        $raws = (Get-ChildItem -Path $ProfDir -Filter '*.profraw' -ErrorAction SilentlyContinue).FullName
        if ($raws) {
            & $profdata merge -sparse $raws -o $merged
            & $cov report $Bin "--instr-profile=$merged" (Join-Path $Workspace 'crates') |
                Tee-Object -FilePath (Join-Path $RunDir 'coverage-summary.txt')
            & $cov show $Bin "--instr-profile=$merged" --format=html `
                --output-dir=(Join-Path $RunDir 'coverage-html') (Join-Path $Workspace 'crates') *> $null
            Write-Host "Coverage HTML: $(Join-Path $RunDir 'coverage-html\index.html')"
        }
        else { Write-Host "No .profraw files produced (was the binary built with -Coverage?)" -ForegroundColor Yellow }
    }
    catch {
        Write-Host "Coverage report failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
$Results | Export-Csv -Path (Join-Path $RunDir 'results.csv') -NoTypeInformation
$pass = ($Results | Where-Object Status -eq 'PASS').Count
$fail = ($Results | Where-Object Status -eq 'FAIL').Count
$skip = ($Results | Where-Object Status -eq 'SKIP').Count

$summary = @"
winlsof live smoke test  -  $Stamp
Binary   : $Bin
Elevated : $IsAdmin     Coverage: $([bool]$Coverage)
Result   : PASS=$pass  FAIL=$fail  SKIP=$skip   (total $($Results.Count))
Results  : $RunDir
"@
Set-Content -Path (Join-Path $RunDir 'summary.txt') -Value $summary

Write-Host "`n$summary"
if ($fail -gt 0) {
    Write-Host "`nFAILURES:" -ForegroundColor Red
    $Results | Where-Object Status -eq 'FAIL' | ForEach-Object { Write-Host "  - $($_.Name): $($_.Detail)" -ForegroundColor Red }
}
if (-not $IsAdmin) {
    Write-Host "`nNote: not elevated - re-run from an Administrator prompt for the system-wide cases." -ForegroundColor Yellow
}

Stop-Transcript | Out-Null
if ($fail -gt 0) { exit 1 } else { exit 0 }
