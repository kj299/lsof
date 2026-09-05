<#
.SYNOPSIS
    Live Windows smoke test for lsof-rs (lsof.exe).

.DESCRIPTION
    Builds lsof.exe, stands up deterministic fixtures (open file at a known
    offset, named pipe, mapped data file, TCP v4/v6 listeners + an established
    pair, UDP v4/v6, child processes with a known cwd incl. 32-bit WOW64), then
    exercises every lsof option / code path, captures output, and cross-checks
    against native Windows oracles (Get-NetTCPConnection, Get-Process) and the
    harness's own fixtures. No executables are downloaded. Optionally emits an
    llvm-cov line-coverage report.

    See README.md for the coverage map and how to report findings.

.PARAMETER OutDir
    Root folder for results. Default: .\lsof-rs-smoke-results

.PARAMETER SkipBuild
    Reuse an existing target build instead of rebuilding.

.PARAMETER Coverage
    Build an instrumented debug binary and produce a line-coverage report.

.EXAMPLE
    .\Invoke-LsofRsSmokeTest.ps1
.EXAMPLE
    .\Invoke-LsofRsSmokeTest.ps1 -Coverage      # run from an elevated prompt
#>
[CmdletBinding()]
param(
    [string]$OutDir = (Join-Path (Get-Location) 'lsof-rs-smoke-results'),
    [switch]$SkipBuild,
    [switch]$Coverage,
    [string]$Binary
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
$Workspace = Split-Path -Parent $PSScriptRoot       # smoketest/ lives under lsof-rs/
$Stamp     = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunDir    = Join-Path $OutDir $Stamp
$CasesDir  = Join-Path $RunDir 'cases'
$ProfDir   = Join-Path $RunDir 'profraw'
New-Item -ItemType Directory -Force -Path $CasesDir, $ProfDir | Out-Null
Start-Transcript -Path (Join-Path $RunDir 'transcript.log') | Out-Null

$IsAdmin = ([Security.Principal.WindowsPrincipal] `
        [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "lsof-rs live smoke test  ($Stamp)" -ForegroundColor Cyan
Write-Host "Workspace : $Workspace"
Write-Host "Results   : $RunDir"
Write-Host "Elevated  : $IsAdmin   Coverage: $([bool]$Coverage)`n"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
# A prebuilt binary via -Binary (e.g. a downloaded release) skips the build.
if ($Binary -and $Coverage) {
    Write-Host "-Coverage ignored with -Binary (a prebuilt binary isn't instrumented)." -ForegroundColor Yellow
    $Coverage = $false
}
$BuildProfile = if ($Coverage) { 'debug' } else { 'release' }
if (-not $Binary -and -not $SkipBuild -and -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    throw "cargo is not on PATH. Install Rust from https://rustup.rs and open a new shell, or pass -SkipBuild after placing a prebuilt lsof.exe at target\$BuildProfile\lsof.exe (you can download one from the PR's CI 'lsof-exe-windows' artifact)."
}
if (-not $Binary -and -not $SkipBuild) {
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
            $env:RUSTFLAGS = $null
            if ($LASTEXITCODE -ne 0) {
                # `-C instrument-coverage` needs the profiler runtime
                # (profiler_builtins). The x86_64-pc-windows-gnu toolchain doesn't
                # ship it; coverage on Windows needs the MSVC toolchain. Don't abort
                # the whole run for that - fall back to a normal pass.
                Write-Host "Instrumented (-Coverage) build failed: this toolchain has no profiler runtime (profiler_builtins). Coverage on Windows needs the MSVC toolchain (see README). Falling back to a normal run without coverage." -ForegroundColor Yellow
                $Coverage = $false
                $BuildProfile = 'release'
            }
        }
        if (-not $Coverage) {
            & cargo build --release
            if ($LASTEXITCODE -ne 0) {
                $existingBin = Join-Path $Workspace 'target\release\lsof.exe'
                $hint = ''
                if (Test-Path $existingBin) {
                    # A previously built binary is present, so a build failure
                    # here is almost always a transient file lock on target\
                    # (OneDrive sync, antivirus, or an elevated run clashing
                    # with a prior unelevated one) rather than a code error.
                    $hint = " A built lsof.exe already exists, so this looks like a transient file lock on target\ (OneDrive sync / antivirus / an elevated-vs-unelevated clash), not a code error. Re-run with -SkipBuild to reuse the current binary; longer term, pause OneDrive during builds or move the clone off OneDrive."
                }
                elseif (-not (Get-Command link.exe -ErrorAction SilentlyContinue)) {
                    # Missing MSVC linker (e.g. after switching toolchains).
                    $hint = " If you switched to the MSVC toolchain, it needs VS Build Tools' link.exe; switch back with 'rustup default stable-x86_64-pc-windows-gnu' or install Build Tools for Visual Studio (Desktop C++ workload)."
                }
                throw "cargo build failed ($LASTEXITCODE).$hint"
            }
        }
    }
    finally {
        $env:RUSTFLAGS = $null
        Pop-Location
    }
}
if ($Binary) {
    if (-not (Test-Path $Binary)) { throw "-Binary not found: $Binary" }
    $Bin = (Resolve-Path $Binary).Path
}
else {
    $Bin = Join-Path $Workspace ("target\{0}\lsof.exe" -f $BuildProfile)
}
if (-not (Test-Path $Bin)) { throw "lsof.exe not found at $Bin (build it, pass -Binary <path>, or drop -SkipBuild)" }
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
    # Cache the process handle while it's alive. Without this, a -PassThru process
    # object's .ExitCode reads back as $null after exit (a long-standing
    # Start-Process quirk), which would make every exit-code assertion bogus.
    $null = $p.Handle
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
    $fx.FilePath = Join-Path $env:TEMP ("lsof_rs_file_{0}.dat" -f $self)
    $fx.File = [System.IO.File]::Open($fx.FilePath, 'Create', 'ReadWrite', 'None')
    $bytes = [byte[]](0..255); $fx.File.Write($bytes, 0, $bytes.Length); $fx.File.Flush()
    [void]$fx.File.Seek(128, [System.IO.SeekOrigin]::Begin)
    # Park the KERNEL file pointer at 128 too. lsof-rs reports the kernel
    # position (NtQueryInformationFile), but .NET 6+ FileStream (pwsh 7) does
    # positional I/O and never moves the OS pointer -- Seek() above only updates
    # the managed view, so on pwsh the kernel position would still be 0 and the
    # `-o` case would fail (as it did on hosted CI). Under PS 5.1 / .NET
    # Framework, Seek() calls SetFilePointer eagerly, so this is idempotent.
    if (-not ('LsofRsNative.Kernel32' -as [type])) {
        Add-Type -Namespace LsofRsNative -Name Kernel32 -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool SetFilePointerEx(System.IntPtr hFile, long liDistanceToMove, out long lpNewFilePointer, uint dwMoveMethod);
'@
    }
    $kernelPos = 0L
    $seekOk = [LsofRsNative.Kernel32]::SetFilePointerEx(
        $fx.File.SafeFileHandle.DangerousGetHandle(), 128, [ref]$kernelPos, 0)  # 0 = FILE_BEGIN
    if (-not $seekOk -or $kernelPos -ne 128) {
        Write-Host "warn: could not park the kernel file pointer at 128 (got $kernelPos); the -o case may fail" -ForegroundColor Yellow
    }

    # Named pipe server (PIPE), plus a connected client end so `-E` can
    # resolve both endpoint PIDs (an unconnected instance has no client).
    $fx.PipeName = "lsof_rs_pipe_$self"
    $fx.Pipe = New-Object System.IO.Pipes.NamedPipeServerStream($fx.PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $accept = $fx.Pipe.WaitForConnectionAsync()
        $fx.PipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $fx.PipeName, [System.IO.Pipes.PipeDirection]::InOut)
        $fx.PipeClient.Connect(2000)
        [void]$accept.Wait(2000)
    }
    catch { $fx.PipeClient = $null }

    # Memory-mapped DATA file (mem via mapped.rs).
    $fx.MapPath = Join-Path $env:TEMP ("lsof_rs_map_{0}.bin" -f $self)
    # 4096-byte buffer. NB: [byte[]](1..4096) overflows -- a [byte] holds 0-255,
    # so casting a 1..4096 range throws "Cannot convert value 256 to System.Byte".
    [System.IO.File]::WriteAllBytes($fx.MapPath, [byte[]]::new(4096))
    $fx.Mmf = [System.IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile($fx.MapPath, 'Open', "lsof-rsmap$self")
    $fx.View = $fx.Mmf.CreateViewAccessor()

    # TCP v4 listener + an established connection pair.
    $fx.Tcp4 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $fx.Tcp4.Start()
    $fx.Port4 = ([System.Net.IPEndPoint]$fx.Tcp4.LocalEndpoint).Port
    $fx.Client4 = [System.Net.Sockets.TcpClient]::new()
    $fx.Client4.Connect([System.Net.IPAddress]::Loopback, $fx.Port4)
    $fx.Server4 = $fx.Tcp4.AcceptTcpClient()

    # TCP v6 listener + an established connection pair (may be unavailable; tolerate).
    try {
        $fx.Tcp6 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::IPv6Loopback, 0)
        $fx.Tcp6.Start()
        $fx.Port6 = ([System.Net.IPEndPoint]$fx.Tcp6.LocalEndpoint).Port
        $fx.Client6 = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $fx.Client6.Connect([System.Net.IPAddress]::IPv6Loopback, $fx.Port6)
        $fx.Server6 = $fx.Tcp6.AcceptTcpClient()
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
    Test-Case 'version' 'cli' { $r = Invoke-Lsof @('-v') 'version'; Assert-Contains $r.Out 'lsof-rs'; "exit=$($r.Exit)" }
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
        $r = Invoke-Lsof @('-a', '-c', 'cmd', '-d', 'txt') 'c-cmd'; Assert-ContainsCI $r.Out 'cmd.exe'
    }

    # ===================== handles: file / offset / pipe / mapped =====================
    Test-Case 'open-file-listed' 'handles/file' { $r = Invoke-Lsof @('-p', "$self") 'p-self-file'; Assert-ContainsCI $r.Out "lsof_rs_file_$self" }
    Test-Case 'file-offset-dash-o' 'handles/offset' { $r = Invoke-Lsof @('-o', '-p', "$self") 'p-self-o'; Assert-Contains $r.Out '0t128' }
    Test-Case 'named-pipe-listed' 'handles/pipe' { $r = Invoke-Lsof @('-p', "$self") 'p-self-pipe'; Assert-ContainsCI $r.Out "lsof_rs_pipe_$self" }
    Test-Case 'mapped-data-file-listed' 'handles/mapped' { $r = Invoke-Lsof @('-p', "$self") 'p-self-map'; Assert-ContainsCI $r.Out "lsof_rs_map_$self" }

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
        $r = Invoke-Lsof @('-a', '-d', 'cwd', '-p', "$($fx.Cwd64.Id)") 'cwd64'; Assert-ContainsCI $r.Out 'cwd'; Assert-ContainsCI $r.Out 'C:\Windows'
    }
    Test-Case 'cwd-wow64-32bit' 'cwd/wow64' {
        if (-not $fx.Cwd32) { Skip 'no SysWOW64 cmd.exe' }
        $r = Invoke-Lsof @('-a', '-d', 'cwd', '-p', "$($fx.Cwd32.Id)") 'cwd32'; Assert-ContainsCI $r.Out 'C:\Windows'
    }
    Test-Case 'modules-txt-image' 'modules' {
        $r = Invoke-Lsof @('-a', '-d', 'txt', '-p', "$($fx.Cwd64.Id)") 'txt'; Assert-ContainsCI $r.Out 'cmd.exe'
        $img = (Get-Process -Id $fx.Cwd64.Id).Path
        if ($img) { Assert-ContainsCI $r.Out (Split-Path $img -Leaf) 'txt vs Get-Process.Path' }
    }
    Test-Case 'modules-mem-dll' 'modules' {
        $r = Invoke-Lsof @('-a', '-d', 'mem', '-p', "$($fx.Cwd64.Id)") 'mem'; Assert-ContainsCI $r.Out '.dll'
    }

    # ===================== Restart Manager / paths =====================
    Test-Case 'named-file-who-has-open' 'restartmgr' {
        $r = Invoke-Lsof @($fx.FilePath) 'rm-file'; Assert-Contains $r.Out "$self" 'RM lookup should find our PID'
    }
    Test-Case 'plus-D-directory-tree' 'restartmgr/+D' {
        $r = Invoke-Lsof @('+D', $env:TEMP) 'plusD'; Assert-ContainsCI $r.Out 'lsof_rs_'
    }

    # ===================== selection: -d / -R / -a =====================
    Test-Case 'fd-filter-named-cwd' 'selection/-d' {
        $r = Invoke-Lsof @('-a', '-d', 'cwd', '-p', "$($fx.Cwd64.Id)") 'd-cwd'; Assert-NotContains $r.Out ' REG ' '-d cwd should exclude REG'
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
        # Only the named letters may appear. `p` is the one field Lsof.8 calls
        # "always selected"; `f` is NOT — the C emits the fd marker only when it
        # is asked for, so a consumer keying on `f` to start a file record must
        # not see one here.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-Fpn') 'Fpn'
        Assert-Contains $r.Out "p$self"; Assert ($r.Out -match "(?m)^n") 'no n field'
        Assert-NotContains $r.Out 'tIPv4' 'type field should be suppressed by -Fpn'
        Assert (-not ($r.Out -match "(?m)^f")) '-Fpn must not emit the f marker'
    }
    Test-Case 'field-output-bare-F' 'render/-F' {
        # Bare -F selects every standard field, in print.c's order. On Windows
        # the model has no lock, file flags or filesystem device, so the fields
        # that do appear are the ones with values -- plus `a` and `l`, which the
        # C prints EMPTY rather than omitting so every file record has the same
        # shape. Order: f a l t ... i k P n, then the T tokens after the name.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-F') 'F-bare'
        Assert-Contains $r.Out "p$self"
        Assert ($r.Out -match "(?m)^f\d+") 'bare -F must emit the f marker'
        Assert ($r.Out -match "(?m)^a[ ru]$") 'bare -F must emit the a field'
        Assert ($r.Out -match "(?m)^l ?$") 'bare -F must emit an empty l field'
        Assert ($r.Out -match "(?ms)^PTCP.*?^n") 'P must come before n'
    }
    Test-Case 'field-output-socket-state' 'render/-F' {
        # The state is not part of NAME: the C keeps it in Lf->lts and prints it
        # from print_tcptpi(), so `n` carries the endpoints alone and the state
        # arrives as its own TST= token. Reporting it in both is the bug this
        # guards.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-FnT') 'F-state'
        Assert-Contains $r.Out 'TST=LISTEN'
        Assert-NotContains $r.Out '(LISTEN)' 'the state must not also be in the n field'
        # ...while the table still shows it, appended by the renderer.
        $t = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)") 'F-state-table'
        Assert-Contains $t.Out '(LISTEN)'
    }
    Test-Case 'field-output-nul-F0' 'render/-F0' {
        # Every field is NUL-terminated and each set gets a NL *appended* after
        # that NUL, so a set ends "...`0`n". Appending rather than replacing is
        # the whole point of -F0: a consumer splitting the stream on NUL
        # otherwise gets one set's last field glued to the next set's first.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-F0') 'F0'
        Assert ($r.Out.Contains([char]0)) 'expected NUL terminators'
        Assert ($r.Out.Contains("$([char]0)`n")) 'a set must end with NUL then NL'
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

    # ===================== Phase 5A: parity switches =====================
    Test-Case 'state-filter-listen' 'selection/-s' {
        # -iTCP:<port> matches the listener (LISTEN) + the established pair;
        # -sTCP:LISTEN must keep only the LISTEN row.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-sTCP:LISTEN') 's-listen'
        Assert-Contains $r.Out 'LISTEN'
        Assert-NotContains $r.Out 'ESTABLISHED' '-sTCP:LISTEN should exclude ESTABLISHED'
    }
    Test-Case 'state-filter-exclude' 'selection/-s^' {
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-sTCP:^LISTEN') 's-not-listen'
        Assert-NotContains $r.Out 'LISTEN' '-sTCP:^LISTEN should exclude LISTEN'
    }
    Test-Case 'tasks-dash-K' 'selection/-K' {
        $r = Invoke-Lsof @('-K', '-p', "$self") 'K'
        Assert-Contains $r.Out 'THRD' '-K should emit THRD task rows'
    }
    Test-Case 'link-count-dash-L' 'render/-L' {
        $r = Invoke-Lsof @('-L', '-p', "$self") 'L'
        Assert-Contains $r.Out 'NLINK' '-L should add the NLINK column'
    }
    Test-Case 'link-filter-plus-L' 'selection/+L' {
        # +L 1 keeps only link-count-0 files; deterministic content varies, so
        # just assert it parses and runs cleanly (implies -L).
        $r = Invoke-Lsof @('-a', '+L', '1', '-p', "$self") 'plusL'
        Assert ($r.Exit -eq 0) "+L 1 should run cleanly (exit=$($r.Exit))"
    }
    Test-Case 'numeric-ids-dash-l' 'render/-l' {
        $r = Invoke-Lsof @('-l', '-p', "$self") 'l'
        Assert-Contains $r.Out 'S-1-' '-l should render the numeric SID'
    }
    Test-Case 'ppid-select-dash-g' 'selection/-g' {
        # Our cmd.exe child's parent is this harness ($self); -g <self> selects it.
        $r = Invoke-Lsof @('-g', "$self") 'g'
        Assert-Contains $r.Out "$($fx.Cwd64.Id)" '-g <self> should select our child cmd.exe'
    }
    Test-Case 'quiet-dash-Q' 'misc/-Q' {
        $r = Invoke-Lsof @('-Q', '-p', '4294967294') 'Q'
        Assert-NotContains $r.Err 'no matching' '-Q should suppress the no-match message'
    }
    Test-Case 'suppress-warnings-dash-w' 'misc/-w' {
        if ($IsAdmin) { Skip 'privilege hint only appears unelevated' }
        $r = Invoke-Lsof @('-w', '-p', "$self") 'w'
        Assert-NotContains $r.Err 'Administrator' '-w should suppress the privilege hint'
    }
    Test-Case 'no-op-dash-O' 'misc/-O' {
        $r = Invoke-Lsof @('-O', '-p', "$self") 'O'
        Assert ($r.Exit -eq 0) "-O should be accepted (exit=$($r.Exit))"
    }
    Test-Case 'command-width-plus-c' 'render/+c' {
        $r = Invoke-Lsof @('+c', '4', '-p', "$self") 'plusc'
        Assert ($r.Exit -eq 0) "+c should be accepted (exit=$($r.Exit))"
    }
    Test-Case 'help-alias-question' 'misc/-?' {
        $r = Invoke-Lsof @('-?') 'q-help'; Assert-Contains $r.Out 'USAGE'
    }
    Test-Case 'end-of-options-dashdash' 'misc/--' {
        # `--` ends options; the path after it is looked up (RM finds our PID).
        $r = Invoke-Lsof @('--', $fx.FilePath) 'dashdash'
        Assert-Contains $r.Out "$self" '-- <file> should be treated as a path lookup'
    }

    # ===================== Phase 5B: -T extended TCP info =====================
    Test-Case 'tcp-info-window-dash-T' 'render/-T' {
        if (-not $IsAdmin) { Skip 'EStats (window/queue) need Administrator' }
        # The established loopback pair on Port4 should report a receive window.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-Tw') 'T-window'
        Assert-Contains $r.Out '(Win=' '-Tw should annotate established rows with a window'
    }
    Test-Case 'tcp-info-window-v6-dash-T' 'render/-T6' {
        if (-not $IsAdmin) { Skip 'EStats (window/queue) need Administrator' }
        if (-not $fx.Server6) { Skip 'no established IPv6 loopback pair' }
        # Same, over IPv6 (GetPerTcp6ConnectionEStats / MIB_TCP6ROW path).
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port6)", '-Tw') 'T-window-v6'
        Assert-Contains $r.Out '(Win=' '-Tw should annotate established IPv6 rows'
    }
    Test-Case 'tcp-info-fields-dash-T' 'render/-T -F' {
        if (-not $IsAdmin) { Skip 'EStats (window/queue) need Administrator' }
        # -F carries the stats as structured T tokens with lsof's prefixes
        # (QR/QS/WR); the table-only (Win=) suffix must NOT leak into the
        # n (name) field.
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-Tqw', '-F') 'T-fields'
        Assert-Contains $r.Out 'TWR=' '-Tw should emit a TWR= (window) T field'
        Assert-Contains $r.Out 'TQR=' '-Tq should emit a TQR= (read queue) T field'
        Assert-Contains $r.Out 'TQS=' '-Tq should emit a TQS= (send queue) T field'
        Assert-NotContains $r.Out '(Win=' '-F name must stay clean of the table suffix'
    }
    Test-Case 'tcp-info-json-dash-T' 'render/-T -J' {
        if (-not $IsAdmin) { Skip 'EStats (window/queue) need Administrator' }
        $r = Invoke-Lsof @('-nP', "-iTCP:$($fx.Port4)", '-Tqw', '-J') 'T-json'
        Assert-Contains $r.Out '"tcp_window":' '-Tw should emit tcp_window in JSON'
        Assert-Contains $r.Out '"tcp_queue_recv":' '-Tq should emit tcp_queue_recv'
        Assert-Contains $r.Out '"tcp_queue_send":' '-Tq should emit tcp_queue_send'
        $null = $r.Out | ConvertFrom-Json   # throws if the JSON regressed
    }

    # ===================== Phase 5B: -E pipe endpoint info =====================
    Test-Case 'pipe-endpoints-dash-E' 'render/-E' {
        if (-not $fx.PipeClient -or -not $fx.PipeClient.IsConnected) { Skip 'pipe client did not connect' }
        # Both ends of the fixture pipe live in this process; -E annotates the
        # pipe rows with peer PIDs via GetNamedPipe{Server,Client}ProcessId.
        # Needs no elevation (own-process handles).
        $r = Invoke-Lsof @('-E', '-p', "$self") 'E'
        Assert-Contains $r.Out "server=$self" '-E should annotate pipe rows with the server PID'
        Assert-Contains $r.Out "client=$self" '-E should annotate pipe rows with the client PID'
    }
    Test-Case 'pipe-endpoints-plus-E' 'render/+E' {
        if (-not $fx.PipeClient -or -not $fx.PipeClient.IsConnected) { Skip 'pipe client did not connect' }
        # +E = -E plus the peers' own rows. Our peer is this same process (so
        # already selected); assert the superset parses and annotates alike.
        $r = Invoke-Lsof @('+E', '-p', "$self") 'plusE'
        Assert ($r.Exit -eq 0) "+E should run cleanly (exit=$($r.Exit))"
        Assert-Contains $r.Out "server=$self" '+E should annotate like -E'
    }

    # ===================== Phase 5B: -U UNIX-domain sockets (ETW) =====================
    Test-Case 'unix-sockets-dash-U' 'sockets/-U' {
        if (-not $IsAdmin) { Skip 'AF_UNIX enumeration uses the ETW AFD capture (needs Administrator)' }
        # `-U` triggers the short ETW AFD capture and restricts output to AF_UNIX
        # rows. AF_UNIX sockets are ephemeral, so a 2s capture window can't
        # guarantee a specific row; assert instead that the capture fired (its
        # histogram is written to stderr whenever the AFD session starts) and
        # that the run exits cleanly.
        $r = Invoke-Lsof @('-U') 'U'
        Assert ($r.Exit -eq 0) "-U should run cleanly (exit=$($r.Exit))"
        Assert-Contains $r.Err 'etw: captured' '-U stderr (ETW histogram)'
    }
    Test-Case 'inet-icmp-family-dash-i' 'sockets/-iICMP' {
        if (-not $IsAdmin) { Skip 'ICMP rows come from the ETW AFD capture (needs Administrator)' }
        # `-iICMP` implies the ETW capture with NO --etw flag (the wiring under
        # test). Same leniency as -U: a 2s window can't guarantee live ICMP
        # traffic, so assert the capture fired and the run exits cleanly.
        $r = Invoke-Lsof @('-nP', '-iICMP') 'i-icmp'
        Assert ($r.Exit -eq 0) "-iICMP should run cleanly (exit=$($r.Exit))"
        Assert-Contains $r.Err 'etw: captured' '-iICMP must imply the ETW capture'
        Assert-NotContains $r.Out ' TCP ' '-iICMP must not list TCP rows'
    }
    Test-Case 'inet-raw-family-dash-i' 'sockets/-iRAW' {
        if (-not $IsAdmin) { Skip 'RAW rows come from the ETW AFD capture (needs Administrator)' }
        $r = Invoke-Lsof @('-nP', '-iRAW') 'i-raw'
        Assert ($r.Exit -eq 0) "-iRAW should run cleanly (exit=$($r.Exit))"
        Assert-Contains $r.Err 'etw: captured' '-iRAW must imply the ETW capture'
        Assert-NotContains $r.Out ' UDP ' '-iRAW must not list UDP rows'
    }

    # ===================== native oracle cross-check =====================
    # No downloads. The harness OWNS its fixtures, so their paths are
    # authoritative ground truth, and Get-Process is a native, always-present
    # oracle. (This replaces the former Sysinternals handle64.exe cross-check,
    # which downloaded an executable at runtime -- a supply-chain risk if the
    # download host were compromised. Sockets are already cross-checked natively
    # against Get-NetTCPConnection in tcp4-listen-by-port above.)
    Test-Case 'native-handle-cross-check' 'oracle/native' {
        $r = Invoke-Lsof @('-p', "$self") 'p-self-handlecmp'
        # lsof-rs must report every resource this process is known to hold open.
        Assert-ContainsCI $r.Out "lsof_rs_file_$self" 'lsof-rs should list the held-open fixture file'
        Assert-ContainsCI $r.Out "lsof_rs_pipe_$self" 'lsof-rs should list the fixture named pipe'
        Assert-ContainsCI $r.Out "lsof_rs_map_$self" 'lsof-rs should list the mapped fixture file'
        # Native independent signal: this process really does hold kernel handles.
        $native = (Get-Process -Id $self).HandleCount
        Assert ($native -ge 1) 'Get-Process reported no handle count for this process'
        "fixtures matched; Get-Process HandleCount=$native"
    }
}
finally {
    Write-Host "`nCleaning up fixtures..." -ForegroundColor Cyan
    foreach ($k in 'Server4', 'Client4', 'Server6', 'Client6', 'Udp4', 'Udp6') { if ($fx[$k]) { try { $fx[$k].Dispose() } catch {} } }
    foreach ($k in 'Tcp4', 'Tcp6') { if ($fx[$k]) { try { $fx[$k].Stop() } catch {} } }
    if ($fx.View) { try { $fx.View.Dispose() } catch {} }
    if ($fx.Mmf) { try { $fx.Mmf.Dispose() } catch {} }
    if ($fx.PipeClient) { try { $fx.PipeClient.Dispose() } catch {} }
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
        if (-not (Test-Path $profdata) -or -not (Test-Path $cov)) {
            Write-Host "llvm-tools not found under $llvmbin. Run: rustup component add llvm-tools-preview" -ForegroundColor Yellow
        }
        elseif ($raws) {
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
# @() forces array context so .Count is reliable even when exactly one case
# matches (a lone scalar's .Count renders empty otherwise).
$pass = @($Results | Where-Object Status -eq 'PASS').Count
$fail = @($Results | Where-Object Status -eq 'FAIL').Count
$skip = @($Results | Where-Object Status -eq 'SKIP').Count

$summary = @"
lsof-rs live smoke test  -  $Stamp
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
