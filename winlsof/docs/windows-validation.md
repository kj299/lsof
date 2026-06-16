# winlsof — live Windows validation plan

This plan validates the `winlsof` (`lsof.exe`) build end-to-end on a real
Windows 10/11 x64 host, cross-checking every feature against a native Windows
"oracle" (`Get-Process`, `Get-NetTCPConnection`, `netstat`, Sysinternals
`handle.exe`, etc.). CI already proves the code compiles, lints, and that the
pure helper logic unit-tests pass on `windows-latest`; this plan covers the part
CI cannot: a live system-wide run.

Example outputs below are **representative** (real PIDs/paths will differ). A
case passes if the shape matches and the cross-check agrees.

## 0. Build & setup

```powershell
# from the repo root
cd winlsof
cargo build --release
$lsof = ".\target\release\lsof.exe"

# optional oracle (Sysinternals) — handy for handle cross-checks
#   https://learn.microsoft.com/sysinternals/downloads/handle
#   put handle64.exe on PATH
```

Run the **unprivileged** cases in a normal PowerShell, and the **elevated**
cases (§8) in a PowerShell started with "Run as administrator".

---

## 1. Smoke: version / help

| # | Command | Expected |
|---|---|---|
| T1 | `& $lsof -v` | `winlsof 0.1.0 (memory-safe lsof for Windows)` |
| T2 | `& $lsof -h` | usage text listing `-p -u -c -i -a -n -P -t -F -J -j -r` and `+D` |

---

## 2. Processes, command, user (Phase 1)

```powershell
# T3 — terse PID list vs Get-Process
(& $lsof -t 2>$null | Measure-Object).Count
(Get-Process | Select-Object -Expand Id | Sort-Object -Unique).Count   # should be in the same ballpark

# T4 — a known process; txt row must equal its image path
$p = Get-Process explorer | Select-Object -First 1
& $lsof -p $p.Id 2>$null | Select-String 'txt|cwd' | Select-Object -First 3
(Get-Process -Id $p.Id).Path        # cross-check the txt path

# T5 — select by command name
& $lsof -c explorer 2>$null | Select-Object -First 3
```

Representative T4 output:

```
COMMAND       PID USER             FD   TYPE DEVICE SIZE/OFF   NODE NAME
explorer.exe 7324 DOMAIN\alice     cwd  DIR  C:                     C:\Users\alice
explorer.exe 7324 DOMAIN\alice     txt  REG  C:      4441600        C:\Windows\explorer.exe
explorer.exe 7324 DOMAIN\alice     mem  REG  C:      2059664        C:\Windows\System32\ntdll.dll
```

**Pass:** the `txt` NAME equals `(Get-Process -Id <PID>).Path`; `USER` shows
`DOMAIN\user`; `-c explorer` only returns rows whose COMMAND starts with
`explorer`.

---

## 3. Network — TCP/UDP, v4/v6 (Phase 2)  ← strongest oracle match

```powershell
# Start a known listener on port 8765 in its own window, note its PID:
$srv = Start-Process python -ArgumentList '-m','http.server','8765' -PassThru

# T6 — find it by port
& $lsof -nP -iTCP:8765
# cross-check:
Get-NetTCPConnection -LocalPort 8765 | Select-Object OwningProcess,State,LocalAddress
netstat -ano | Select-String ':8765'

# T7 — all TCP, owning PID present
& $lsof -nP -iTCP 2>$null | Select-Object -First 5

# T8 — UDP
& $lsof -nP -iUDP 2>$null | Select-Object -First 5
Get-NetUDPEndpoint | Select-Object -First 5 LocalAddress,LocalPort,OwningProcess

# T9 — IPv6 only
& $lsof -nP -i6 2>$null | Select-Object -First 5

# T10 — machine formats on a socket
& $lsof -nP -iTCP:8765 -F
& $lsof -nP -iTCP:8765 -J | ConvertFrom-Json | Select-Object -Expand processes

Stop-Process $srv.Id
```

Representative T6 output:

```
COMMAND   PID USER          FD  TYPE DEVICE SIZE/OFF NODE NAME
python   9012 DOMAIN\alice  unk IPv4              TCP  *:8765 (LISTEN)
```

**Pass:** the PID winlsof reports for port 8765 equals
`(Get-NetTCPConnection -LocalPort 8765).OwningProcess` and the `netstat -ano`
PID; `STATE` matches (`LISTEN`/`ESTABLISHED`/…); `-i6` returns only `IPv6`
rows; `-J` parses as JSON with `protocol":"TCP"` and `"state":"LISTEN"`. (The FD
shows `unk` — the socket handle value isn't in the MIB table; this is expected.)

---

## 4. Open file handles (Phase 3)

```powershell
# Hold a file open in THIS PowerShell process:
$path = "$env:TEMP\winlsof_test.txt"; "hi" | Set-Content $path
$f = [System.IO.File]::Open($path,'Open','Read','None')

# T11 — list this process's open files; the test file should appear
& $lsof -p $PID 2>$null | Select-String 'winlsof_test'

# cross-check with Sysinternals handle (optional):
handle64.exe -p $PID winlsof_test
$f.Close(); Remove-Item $path
```

Representative T11 output:

```
powershell 4180 DOMAIN\alice  784r REG C: 3 196610 C:\Users\alice\AppData\Local\Temp\winlsof_test.txt
```

**Pass:** the file path appears under the correct PID with access `r`, a numeric
FD (the handle value), and a NODE (file index); `handle64.exe` lists the same
file for that PID.

---

## 5. Named-file lookup via Restart Manager (Phase 4) — no elevation

```powershell
$path = "$env:TEMP\winlsof_test.txt"; "hi" | Set-Content $path
$f = [System.IO.File]::Open($path,'Open','Read','None')

# T12 — "who has this open?" (works WITHOUT Administrator)
& $lsof $path
# T13 — directory form
& $lsof +D $env:TEMP 2>$null | Select-String 'winlsof_test'

# cross-check:
handle64.exe $path
$f.Close(); Remove-Item $path
```

Representative T12 output:

```
COMMAND     PID USER         FD  TYPE DEVICE SIZE/OFF NODE NAME
powershell 4180 DOMAIN\alice unk REG  C:                    C:\Users\alice\AppData\Local\Temp\winlsof_test.txt
```

**Pass:** the holding process (powershell) is listed even in a *non-elevated*
shell; the PID matches `handle64.exe`'s output.

---

## 6. Working directory `cwd` (Phase 4, best-effort)

```powershell
# T14 — start a process with a known cwd
$p = Start-Process cmd -ArgumentList '/k','cd /d C:\Windows' -PassThru
Start-Sleep 1
& $lsof -p $p.Id 2>$null | Select-String 'cwd'
Stop-Process $p.Id
```

Representative output: `cmd.exe 1234 DOMAIN\alice cwd DIR C: C:\Windows`

**Pass:** the `cwd` row shows `C:\Windows`. (If absent, see Known limitations —
64-bit offsets / access.)

---

## 7. Mapped modules `txt`/`mem` (Phase 4)

```powershell
# T15 — mem rows should be a subset of the process's loaded modules
$p = Get-Process explorer | Select-Object -First 1
$mem = (& $lsof -p $p.Id 2>$null | Select-String '\bmem\b' | ForEach-Object {($_ -split '\s+')[-1]})
$mods = (Get-Process -Id $p.Id).Modules.FileName
($mem | Where-Object { $_ -notin $mods }).Count    # expect 0 (all winlsof mem entries are real modules)
```

**Pass:** the `txt` entry equals the image path and every `mem` NAME is one of
`(Get-Process -Id <PID>).Modules.FileName`.

---

## 8. Least privilege (the explicit requirement)

```powershell
# T16 (unprivileged) — the hint goes to STDERR, output is your accessible view
& $lsof 1>$null          # stderr should show:
#   lsof: showing your accessible processes; re-run as Administrator for a system-wide view

# T17 (unprivileged) — `-i` needs NO elevation and prints NO hint
& $lsof -nP -i 2>&1 1>$null     # expect: (no output on stderr)
(& $lsof -nP -iTCP 2>$null | Measure-Object).Count   # full socket list still present
```

Then open an **elevated** PowerShell ("Run as administrator"):

```powershell
$lsof = ".\target\release\lsof.exe"
# T18 — system process handles are now visible (more rows than unprivileged)
& $lsof -p (Get-Process services | Select-Object -Expand Id) 2>$null | Measure-Object
#   compare this count to the same command run unprivileged (should be >= , typically >)

# T19 — even elevated, `-i` is network-only (no handle enumeration / no SeDebugPrivilege)
& $lsof -nP -iTCP 2>$null | Select-Object -First 3
#   (deep check, optional) run under Sysinternals Process Monitor and confirm the
#   lsof.exe run for `-i` does NOT enable SeDebugPrivilege, while a plain `& $lsof`
#   run does (just-in-time, then drops it).
```

**Pass:** unprivileged plain run prints the Administrator hint on stderr and only
fully details your own processes; `-i` prints no hint and returns the complete
socket table without elevation; elevated run reveals system processes' handles;
`-i` performs no handle enumeration in either case.

---

## 9. Repeat mode (Phase 4)

```powershell
# T20 — refresh every 2s with lsof's separator; Ctrl-C to stop
& $lsof -r2 -nP -iTCP:8765
```

**Pass:** output repeats every ~2s with a `=======` line between cycles and
stops on Ctrl-C.

---

## Pass/fail summary

| Case | Feature | Oracle | Pass criterion |
|---|---|---|---|
| T1–T2 | version/help | — | strings present |
| T3–T5 | processes/command/user | `Get-Process` | PID set & image path match |
| T6–T10 | TCP/UDP v4/v6, `-i`, `-F`/`-J` | `Get-NetTCPConnection`, `netstat`, `Get-NetUDPEndpoint` | owning PID + state match |
| T11 | file handles | `handle64.exe` | path under right PID, access `r` |
| T12–T13 | named-file / `+D` (RM) | `handle64.exe` | holder PID match, no admin needed |
| T14 | `cwd` | known launch dir | path matches |
| T15 | `txt`/`mem` | `(Get-Process).Modules` | subset/equality |
| T16–T19 | least privilege | run elevated vs not, ProcMon | hint + visibility + no SeDebug for `-i` |
| T20 | repeat | — | cyclic refresh + separator |

## Known limitations to expect (not failures)

- **Socket FD shows `unk`** — the socket handle value isn't in the IP Helper
  table; correlating it would require matching against the handle table.
- **Some details need elevation** — unprivileged runs can't read other users' /
  protected processes' handles (by design; matches lsof needing root).
- **`cwd` is 64-bit, best-effort** — it uses documented x64 PEB offsets and
  `PROCESS_VM_READ`; 32-bit (WOW64) targets or denied reads yield no `cwd` row.
- **Hang-prone handles** — names for `0x0012019F` handles are resolved on a
  worker thread with a 100 ms timeout, so a rare one may show no name.
- **No `rtd`** — Windows has no per-process root directory.
