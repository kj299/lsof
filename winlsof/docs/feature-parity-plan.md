# winlsof — full lsof option-parity plan (Phase 5)

The original [project plan](../../...) was explicit about being a **Core MVP
first** rewrite: implement the canonical lsof options that map onto Windows
data, validate end-to-end on real hardware, ship. That milestone landed as
[v0.1.0](https://github.com/kj299/lsof/releases/tag/winlsof-v0.1.0). But a
*full* port of upstream lsof needs the rest of the option surface — the user
correctly pointed out that switches like `-s`, `-K`, `-L`, `-l`, `-g`, `-T`
were never planned past the MVP. This doc reconstitutes the missing
requirements and lays out **Phase 5** to close the gap.

## Source of truth

Upstream lsof's authoritative SYNOPSIS (from `../docs/manpage.md`):

```
lsof [ -?abChHlnNOPQRtUvVX ] [ -A A ] [ -c c ] [ +c c ] [ +|-d d ]
     [ +|-D D ] [ +|-e s ] [ +|-E ] [ +|-f [cfgGn] ] [ -F [f] ]
     [ -g [s] ] [ -i [i] ] [ -k k ] [ -K k ] [ +|-L [l] ] [ +|-m m ]
     [ +|-M ] [ -o [o] ] [ -p s ] [ +|-r [t[m<fmt>]] ] [ -s [p:s] ]
     [ -S [t] ] [ -T [t] ] [ -u s ] [ +|-w ] [ -x [fl] ] [ -z [z] ]
     [ -Z [Z] ] [ -- ] [names]
```

47 distinct options in total. Per `docs/options.md`, options are also classified
as Selection / Output / Precautionary / Miscellaneous.

## Inventory — status & Windows mapping

| Option | Class | Status | Windows mapping / note |
|---|---|---|---|
| `-a` | sel | ✅ shipped | AND combinator |
| `-A A` | sel | ❌ N/A | AFS NWA mode (HP-UX); not portable |
| `-b` | prec | ❌ N/A | "avoid blocking kernel" — superseded by our own bounded-worker model |
| `-c c` | sel | ✅ shipped | Match by command/image name |
| `+c c` | out | 🟡 **Phase 5A** | Max command-name width in the COMMAND column — small render tweak |
| `-C` | prec | ❌ N/A | Kernel name cache; Unix-only |
| `-d d` | sel | ✅ shipped | FD filter (`cwd`/`txt`/`mem`/numbers/ranges/`^excl`) |
| `+d d` | sel | ✅ shipped | Directory tree (non-recursive) |
| `-D D` | prec | ❌ N/A | Device cache `/dev` — Unix-only |
| `+D D` | sel | ✅ shipped | Directory tree (recursive) |
| `-e s` | prec | ❌ N/A | Filesystem exempt — Unix mount-table thing |
| `-E` | out | 🟡 **Phase 5B** | Show socket endpoint detail; partially redundant with our `-i` NAME |
| `+E` | out | 🟡 **Phase 5B** | Same, extended |
| `-f [cfgGn]` | misc | ❌ mostly N/A | Filesystem-detail sub-flags; Unix-specific internals |
| `+f [cfgGn]` | misc | ❌ mostly N/A | Same |
| `-F [f]` | out | ✅ shipped | Field output (with `-F0` for NUL) |
| `-g [s]` | sel | 🟡 **Phase 5A** | Process *group* filter. Windows has no PGID — map to PPID (select children of PPID) and document as a Windows extension of `-g` semantics. |
| `-h` | misc | ✅ shipped | Help |
| `-?` | misc | 🟡 **Phase 5A** | Alias for `-h` — one-line add |
| `-H` | out | ❌ N/A | Legacy "headers" toggle on certain dialects |
| `-i [i]` | sel | ✅ shipped | Internet sockets `[46][tcp|udp][@host][:port]` |
| `-J` | out | ✅ shipped | JSON aggregated (winlsof extension, matches upstream's new format) |
| `-j` | out | ✅ shipped | JSON Lines (winlsof extension) |
| `-k k` | misc | ❌ N/A | Kernel symbol file — Unix-only |
| `-K [t]` | sel | 🟡 **Phase 5A** | **List tasks/threads.** Windows: Toolhelp32 `TH32CS_SNAPTHREAD` + `Thread32First/Next` enumerates threads per PID; render one row per thread under the process, with thread ID and start address. |
| `-l` | out | 🟡 **Phase 5A** | Numeric ID instead of resolved name. Windows: show the raw SID string instead of `DOMAIN\user` |
| `-L [l]` | out | 🟡 **Phase 5A** | **Show link count column** (with `+L count` filtering). Windows: `BY_HANDLE_FILE_INFORMATION.nNumberOfLinks` is already in the existing `disk_details()` call — just plumb it through `OpenFile`. |
| `+L [l]` | sel | 🟡 **Phase 5A** | Filter to files whose link count < `l` (`+L1` is unlinked-but-open files — a security-interesting case on Windows too) |
| `-m m` | misc | ❌ N/A | Mount supplement — Unix mtab |
| `+m [m]` | misc | ❌ N/A | Mount supplement output |
| `+|-M` | misc | ❌ N/A | Portmapper — Unix RPC |
| `-n` | out | ✅ shipped | No host name resolution |
| `-N` | sel | ❌ N/A | NFS-file listing |
| `-o [o]` | out | ✅ shipped | File offset in SIZE/OFF |
| `-O` | prec | 🟡 **Phase 5A** | "Avoid fork" — Unix-specific perf flag; safe to accept as a documented no-op for portability |
| `-p s` | sel | ✅ shipped | PID filter (comma-separated, accepts `^excl`) |
| `-P` | out | ✅ shipped | Numeric port instead of service name |
| `-Q` | misc | 🟡 **Phase 5A** | Quiet exit on no matches — we already do roughly this; explicit flag + the exit-code semantic |
| `+|-r [t]` | misc | ✅ shipped | Repeat (default 15s) |
| `-R` | out | ✅ shipped | PPID column |
| `-s [p:s]` | sel | 🟡 **Phase 5A** | **Protocol-state filter**: `-sTCP:LISTEN`, `-sTCP:^TIME_WAIT,^CLOSE_WAIT`. State already on the row — pure filter work. Single most-requested missing switch. |
| `-S [t]` | prec | ❌ N/A | `lstat`/`readlink` timeout — Unix; we have our own bounded model |
| `-t` | out | ✅ shipped | Terse PIDs only |
| `-T [t]` | out | 🟡 **Phase 5B** | TCP/TPI info: `-Tfqsw` = follow / queue lengths / state / TCP window. Windows: state is free; queue/window need `GetPerTcpConnectionEStats` (per-connection extended stats, IPv4 only, needs admin). Partial. |
| `-u s` | sel | ✅ shipped | User filter |
| `-U` | sel | 🟡 **Phase 5B** | UNIX-domain sockets. Windows: AF_UNIX exists since Win10 1803 — surfaces via the deferred ETW item §5 (currently the only public way). |
| `-v` | misc | ✅ shipped | Version banner |
| `-V` | misc | ✅ shipped | Verbose unmatched-search reporting |
| `+|-w` | misc | 🟡 **Phase 5A** | Warning enable/disable. We mostly already suppress; add the toggle. |
| `-x [fl]` | misc | ❌ N/A | Cross-mount FS traversal — Unix mount table |
| `-X` | out | ❌ N/A | Cross-over info — Linux epoll bridge |
| `-z [z]` | sel | ❌ N/A | Solaris zones |
| `-Z [Z]` | sel | ❌ N/A | SELinux contexts |
| `--` | misc | 🟡 **Phase 5A** | End-of-options sentinel — one-line parser change so `lsof -- -file` lets you name a file that starts with `-` |
| `<bare>` | sel | ✅ shipped | Path/name lookup via Restart Manager |

## Phase 5A — quick parity wins — ✅ COMPLETE

All 12 switches landed (commits across three iterations: the nine
render/filter/argparse tweaks, then `-L`/`+L`, then `-K`). Each is a small
render-tweak, filter-tweak, or argparse change. Together they close the
biggest gap in lsof-canonical CLI surface. Bonus: `--unicode`/`--ascii`
output-encoding flags were added after hardware feedback on console garbling.

| Switch | Effort | What lands |
|---|---|---|
| **`-s [p:s]`** | M | parser + `Selection::inet.state_filter`, filter in `apply()`; supports `TCP:LISTEN`, `TCP:^TIME_WAIT`, comma-separated lists |
| **`-K [t]`** | M | new `threads.rs` (`CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD)`); thread row per PID with TID + start addr; renders as `task` FD class |
| **`-L`** | S | plumb `nNumberOfLinks` (already read in `disk_details`) through `OpenFile.links`; new NLINK column when `-L` |
| **`+L [l]`** | S | filter rows by link count `< l`; combine with `-L` |
| **`-l`** | S | render numeric SID string instead of resolved `DOMAIN\user` |
| **`-g [s]`** | S | document Windows semantics ("select children of PPID(s)"); reuses existing PID-set parser |
| **`-Q`** | S | suppress "no matching open files" stderr; exit 0 even on empty result set |
| **`-w` / `+w`** | S | toggle the privilege-hint stderr line |
| **`-O`** | S | accept and no-op (with optional verbose-mode note) — pure portability |
| **`+c c`** | S | column-width cap on COMMAND in `table::render` |
| **`-?`** | S | alias to `-h` |
| **`--`** | S | end-of-options in argparse |

Estimated combined effort: **1 substantial commit** (~300–500 LOC across
`args.rs`, `selection.rs`, `table.rs`, plus new `threads.rs` and `Selection`
fields). Each switch gets a golden test in `lsof-core/tests/golden.rs` where it
affects rendering, plus a smoke-test case in `Invoke-WinlsofSmokeTest.ps1`.

## Phase 5B — deeper info (later)

Switches that need new Windows API work, or significant data-model expansion:

- **`-T [fqsw]`** — TCP queue/window: per-connection extended stats via
  `GetPerTcpConnectionEStats` / `GetPerTcp6ConnectionEStats`. Admin required;
  IPv4 fully supported, IPv6 partial. Render under the existing socket NAME or
  as a follow-on `(state) (rx_q=N tx_q=M win=N)` suffix.
- **`-E` / `+E`** — endpoint detail expansion. Lsof shows peer-PID for UNIX
  sockets; the closest Windows analog is the AFD-endpoint pointer surfaced by
  ETW. Bundle with item §5 resume.
- **`-U`** — explicit UNIX-domain filter. Lights up once ETW iteration 3 lands.

## Out of scope (Unix-only — accept-and-no-op or reject)

`-A`, `-b`, `-C`, `-D`, `-e`, `-f/+f`, `-H`, `-k`, `-m/+m`, `+M`, `-N`, `-S`,
`-x`, `-X`, `-z`, `-Z`. The parser should produce a clear error
("unsupported on Windows: -X") rather than silently ignoring; that's better
than appearing to accept and surprising the user.

## Sequencing

1. ~~**Phase 5A** — quick wins, all 12 switches~~ — ✅ **done.**
2. ~~**ETW iteration 3** — AFD-event parsing → non-TCP/UDP `-i` rows~~ —
   ✅ **done** (raw/ICMP/AF_UNIX now surface under `--etw`); unblocks `-U`.
3. **Phase 5B** (next) — `-T` (TCP queue/window via `GetPerTcp*EStats`),
   `-E`/`+E` (endpoint detail), `-U` (UNIX-domain filter, now backed by the
   ETW AFD path).
4. **Smoke-test additions** — extend `Invoke-WinlsofSmokeTest.ps1` with one
   case per new Phase 5A switch (target: 37 → ~50 cases).

## What I'm NOT promising

- **No new `-J`/`-j` JSON schema breakage**: every Phase 5A addition that adds a
  data field also adds it to `OpenFile`/`Process` in `lsof-core`; the JSON
  shape just grows new keys, never renames or removes.
- **No surprise CLI-behavior changes**: existing scripts that use the v0.1.0
  surface keep working exactly. Phase 5 is *additive*.
- **No silent acceptance of irrelevant Unix switches**: `-Z` etc. error out
  with a clear "unsupported on Windows" message rather than getting ignored.
