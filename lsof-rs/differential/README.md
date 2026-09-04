# lsof-rs socket differential — oracle-substitution mode

The reference C `lsof` **cannot run on Windows**, so lsof-rs can't be diffed
against it the way the porting kit's normal differential diffs a C binary against
its Rust port. This harness is the substitute the retrospective prescribed
(`porting-kit/RETROSPECTIVE-lsof.md` §5): use the **operating system's own socket
table as the oracle** and compare lsof-rs's `-i` output against it as a **set**.

That set-equivalence is the point. The pre-existing smoke test asks *"does the
output contain this one string?"* — which a silently dropped, extra, or
misclassified socket row sails straight past. This asks *"is lsof-rs's socket set
**equal** to the OS oracle's, modulo a ledger of intentional differences?"* — the
only check that catches a missing or wrong row. The survey flagged this as the
single highest-leverage correctness improvement available to the port.

## Design

Two pieces, split so the logic is testable off-Windows:

| File | Runs on | Role |
|---|---|---|
| `oracle_diff.py` | any host | Parse lsof-rs (`-J` **or** `-F`) + the oracle JSON, canonicalize both identically, set-diff, honor the ledger, exit non-zero on unledgered divergence. Pure stdlib. |
| `capture.ps1` | windows | Stand up self-owned fixtures, capture lsof-rs's view **and** `Get-NetTCPConnection`/`Get-NetUDPEndpoint`, invoke the comparator. Built-in cmdlets only — no Sysinternals, no elevation, no third-party Actions. |
| `ledger.json` | — | Intentional-divergence rules (empty for the fixture gate; see below). |
| `test_oracle_diff.py` | any host | Unit tests over the comparator, using the **verbatim** mock-backend output of the real binary. |

**Why the capture is fixture-scoped.** lsof-rs and the oracle are sampled a few
milliseconds apart, so a machine-wide comparison would flake on every transient
connection. Instead `capture.ps1` creates sockets it owns — a loopback TCP
listener, an established loopback pair (which exercises the remote-address path),
and a bound UDP socket — then scopes the diff to **this pid and these ports**.
Deterministic, zero-flake, and it still exercises enumeration → classification →
field formatting end to end. The fixtures cover both the **family** and **state**
classes: over IPv4 loopback, `LISTEN` + `ESTABLISHED` + a half-closed pair pinned
in **`CLOSE_WAIT`/`FIN_WAIT2`** + a bound UDP socket; over IPv6 loopback,
`LISTEN` + `ESTABLISHED`. The half-close (client `Shutdown(Send)` with the socket
kept open) is what makes the non-ESTABLISHED states deterministic — both rows
stay owned by the harness pid and hold their state for as long as the sockets
live, where a full close would instead orphan an unattributable pid-0
`TIME_WAIT`. A host without `::1` degrades the IPv6 class with a warning rather
than failing (hosted runners always have it).

**Why JSON is the gate.** lsof-rs's `-J` emits structured `local`/`remote`/`state`
already, so it maps onto the oracle without fragile string-splitting. The `-F`
parser is kept and tested too (it proves the scriptable contract), but the gate
runs on `-J`.

## Canonicalization (both sides, identically)

- Wildcard hosts (`0.0.0.0`, `::`, `[::]`) → `*`.
- IPv6 brackets stripped; zone id (`%12`) dropped; lower-cased.
- TCP states folded onto lsof's names (`Listen`→`LISTEN`, `TimeWait`→`TIME_WAIT`, …).
- A listener's placeholder peer (`0.0.0.0:0`) → *no remote*, matching lsof/lsof-rs.

## The ledger

`ledger.json` is a list of rules; a divergence is suppressed when every key it
pins matches — `proto`/`family`/`state` and `local`/`remote` are **exact**
against the canonical form (`*:53`, `127.0.0.1:445`, compressed IPv6), and `side`
is `missing`|`extra`|`any`. Exact (not substring) so a rule for `*:53` can't
silently swallow `*:5353`.

It carries one entry the fixture gate needs, and it is a real finding the
differential surfaced on its first Windows run: lsof-rs enumerates via
`GetExtendedTcpTable` (connection-oriented, like lsof), so it does **not** report
transient **`BOUND`** sockets that the NSI source behind `Get-NetTCPConnection`
does (a .NET client leaves a dual-stack `BOUND` IPv6 shadow). That is a documented
data-source difference, not a bug — so `{"state":"BOUND","side":"missing"}` is
ledgered. The ledger also covers the broader machine-wide mode and other
API-attributed gaps (e.g. connected-UDP foreign address, which IP Helper does not
expose) when this is pointed at live traffic.

## Exit codes

The comparator and `capture.ps1` share three codes so CI triage can tell a real
bug from broken plumbing: **0** = lsof-rs's set matches the oracle; **1** = a
genuine socket-set divergence (a missing/extra/misclassified row); **2** = infra
— an empty or malformed capture, a lsof-rs non-zero exit/hang, or a transient
oracle failure — which is explicitly *not* a lsof-rs verdict. The comparator
refuses to pass on an empty in-scope capture (a `{"processes":[]}` regression
can't slip through green), and `capture.ps1` asserts its own fixtures appear in
the oracle before diffing (a transiently-empty oracle can't masquerade as
lsof-rs "extras").

## Run it

```powershell
# Windows, against a built or released binary (PowerShell 7 / pwsh):
pwsh lsof-rs/differential/capture.ps1 -Bin lsof-rs/target/release/lsof.exe
```

```bash
# Any host — exercise the comparator directly:
python3 lsof-rs/differential/test_oracle_diff.py
```

CI wires `capture.ps1` into the `windows` job of `.github/workflows/lsof-rs-ci.yml`.
It runs on every PR on a real `windows-latest` runner, but starts **non-gating**
(`continue-on-error: true`): its flake vectors are environment- and
timing-dependent and can't be proven safe from a local run, so it observes for a
few green runs before being promoted to a hard gate (remove `continue-on-error`).
That is the retrospective's "fix → then pin the test that would have caught it",
finally on its way to being enforced instead of only practiced.

## Lineage

This applies the pattern from the **porting kit** (now `kj299/c2rust-port` v1.0)
that this very port helped distill: normalize both sides identically, diff, and
ledger the intentional divergences. It is the "oracle-substitution" second mode
that `RETROSPECTIVE-lsof.md` said the kit's differential must support.

---

## Linux — mode 1, the real C oracle (`linux_diff.py`)

On Linux the reference implementation runs on the same host, so the substitute
above is not needed: this is the kit's **mode 1** differential — the C `lsof`
built from **this tree** (the exact source being ported; apt's package is four
minor versions behind and would let the harness manufacture divergences that are
not the port's) and lsof-rs, run against the same fixture process at the same
instant, diffed through `porting-kit/harnesses/differential/diff_run.py` with
[`../DIVERGENCES.md`](../DIVERGENCES.md) as the ledger.

| File | Role |
|---|---|
| `linux_diff.py` | Stand up four self-owned fixtures (A: cwd + a regular file, a hostile-named file, a directory and a FIFO on fds 3/4/5/6; B: a TCP listener, a UDP socket, an AF_UNIX listener; C and D: sleepers whose COMMAND holds one of every character class the C escapes — ASCII controls, then é and the 8-bit CSI), substitute their PIDs into the matrix, run the kit runner under `LC_ALL=C.UTF-8` (the C's `safestrprt()` is locale-dependent; lsof-rs matches its UTF-8 behavior), tear down. Adds nothing to the comparison itself — that is the kit's. Three-way exit: 0 match/ledgered · 1 unexplained divergence · 2 infra (a missing binary, a fixture that did not come up, the locale not installed). |
| `linux-matrix.toml` | 13 cases. Every one carries `-a` (lsof ORs list options otherwise — see the ledger) and `-n -P` (lsof-rs never resolves names). File cases pass `-d ^mem` so they measure their own surface; `files-mem-rows` measures that gap and is ledgered as L2 debt. |

Why the fixture matters: both binaries see the **same** process, so PIDs, inodes,
devices and sizes are identical on both sides and the kit's default
whitespace-only normalization is all that is needed. Numbers are never masked
here — they are exactly the cells this gate exists to compare.

```sh
# from the repo root: build the oracle (binary target only; the man page
# needs groff and the oracle needs no manual), then lsof-rs, then diff
autoreconf -vif && ./configure && make lsof
( cd lsof-rs && cargo build --release --bin lsof )
python3 lsof-rs/differential/linux_diff.py --oracle ./lsof --rust lsof-rs/target/release/lsof
```

First run, 2026-09-02, against C 4.99.6: 13 cases, 9 MATCH, 4
DIVERGE(ledgered), 0 unexplained. Before it was a gate, doing this by hand
found every fidelity bug in phases L0 and L1 — and on its first fixture it found
two more (the `0t0` offset cell for devices and FIFOs; `pipe` in NAME), fixed in
the same PR. It runs on every Linux CI push as a hard gate.
