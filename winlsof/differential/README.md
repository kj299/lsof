# winlsof socket differential — oracle-substitution mode

The reference C `lsof` **cannot run on Windows**, so winlsof can't be diffed
against it the way the porting kit's normal differential diffs a C binary against
its Rust port. This harness is the substitute the retrospective prescribed
(`porting-kit/RETROSPECTIVE-lsof.md` §5): use the **operating system's own socket
table as the oracle** and compare winlsof's `-i` output against it as a **set**.

That set-equivalence is the point. The pre-existing smoke test asks *"does the
output contain this one string?"* — which a silently dropped, extra, or
misclassified socket row sails straight past. This asks *"is winlsof's socket set
**equal** to the OS oracle's, modulo a ledger of intentional differences?"* — the
only check that catches a missing or wrong row. The survey flagged this as the
single highest-leverage correctness improvement available to the port.

## Design

Two pieces, split so the logic is testable off-Windows:

| File | Runs on | Role |
|---|---|---|
| `oracle_diff.py` | any host | Parse winlsof (`-J` **or** `-F`) + the oracle JSON, canonicalize both identically, set-diff, honor the ledger, exit non-zero on unledgered divergence. Pure stdlib. |
| `capture.ps1` | windows | Stand up self-owned fixtures, capture winlsof's view **and** `Get-NetTCPConnection`/`Get-NetUDPEndpoint`, invoke the comparator. Built-in cmdlets only — no Sysinternals, no elevation, no third-party Actions. |
| `ledger.json` | — | Intentional-divergence rules (empty for the fixture gate; see below). |
| `test_oracle_diff.py` | any host | Unit tests over the comparator, using the **verbatim** mock-backend output of the real binary. |

**Why the capture is fixture-scoped.** winlsof and the oracle are sampled a few
milliseconds apart, so a machine-wide comparison would flake on every transient
connection. Instead `capture.ps1` creates sockets it owns — a loopback TCP
listener, an established loopback pair (which exercises the remote-address and
TCP-state path, where fidelity bugs like the EStats-on-non-ESTABLISHED regression
hid), and a bound UDP socket — then scopes the diff to **this pid and these
ports**. Deterministic, zero-flake, and still exercises enumeration →
classification → field formatting end to end.

**Why JSON is the gate.** winlsof's `-J` emits structured `local`/`remote`/`state`
already, so it maps onto the oracle without fragile string-splitting. The `-F`
parser is kept and tested too (it proves the scriptable contract), but the gate
runs on `-J`.

## Canonicalization (both sides, identically)

- Wildcard hosts (`0.0.0.0`, `::`, `[::]`) → `*`.
- IPv6 brackets stripped; zone id (`%12`) dropped; lower-cased.
- TCP states folded onto lsof's names (`Listen`→`LISTEN`, `TimeWait`→`TIME_WAIT`, …).
- A listener's placeholder peer (`0.0.0.0:0`) → *no remote*, matching lsof/winlsof.

## The ledger

`ledger.json` is a list of rules; a divergence is suppressed when every key it
pins (`proto`/`family`/`state` exact, `local`/`remote` substring, `side` =
`missing`|`extra`|`any`) matches. It is **empty** for the fixture gate — the
controlled sockets must match exactly. It exists for the broader, machine-wide
mode and for documenting real API-attributed gaps (e.g. connected-UDP foreign
address, which IP Helper does not expose) when this is pointed at live traffic.

## Run it

```powershell
# Windows, against a built or released binary (PowerShell 7 / pwsh):
pwsh winlsof/differential/capture.ps1 -Bin winlsof/target/release/lsof.exe
```

```bash
# Any host — exercise the comparator directly:
python3 winlsof/differential/test_oracle_diff.py
```

CI wires `capture.ps1` into the `windows` job of `.github/workflows/winlsof-ci.yml`,
so the differential gates every PR on a real `windows-latest` runner — the
retrospective's "fix → then pin the test that would have caught it", finally
enforced instead of practiced.

## Lineage

This applies the pattern from the **porting kit** (now `kj299/c2rust-port` v1.0)
that this very port helped distill: normalize both sides identically, diff, and
ledger the intentional divergences. It is the "oracle-substitution" second mode
that `RETROSPECTIVE-lsof.md` said the kit's differential must support.
