# lsof-rs coverage gate — does the test surface cover the C's feature surface?

Every other gate in this repo asks *"is what we test correct?"* This one asks the
question that has no other owner: **"are we testing everything the port claims to
do?"** A differential can be fully green and say nothing about a feature no
fixture ever creates — which is exactly what happened here (porting-kit
`LESSONS.md` #8): the socket differential passed every run while lsof-rs silently
dropped **every non-File kernel object type**, because no test ever opened a
registry key, an event, or a mutant. The gap was invisible to both sides of the
diff — a false MATCH, never a divergence.

The gate is the kit's `harnesses/coverage/coverage_gate.py`; this directory holds
lsof-rs's two inputs.

| File | Role |
|---|---|
| `feature-inventory-lsof-rs.toml` | The **contract**: the C's full enumerated surface (45 option letters, 111 TYPE codes — extracted from `src/main.c` + `lib/print.c`) plus lsof-rs's 7 Windows-native TYPE codes, minus explicit waivers. |
| `coverage-matrix.toml` | The **declaration**: one `[[case]]` per real test in lsof-rs's suite — golden tests, the socket differential, and the 62-case live smoke harness. |

### All three sources actually run in CI

A coverage declaration is only worth as much as the test behind it, so every
source the matrix cites is executed by `lsof-rs-ci.yml`: golden tests and the
backend unit tests via `cargo test --all` (both runners), the socket
differential and the live smoke harness on the Windows runner. The smoke
harness was manual-only until 2026-07-25 — the matrix was crediting coverage
from a harness CI never ran, which is precisely the "declaring coverage you
don't have" failure this gate exists to prevent.

It was landed **observe-first** per porting-kit LESSONS #9, and the pattern
paid immediately: the first hosted-runner execution surfaced two real findings
(an 8.3 short-name gap in lsof-rs's path selectors, and a fixture asserting a
kernel file position modern .NET no longer moves — both fixed) without ever
turning master red. After two consecutive fully-green runs
(`PASS=53 FAIL=0 SKIP=2`; the SKIPs are elevation-dependent cases that
self-skip by design), it was **promoted to a hard gate** — a smoke FAIL now
fails the Windows job.

## Running it

```sh
python3 ../../porting-kit/harnesses/coverage/coverage_gate.py \
  --inventory feature-inventory-lsof-rs.toml \
  --matrix coverage-matrix.toml
```

Exit 0 = every non-waived feature is exercised; 1 = something isn't (it is named);
2 = infra error (unreadable/unparseable input), never confused with a real gap.
It runs in the `core + lints (linux)` CI job — pure stdlib Python, no toolchain.

## How coverage is counted

- **Options** are inferred from each case's `args`. Clusters count (`-nP` covers
  both), and scanning **stops after a value-taking option**: `-iTCP:80` is `-i`
  with a value, so `T`, `C`, `P` are *not* credited. Over-crediting would hide
  the gaps the gate exists to find.
- **TYPE codes** must be declared per case with `covers = ["type:KEY", …]`,
  because no flag spells what a *fixture* creates. That declaration is the whole
  mechanism: it is the thing that was missing when the object types vanished.

Keep the matrix truthful. A case belongs there only if a test really runs those
args and really asserts on that output — declaring coverage you don't have turns
this gate from a control into a lie.

## Waivers

Everything out of scope is an explicit `[[waive]]` with a reason; grouped
`ids = [...]` share one reason, and there are no globs, so a feature added to the
C later can never be swallowed by an existing waiver.

### Waivers are scoped per platform

A waiver may carry `platforms = [...]`, and **the gate runs once per platform**:

```sh
coverage_gate.py --inventory ... --matrix ... --platform windows
coverage_gate.py --inventory ... --matrix ... --platform linux
```

This exists because of a failure this file actually had. Most waiver reasons are
platform-specific — "Unix-only", "no Windows equivalent" — and such a reason
**expires the day the port grows a backend for that platform**. Nothing in the
file changes, so an unscoped gate stays green while excusing features the new
backend is expected to have. When the Linux backend merged, this inventory was
waiving `-Z` as "SELinux contexts", `-X` as "Linux epoll bridge", and every Unix
socket family — on a port that now targets Linux.

Two of them were not merely expired but wrong on the day: `type:BLK` and
`type:FIFO` were waived as having no Windows analogue while the Linux backend was
already emitting both. Scoping turned them from waived into **covered**.

A waiver with no `platforms` applies everywhere, and that is the right default
for genuinely other-dialect features (Solaris zones, BSD kqueue, HP-UX AFS).

### The three kinds

1. **Options declared N/A** — 5 unscoped (`-A` AFS, `-z` Solaris zones, `-C`
   kernel name cache, `-H`, `-k`), 10 Windows-scoped.
2. **Other dialects' TYPE codes** — Solaris `/proc`, BSD/macOS vnodes, and
   macOS link-layer families are unscoped; Unix socket families and Unix object
   types are Windows-scoped.
3. **Coverage debt** — **none on Windows.** On Linux, the features whose Windows
   waiver expired are declared as debt (`reason` beginning `DEBT (L1)` / `DEBT
   (L2)`) naming the phase that closes them. They are *debt, not waivers*: a
   waiver claims "we will never do this", which would be untrue of `-Z` or of
   socket classification. The gate output prints each one, so the list cannot rot
   unseen.

## Coverage debt: closed (2026-07-25)

The gate's first run reported 7 in-scope features that no test touched. They were
closed with tests, not with waivers:

| Was uncovered | Now covered by |
|---|---|
| `opt:u` | `args::tests::user_filter_parses` (`-u alice`, `-ualice`, comma lists) + `selection::tests::user_selector` (bare account or `DOMAIN\user`, either case; rejects a different domain and an unknown user) |
| `type:CHR` `type:EVT` `type:MUT` `type:SECT` `type:PROC` `type:TOKN` | `handles::tests::enumerates_real_kernel_object_types` |

That last test is deliberately **end-to-end**: it creates a real Event, Mutant,
Section, process handle, token, and NUL character device in-process, then runs the
actual `enumerate()` over this PID and requires each object's TYPE code to come
back. A unit test of the type-name→`FileType` mapping would *not* have caught the
original bug, which was a `continue` in the enumeration loop — upstream of
classification. It asserts only on objects it actually managed to create, so a
hardened environment can't produce a phantom failure, and it fails outright if it
could create none.

Everything is hard-gated now: deleting any coverage declaration makes the gate
exit 1 naming that feature (verified for `type:KEY`, `type:TOKN`, and `opt:u`).
