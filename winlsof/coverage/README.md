# winlsof coverage gate — does the test surface cover the C's feature surface?

Every other gate in this repo asks *"is what we test correct?"* This one asks the
question that has no other owner: **"are we testing everything the port claims to
do?"** A differential can be fully green and say nothing about a feature no
fixture ever creates — which is exactly what happened here (porting-kit
`LESSONS.md` #8): the socket differential passed every run while winlsof silently
dropped **every non-File kernel object type**, because no test ever opened a
registry key, an event, or a mutant. The gap was invisible to both sides of the
diff — a false MATCH, never a divergence.

The gate is the kit's `harnesses/coverage/coverage_gate.py`; this directory holds
winlsof's two inputs.

| File | Role |
|---|---|
| `feature-inventory-winlsof.toml` | The **contract**: the C's full enumerated surface (45 option letters, 111 TYPE codes — extracted from `src/main.c` + `lib/print.c`) plus winlsof's 7 Windows-native TYPE codes, minus explicit waivers. |
| `coverage-matrix.toml` | The **declaration**: one `[[case]]` per real test in winlsof's suite — golden tests, the socket differential, and the 55-case live smoke harness. |

## Running it

```sh
python3 ../../porting-kit/harnesses/coverage/coverage_gate.py \
  --inventory feature-inventory-winlsof.toml \
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
C later can never be swallowed by an existing waiver. Three kinds:

1. **Options declared N/A** (15) — reasons verbatim from
   `docs/feature-parity-plan.md` (`-A` AFS, `-z` Solaris zones, `-Z` SELinux, …).
2. **Other dialects' TYPE codes** (103) — Solaris `/proc`, BSD/macOS vnodes, Unix
   socket families, and `FIFO` (unreachable on Windows: pipe handles type as
   `PIPE`).
3. **Coverage debt** (7) — *in scope, shipped, not yet exercised.* These are not
   scope decisions, they are missing fixtures, and the gate prints them on every
   run so they stay visible:

   | Feature | Missing fixture |
   |---|---|
   | `opt:u` | no smoke case runs `-u` (user filter) |
   | `type:CHR` | nothing opens a character-device/console handle |
   | `type:EVT` `type:MUT` `type:SECT` `type:PROC` `type:TOKN` | the all-handle scan types these, but no fixture creates/opens one |

   Delete the waiver the moment a test covers it — the gate then enforces it
   forever. Everything else is hard-gated today, so a *newly* dropped feature
   fails CI immediately.

The `type:KEY` entry is not on that list because the golden test
`windows_object_types_render` genuinely asserts it. Dropping that assertion makes
the gate fail with `UNCOVERED type:KEY` — verified.
