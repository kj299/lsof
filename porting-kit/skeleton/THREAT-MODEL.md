# Threat model — <project>

Fill this in at Phase 0, before writing Rust. It scopes what "secure" means here
and tells the port loop which modules touch untrusted input (fuzz those first)
and which cross a privilege boundary (audit those hardest).

## 1. Assets — what are we protecting?
- e.g. the integrity of the host we run on; the confidentiality of data we read;
  our own process from being subverted by hostile input.

## 2. Trust boundaries — where does untrusted data / lower trust cross in?
List each entry point and mark it. These are the fuzz + validation priorities.
| Entry point | Source | Trust | Ported module |
|---|---|---|---|
| CLI args / stdin | user / pipe | untrusted | `cli`, `core::parser` |
| files parsed | filesystem | semi-trusted | |
| network / IPC | remote | untrusted | |
| environment / config | operator | trusted-ish | |

## 3. Privilege transitions
Where does the tool gain/drop privilege, elevate, or act on another security
principal's behalf? Each is an audit hotspot; keep privilege JUST-IN-TIME and
scoped (the retrospective's `PrivilegeGuard` RAII pattern).

## 4. Attacker capabilities we defend against
- Supplies arbitrary bytes on any untrusted boundary (→ no panic/UB: fuzz gate).
- Supplies pathological sizes (→ no integer overflow / OOM: overflow-checks on).
- Races the filesystem/IPC (→ no TOCTOU: prefer open-then-check over check-then-open).

## 5. Explicit non-goals
- e.g. we do not defend against a malicious operator who already has our
  privileges; side-channel resistance is out of scope. State them so reviewers
  don't assume coverage that isn't there.

## 6. C-defect inventory (from `scan_c_flaws.py`)
Link the Phase-0 scan output. Each confirmed flaw becomes a DIVERGENCES.md entry
when the port closes it.
