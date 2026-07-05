# Architecture template — the workspace shape that makes safety structural

Copy [`skeleton/`](skeleton/) to your new project root and rename the crates.
This is the layering that worked in the winlsof port, refocused (per the author's
direction) on **unsafe isolation and safety**, not OS abstraction.

```
workspace/
├─ crates/
│  ├─ core/   #![forbid(unsafe_code)]   ← MOST of the ported logic lives here
│  │          model, parsing, algorithm, rendering. Zero FFI. Testable anywhere,
│  │          on any host, with no target set up. Fuzzed. Miri-clean trivially.
│  ├─ sys/    the ONLY crate allowed `unsafe`
│  │          every FFI call wrapped in a small audited safe fn; every OS resource
│  │          an RAII type (acquire in `new`, release in `Drop`). The unsafe-audit
│  │          harness runs here and HARD-FAILS on any undocumented block.
│  └─ cli/    thin: parse args → build request → call core → render. No logic.
├─ DIVERGENCES.md      intentional-divergence ledger (diff harness reads it)
├─ THREAT-MODEL.md     Phase-0 threat model
└─ deny.toml           copied from harnesses/supply-chain/deny.template.toml
```

## Why this shape

- **`forbid(unsafe_code)` on `core` is the keystone.** It converts "is the unsafe
  contained?" from a recurring review question into a compile-time guarantee. In
  the retrospective, `core` had **0** unsafe and the sys layer **144** — but only
  91 documented. The split is what let the audit gate target exactly one crate.
- **RAII is the bug-killer.** The two most leak-prone C idioms — `close(fd)` and
  drop-privilege — become `Drop` impls (`OwnedResource` in the skeleton is the
  `OwnedHandle`/`PrivilegeGuard` analog). Use-after-free, double-free, leak, and
  privilege-held-too-long stop being possible, not just unlikely.
- **`core` testable everywhere** means CI runs the real logic tests on the cheap
  default runner, every push, regardless of the target platform — winlsof kept
  its 26 core tests green on Linux CI while the backend was Windows-only.

## Conventions the skeleton encodes

- **`overflow-checks = true` in release.** Silent integer wraparound is a C bug
  class a safety rewrite must not reproduce; pay the small cost.
- **`#![deny(unsafe_op_in_unsafe_fn)]` in `sys`.** Even inside an `unsafe fn`,
  each unsafe operation needs an explicit `unsafe {}` — so every one gets a
  `// SAFETY:` and the audit harness sees it.
- **No `unwrap()`/`expect()` on untrusted input.** Parsers return `Result`; the
  fuzz gate enforces "never panic on arbitrary bytes."
- **Dependencies are liabilities.** Each one must clear the supply-chain gate.
  A rewrite for safety that pulls unsafety in through the dep tree has failed.

## If your port *is* cross-platform

Keep the seam, but as an *isolation* boundary, not a feature: a trait in `core`
whose implementations live in `sys` behind `#[cfg(...)]`, with a mock impl so
`core` stays testable off-target. That is all the OS abstraction the kit
prescribes — the focus stays on safety, per the author's direction.
