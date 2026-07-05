# SECURITY-CHECKLIST — per-module and per-release controls

The control ledger PLAYBOOK.md refers to. Work it top to bottom; each item names
the harness that enforces it. "Do as much as possible to add controls to adhere
to safety and security" — this is that list.

## Per module (Phase 4 gates)

- [ ] **No `unsafe` in `core`.** `#![forbid(unsafe_code)]` present → compile-time.
- [ ] **Every `unsafe` block justified.** `unsafe-audit/audit_unsafe.py crates/`
      reports 0 undocumented. Each `// SAFETY:` states the invariant that makes
      the block sound, not just "it's fine." (Toolchain-free hard gate.)
- [ ] **Every `unsafe fn` justified.** `clippy::missing_safety_doc` is enabled
      (via `[workspace.lints]`) and `-D` in CI, so every `pub unsafe fn` carries a
      `/// # Safety` section. The audit harness deliberately doesn't cover fns —
      clippy does; both must be wired (LESSONS #3: they weren't, so 11 winlsof
      `unsafe fn` went unchecked). `clippy::undocumented_unsafe_blocks` also runs
      as a cross-check of the harness.
- [ ] **`unsafe_op_in_unsafe_fn = "deny"`** (workspace lint), so every unsafe op
      inside an unsafe fn is individually blocked and commented.
- [ ] **No panic on untrusted input.** A `cargo-fuzz` target exists for every
      parse/decode entry point and runs clean (60s smoke min; nightly deep).
      No `unwrap()`/`expect()`/`[i]` indexing on attacker-controlled data.
- [ ] **No UB.** Miri passes on the pure logic; ASan/UBSan pass over the FFI
      layer; TSan if the module shares state across threads (winlsof's hang class).
- [ ] **Integer safety.** `overflow-checks = true`; size math uses
      `checked_*`/`saturating_*`; no `as` truncation on lengths/offsets from
      input. (Closes the C `malloc(a*b)` overflow class.)
- [ ] **Bounds by construction.** Slices + lengths, not raw pointer + count.
      Buffer "call-twice-for-size" idioms use a growing `Vec` with checks.
- [ ] **Differential-clean.** `diff_run.py` shows MATCH or a ledgered divergence;
      no unexplained drift.
- [ ] **C flaws closed.** Every `scan_c_flaws.py` hit in this module is either
      not-applicable (documented) or fixed → `DIVERGENCES.md` entry with CWE.

## Per release (Phase 5)

- [ ] **Supply chain clean.** `supply-chain/run_supply_chain.sh`: `cargo audit`
      (no open RUSTSEC advisories) + `cargo deny` (licenses allow-listed, sources
      restricted to crates.io, no banned/duplicate crates). Dependency count is
      justifiable — a safety rewrite doesn't import unsafety through its deps.
- [ ] **Least privilege.** Privileges acquired just-in-time and scoped to the one
      call that needs them (RAII guard), never held globally. Runs unprivileged
      by default; degrades rather than fails when it can't reach something.
- [ ] **No secrets / hostnames / tokens** in the binary, logs, or committed
      artifacts. Default output encoding is the target's lowest-common-denominator
      shell (winlsof: ASCII default; UTF-8 opt-in) so it can't be mis-rendered.
- [ ] **Reproducible + verifiable build.** Publish a checksum; document it.
      Code-sign if distributing binaries (unsigned → SmartScreen/AV friction).
- [ ] **`DIVERGENCES.md` shipped as release notes.** The security fixes over the
      C original are a feature; tell users what behavior changed and why.
- [ ] **Threat model current.** `THREAT-MODEL.md` reflects the shipped surface;
      non-goals stated so reviewers don't assume uncovered protections.

## Threat-model template

See `skeleton/THREAT-MODEL.md`. Fill it at Phase 0: assets, trust boundaries
(→ fuzz priorities), privilege transitions (→ audit hotspots), attacker
capabilities, explicit non-goals, and the C-defect inventory from the flaw scan.
