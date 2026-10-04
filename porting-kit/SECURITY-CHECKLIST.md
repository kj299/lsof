# SECURITY-CHECKLIST — per-module and per-release controls

The control ledger PLAYBOOK.md refers to. Work it top to bottom; each item names
the harness that enforces it. "Do as much as possible to add controls to adhere
to safety and security" — this is that list.

## Per module (Phase 4 gates)

- [ ] **No `unsafe` in `core`.** `#![forbid(unsafe_code)]` on every target root,
      in a form rustc applies → `unsafe-audit/check_forbid_unsafe.py` (hard-fail
      CI; LESSONS #065 found nothing checked the attribute before it).
- [ ] **Every `unsafe` block justified.** `unsafe-audit/audit_unsafe.py crates/`
      reports 0 undocumented. Each `// SAFETY:` states the invariant that makes
      the block sound, not just "it's fine." (Toolchain-free hard gate.) The
      comment must *precede* the block, not trail it — matching clippy's
      `undocumented_unsafe_blocks`, so a green audit predicts a green clippy
      (LESSONS #007; the two gates once disagreed and a trailing comment passed
      the audit but failed CI).
- [ ] **Every `unsafe fn` justified.** `clippy::missing_safety_doc` is enabled
      (via `[workspace.lints]`) and `-D` in CI, so every `pub unsafe fn` carries a
      `/// # Safety` section. The audit harness deliberately doesn't cover fns —
      clippy does; both must be wired (LESSONS #3: they weren't, so 11 lsof-rs
      `unsafe fn` went unchecked). `clippy::undocumented_unsafe_blocks` also runs
      as a cross-check of the harness.
- [ ] **`unsafe_op_in_unsafe_fn = "deny"`** (workspace lint), so every unsafe op
      inside an unsafe fn is individually blocked and commented.
- [ ] **No panic on untrusted input.** A `cargo-fuzz` target exists for every
      parse/decode entry point and runs clean (60s smoke min; nightly deep).
      No `unwrap()`/`expect()`/`[i]` indexing on attacker-controlled data.
- [ ] **No UB.** Miri passes on the pure logic; ASan passes over the FFI layer;
      TSan if the module shares state across threads (lsof-rs's hang class).
      rustc has no UB sanitizer: the harness's `ubsan` mode runs Miri.
- [ ] **Integer safety.** `overflow-checks = true`; size math uses
      `checked_*`/`saturating_*`; no `as` truncation on lengths/offsets from
      input. (Closes the C `malloc(a*b)` overflow class.)
- [ ] **Bounds by construction.** Slices + lengths, not raw pointer + count.
      Buffer "call-twice-for-size" idioms use a growing `Vec` with checks.
- [ ] **Bounded cost on hostile input.** A routine that runs on data a user can
      choose (a file name, a link, a mount source) is measured for time and
      memory on the worst such input at each place it runs. It runs only where
      its answer is used, and what it keeps is bounded by size, not only by
      count. A faithful port of the C brings the C's costs with it; lsof-rs's
      `Readlink()` made every run slow over one user's mount (LESSONS #079).
- [ ] **Differential-clean.** `diff_run.py` shows MATCH or a ledgered divergence;
      no unexplained drift.
- [ ] **The matrix covers the C's surface.** `coverage/coverage_gate.py
      --platform X` reports 0 uncovered on every platform, and every waiver
      says why (LESSONS #018); a waiver that excuses what the port now does is
      removed, not kept.
- [ ] **The cases check something.** The rules the change wrote are mutated, the
      mutants committed beside the cases, and every one is KILLED by
      `port-mutation/mutate_port.py` (LESSONS #083).
- [ ] **The ledgers exist.** `ledgers/check_ledgers.py`: progress file,
      divergence ledger, a fuzz target, a sanitizer job and a sanitizer step
      per tracked unit (LESSONS #019).
- [ ] **C flaws closed.** Every `scan_c_flaws.py` hit in this module is either
      not-applicable (documented) or fixed → `DIVERGENCES.md` entry with CWE.

## Per release (Phase 5)

- [ ] **Supply chain clean.** `supply-chain/run_supply_chain.sh`: `cargo audit`
      (no open RUSTSEC advisories) + `cargo deny` (licenses allow-listed, sources
      restricted to crates.io, no wildcard dependencies; duplicate versions only
      warn, and the template bans nothing — add bans yourself). Dependency count is
      justifiable — a safety rewrite doesn't import unsafety through its deps.
- [ ] **The harness supply chain is clean, too.** The test / differential / smoke
      harness must not download-and-execute a binary oracle: a compromised host
      would run arbitrary code in your dev/CI environment. Use OS-shipped native
      commands as oracles (lsof-rs's smoke test fetched `handle64.exe` from a live
      URL — removed, replaced with native `Get-*` / `netstat`). Supply chain
      covers the code that *tests* the port, not only the code it ships.
- [ ] **Least privilege.** Privileges acquired just-in-time and scoped to the one
      call that needs them (RAII guard), never held globally. Runs unprivileged
      by default; degrades rather than fails when it can't reach something.
- [ ] **No secrets / hostnames / tokens** in the binary, logs, or committed
      artifacts. Default output encoding is the target's lowest-common-denominator
      shell (lsof-rs: ASCII default; UTF-8 opt-in) so it can't be mis-rendered.
- [ ] **Reproducible + verifiable build.** Publish a checksum; document it.
      Code-sign if distributing binaries (unsigned → SmartScreen/AV friction).
- [ ] **`DIVERGENCES.md` shipped as release notes.** The security fixes over the
      C original are a feature; tell users what behavior changed and why.
- [ ] **Threat model current.** `THREAT-MODEL.md` reflects the shipped surface;
      non-goals stated so reviewers don't assume uncovered protections.
      `threat-model/check_threat_model.py` hard-fails a missing file, a leftover
      placeholder or a deleted section; that it is *current* is this box's job.

## Threat-model template

See `skeleton/THREAT-MODEL.md`. Fill it at Phase 0: assets, trust boundaries
(→ fuzz priorities), privilege transitions (→ audit hotspots), attacker
capabilities, explicit non-goals, and the C-defect inventory from the flaw scan.
