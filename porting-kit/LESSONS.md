# LESSONS — append-only log

Every port appends here (via `PROMPTS/90-retrospective.md`). This is how the kit
compounds: each entry names a lesson, the codebase that taught it, and the
`PLAYBOOK.md`/harness section it amended. **Append only — never rewrite history.**

Format per entry:

    ## NNN. <one-line lesson>
    - **Date:** YYYY-MM-DD
    - **Codebase:** <project> (<language/domain>)
    - **What happened:** <the failure or insight, grounded in evidence>
    - **Kit change:** <the concrete PLAYBOOK/harness/template edit made>
    - **Section amended:** <file · section>

---

## 001. The kit's own dry-run against lsof's failure inventory

- **Date:** 2026-07-05
- **Codebase:** winlsof (C `lsof` → Rust, Windows) — Phase 3 self-validation
- **What happened:** Walking `PLAYBOOK.md` end-to-end against the
  `RETROSPECTIVE-lsof.md` §6 failure inventory surfaced five failures the
  playbook, as first drafted, would *not* have prevented. Each was fixed in the
  playbook and is recorded below. This is entry #1 because the first thing the
  kit did was find its own gaps.

  1. **The hang wasn't spiked because it wasn't *recognized* as hazardous.**
     The "spike the scary module first" rule can only fire on a hazard someone
     wrote down. The 7-commit `NtQueryObject` hang had no such note.
     → **Kit change:** Phase 0 now requires *classifying the FFI/syscall surface
     by failure mode* (blocks-indefinitely? needs-privilege? version-variant?),
     which is what arms the spike-first rule.
     → *Section amended:* PLAYBOOK · Phase 0 "Do".

  2. **Hangs are invisible to the safety gates.** A deadlock/blocking call is a
     liveness bug, not UB — Miri/ASan/TSan don't flag it, and "compiles + matches
     oracle" hides it. The playbook's gate set had no liveness check.
     → **Kit change:** documented that the differential harness's per-case
     timeout (`diff_run.py` → `<<TIMEOUT>>`) IS the liveness backstop, and a
     timeout is a design smell to be *designed out*, not wrapped.
     → *Section amended:* PLAYBOOK · Phase 4 gate 2.

  3. **The research-grade spike-and-gate ritual — winlsof's biggest win — was
     underweighted.** The draft only spiked *hazardous modules*, not *capabilities
     that might be impossible*. Those need effort/confidence ratings, a written
     decision gate, and a pivot check (winlsof's ETW pivot: couldn't get the real
     FD, but shipped raw/ICMP/AF_UNIX coverage instead).
     → **Kit change:** added the explicit spike-and-gate sub-process.
     → *Section amended:* PLAYBOOK · Phase 4 (research-grade capability).

  4. **The test harness's host fought back and the playbook didn't warn of it.**
     Six commits went to PowerShell-5.1 / Windows-1252 breakage *in the harness*.
     → **Kit change:** Phase 2 now has a "harden the harness for its host" step
     (write kit harnesses in a portable language — Python + POSIX sh, done — and
     pin the tool's default output encoding to the target's default shell).
     → *Section amended:* PLAYBOOK · Phase 2 "Do".

  5. **Environment friction (toolchain / synced build dir) ate time with no code
     cause.** MSVC-vs-GNU linker mismatch; OneDrive locking `target\`.
     → **Kit change:** Phase 3 gained an "environment preflight" exit criterion.
     → *Section amended:* PLAYBOOK · Phase 3.

- **Validation the kit already pays off:** running the new
  `unsafe-audit/audit_unsafe.py` against the shipped winlsof backend reported
  **131 real `unsafe` blocks, 51 undocumented** — empirically confirming the
  retrospective's inferred "144-vs-91" gap (the tool correctly excludes the
  comment/string matches that inflated the raw grep). The hard-fail gate would
  have prevented every one of those 51 from merging undocumented.
- **Still not prevented (the next port's target):** the kit cannot force the
  *design insight* that ended the hang (avoid the blocking call via a type-index
  pre-probe). It can make the hang *visible* early (classification + timeout
  gate) and buy time to find the insight, but inventing the safe design remains
  human/agent work. A future kit lesson may add a "hazardous-API pattern library"
  of known avoid-the-call recipes.

---

## 002. A noisy Phase-0 scanner is worse than none — it gets ignored

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 1 (kit run against lsof's *actual* C tree)
- **What happened:** Running `c-flaw-scan/scan_c_flaws.py` against real lsof
  (`lib/ src/`) returned **1044 hits, of which 828 were false "format-string"
  positives.** The check flagged arg 0 of every printf-family call, but the
  format string is not arg 0 for `fprintf`/`sprintf`/`snprintf`/`syslog`/`err`
  (it follows the stream / buffer / size / priority). So every
  `fprintf(stderr, "literal", ...)` — the overwhelmingly common, *safe* case —
  was flagged. A Phase-0 tool that cries wolf 828 times gets muted, and the
  ~215 real candidates (97 TOCTOU, 94 integer-overflow, 24 unbounded-copy) drown
  in the noise. That is the exact opposite of the tool's purpose: to *bootstrap
  the flaw inventory*. This is itself a lsof-class failure — a control so noisy
  it is ignored is a broken control (the retrospective's own "a skipped control
  is a broken control").
- **Kit change:** rewrote the format-string check to locate the *format-position*
  argument per function (a small arg-list parser + per-function format index)
  and flag only when that argument is a **non-literal**. Result on the same lsof
  tree: format-string **828 → 8** (all 8 genuine non-literal formats), total
  **1044 → 224**. Pinned with a self-test that asserts `fprintf(stderr, var, ...)`
  flags but `fprintf(stderr, "literal", ...)` and `snprintf(buf, n, "%d", ...)`
  do not.
- **Section amended:** harnesses/c-flaw-scan/scan_c_flaws.py (`FORMAT_FUNCS`,
  `_call_args`, `_scan_format_strings`); the general principle — *tune every
  Phase-0 scanner for signal-to-noise against the real target before trusting
  it* — belongs to PLAYBOOK · Phase 0.

---

## 003. A "delegated" control that nothing enforces is not a control

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 2 (kit run against lsof/winlsof's real code)
- **What happened:** The unsafe-audit harness documents that it covers `unsafe {}`
  blocks + `unsafe impl`, and *delegates* `unsafe fn` `# Safety`-doc coverage to
  "clippy's `missing_safety_doc`." But grepping the shipped winlsof backend found
  **11 `unsafe fn` / `unsafe extern fn` definitions** (ETW callbacks and TDH
  property parsers — real FFI-facing unsafe surface), and **neither the CI
  template nor the skeleton enabled that clippy lint** (it is allow-by-default).
  So the delegation was fiction: no tool, anywhere, checked that any `unsafe fn`
  had a safety contract. A control you point at another tool that you never turn
  on is worse than an acknowledged gap — it reads as covered.
- **Kit change:** wired the clippy half for real. `[workspace.lints]` in the
  skeleton now sets `clippy::missing_safety_doc` + `undocumented_unsafe_blocks`
  (plus `cast_possible_truncation` and `arithmetic_side_effects` — the C-idiom
  footguns), each crate opts in via `[lints] workspace = true`, and the CI
  clippy step passes `-D clippy::missing_safety_doc -D
  clippy::undocumented_unsafe_blocks` as belt-and-suspenders for repos that copy
  the CI without the lints table. Documented the two-layer split (harness =
  toolchain-free block gate; clippy = `unsafe fn` docs + block cross-check) in
  the harness docstring and SECURITY-CHECKLIST. Skeleton still builds offline.
- **Section amended:** skeleton/Cargo.toml (`[workspace.lints]`) + each crate's
  `[lints]`; harnesses/ci/porting-ci.template.yml (clippy step);
  SECURITY-CHECKLIST · per-module; audit_unsafe.py docstring.

---

## 004. Differential fidelity is stdout AND exit code, not stdout alone

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 3 (kit run against lsof's real behavior)
- **What happened:** `diff_run.py` *captured* both binaries' exit codes but its
  verdict was computed from normalized stdout only — the codes were reported and
  ignored. So a rewrite with identical output and a wrong exit status passed as
  MATCH. That is a real fidelity hole: lsof exits 1 on "no matching open files"
  and shell scripts branch on it (`lsof -t … || echo none`); winlsof itself had a
  documented exit-code-capture bug (commit `3a56937`). A harness that blesses the
  wrong status defeats the point of a differential.
- **Kit change:** the verdict is now `stdout_match AND exit_match`; an exit-only
  difference DIVERGEs with a note naming both codes; `--ignore-exit` opts out for
  tools without stable statuses. Pinned with a self-test (same stdout + different
  exit → DIVERGE; `--ignore-exit` → MATCH). PLAYBOOK Phase 4 gate 2 updated.
- **Section amended:** harnesses/differential/diff_run.py (`compare`, CLI,
  self-test); PLAYBOOK · Phase 4 gate 2.

## 005. Path-scope CI, or unrelated changes make PRs look "unstable"

- **Date:** 2026-07-05
- **Codebase:** winlsof / lsof — the repo's own CI, found while landing the kit
- **What happened:** The kit's PR merged from GitHub `mergeable_state: "unstable"`.
  Nothing was failing — all checks went green — but the C project's `build.yml`
  (a full autotools `configure`/`make`/`make check`/`distcheck` on ubuntu-24.04 +
  ubuntu-22.04 + macOS) triggered on **every push/PR with no path filter**, so a
  *docs-and-scripts-only* `porting-kit/` change (and every `winlsof/` change,
  which already has its own path-scoped CI) kicked off three heavyweight C builds
  and left the PR "unstable" until they drained. Wasted CI, and a merge state that
  reads as broken when it isn't. `mergeable_state: "unstable"` means *pending or
  failing non-required checks* — not necessarily failure.
- **Kit change:** added `paths-ignore: ['porting-kit/**', 'winlsof/**']` to the
  C workflow's `push` and `pull_request` triggers (mirroring the path-scoping the
  Rust CI already used), and taught the kit's CI template to scope each
  language/subtree's workflow to its own paths. In a gradual port — where C and
  Rust coexist in one repo — an unscoped `on: [push]` runs the heavy build on
  changes it cannot affect; scope it.
- **Section amended:** harnesses/ci/porting-ci.template.yml (`on:` triggers);
  the `porting-kit-audit` skill (CI-hygiene gate). General rule for PLAYBOOK ·
  Phase 3 (skeleton/CI): scope every workflow to the paths it actually builds.

## Meta — three dry-run passes, three distinct classes of gap

Running the kit against lsof's *actual* code three times (LESSONS #2–#4) found
three different failure classes, none of which the paper Phase-3 pass (#1) caught
— because #1 was a walk of the retrospective's narrative, and these only appear
when you *execute the harnesses against the real codebase*:
- **#2 — too noisy to trust:** a scanner with 828 false positives is muted.
- **#3 — claimed but unwired:** an unsafe-fn doc gate delegated to a lint nobody
  enabled.
- **#4 — checks less than it captures:** a differential that reads exit codes but
  judges on stdout alone.
The lesson about the lessons: **a dry-run that doesn't run the tools against the
real target is theater.** All three gaps were in the *harnesses* (the kit's own
code), not the playbook prose — evidence that a kit is only as good as its tools
are exercised. `PROMPTS/90-retrospective.md` already says "run against the real
code"; these passes prove that half is where the findings live, and it is now
the emphasized half.

---

## 006. Oracle-substitution differential — built, and the native oracle lies in new ways

- **Date:** 2026-07-24
- **Codebase:** winlsof — the socket differential, promoted to a hard CI gate (PR #29)
- **What happened:** RETROSPECTIVE §5 / LESSONS #4 named "oracle-substitution" as
  the differential mode the kit *needs* when the C binary won't run on the target
  (no lsof on Windows). This session built it: winlsof `-i` socket SET vs
  `Get-NetTCPConnection` / `Get-NetUDPEndpoint` over self-owned fixtures, landed
  observe-first then promoted to a hard gate once green. Two failure classes
  appeared that a same-binary diff never produces. (a) **The oracle's serializer
  lied:** `ConvertTo-Json -AsArray` on a single-element set emitted `[[…]]`, and
  the parser read the double-wrap as a divergence (fixed `48d8b4c` — pipe to
  `ConvertTo-Json`, unwrap defensively, and raise on a shape it can't trust). (b)
  **A benign platform race:** a transient IPv6 BOUND shadow socket reported by NSI
  but not `GetExtendedTcpTable` — real, not a port bug — which the divergence
  ledger must *absorb*, not fail on (`61e1f04`). The exit contract grew a third
  value: infra-error (2) ≠ divergence (1) ≠ match (0), so a broken harness can't
  masquerade as a rewrite bug.
- **Kit change:** documented oracle-substitution as a first-class second
  differential mode in the matrix header (both modes, the three-way exit contract,
  and "parse the oracle defensively — its serializer is not your friend"); PLAYBOOK
  Phase 4 gate 2 now points at both modes.
- **Section amended:** harnesses/differential/input-matrix.example.toml (header);
  PLAYBOOK · Phase 4 gate 2.

---

## 007. Two gates for one property must accept the same thing (audit vs clippy SAFETY placement)

- **Date:** 2026-07-24
- **Codebase:** winlsof — the safety-gate PR (#30), caught in CI at `etw.rs`
- **What happened:** The kit runs two checks for "every `unsafe` block is
  documented": the toolchain-free `audit_unsafe.py` (hard gate) and clippy's
  `undocumented_unsafe_blocks` (wired via `[workspace.lints]` + `-D warnings`,
  LESSONS #3). They **disagreed on placement**: the audit accepted a `// SAFETY:`
  *trailing* on the block's own line; clippy credits the comment only when it
  *precedes* the block. So a block documented trailing-style passed the audit
  locally and then failed the clippy gate in CI (`etw.rs:582`). Worse, for a split
  `let x =` / `unsafe { … }` statement the comment must sit *between* the two lines
  to satisfy both (the audit stops at the first real code line; clippy credits a
  comment above the statement). Two gates for one invariant that bless different
  layouts = a gate that greenlights what its twin rejects.
- **Kit change:** tightened `audit_unsafe.py`'s `has_safety_comment` to
  **preceding-only**, matching clippy, so a green audit predicts a green clippy;
  pinned with a self-test (a trailing `// SAFETY:` is now flagged). Re-ran against
  the shipped backend: still **133/133** documented (every block was already
  preceding-style, because clippy enforces it on the green CI), so the tightening
  is regression-free.
- **Section amended:** harnesses/unsafe-audit/audit_unsafe.py (`has_safety_comment`,
  self-test, docstring); SECURITY-CHECKLIST · per-module `unsafe` item.

---

## 008. "Matches the oracle" ≠ "ports all functionality" — a differential is only as complete as its matrix

- **Date:** 2026-07-24
- **Codebase:** winlsof — the full-port depth gap analysis (PR #31)
- **What happened:** A gap analysis found the *option surface* complete (47/47
  switches) and the socket differential fully green — yet the port silently
  dropped **every non-File kernel object type**: registry Keys, Events, Mutants,
  Sections, Process/Thread/Token/Job/ALPC/IOCP handles were skipped with a
  `continue` and never emitted (the `KEY/EVT/MUT/SECT/…` TYPE codes were dead enum
  arms). The differential said nothing because its fixtures only created sockets;
  the golden tests said nothing because they only built File handles. **A green
  differential over a matrix that never exercises a feature class is silent about
  that class** — and in oracle-substitution mode it's sharper, because the native
  oracle *also* only observes what your fixtures create, so an un-created type is a
  *false MATCH*, never a divergence. Fixed by classifying every type via
  `NtQueryObject(TypeInformation)` with `FileType::Other(code)` for the long tail
  (`b6581b9`), so nothing is dropped.
- **Kit change:** added a "COMPLETENESS IS NOT GREENNESS" section to the matrix
  header — enumerate the C's feature surface (every option, every object/record
  TYPE) and give each a case; PLAYBOOK gate 2 carries the caveat. The
  retrospective/audit must include a "what does the C emit that no fixture
  exercises?" completeness pass.
- **Section amended:** harnesses/differential/input-matrix.example.toml (header);
  PLAYBOOK · Phase 4 gate 2.

---

## 009. A superseded CI run is not a passed run — the trap of a CI-only-validated backend

- **Date:** 2026-07-24
- **Codebase:** winlsof — the Windows backend, un-buildable on the Linux dev host
- **What happened:** The Windows crate compiles only on Windows, so its gates
  (clippy/build/test/differential) can *only* run in CI. Two hazards followed.
  First, promoting a brand-new gate straight to hard-fail risks a flaky harness
  wedging every PR — the differential was landed **observe-first**
  (continue-on-error) and read across several real runs before promotion. Second,
  and subtler: an index-cache commit pushed two functions to 8 arguments, tripping
  `clippy::too_many_arguments` — but that failure **never surfaced for two
  commits**, because each rapid follow-up push *cancelled the in-flight Windows
  run*. "CI was green" had referred to an *earlier* commit; the head commit's
  clippy gate had never finished. The lint appeared only when a later push finally
  let a Windows run complete (fixed `9e0bbcf`).
- **Kit change:** PLAYBOOK documents the observe-first→promote pattern for
  CI-only gates, the infra-vs-failure exit-code split, and the rule — before
  calling a CI-only-validated change green, confirm the *head SHA* has a
  **completed** (not cancelled/superseded) run.
- **Section amended:** PLAYBOOK · Cross-cutting controls (CI-only gates).

---

## 010. The test harness's supply chain counts too — don't download-and-run a binary oracle

- **Date:** 2026-07-24
- **Codebase:** winlsof — the live smoke harness (`Invoke-WinlsofSmokeTest.ps1`)
- **What happened:** The smoke harness auto-fetched Sysinternals `handle64.exe`
  from a live URL (RETROSPECTIVE §5, commit `0bb76f0`) and executed it as a handle
  oracle. That is a supply-chain hole in the *test* path: a compromised host (or a
  MITM) would run attacker code in the dev/CI environment — with none of the
  `cargo-deny`/`cargo-audit` scrutiny applied to the *shipped* dependencies. The
  harness was rewritten to drop the download entirely and cross-check against
  **native, OS-shipped commands** only (`Get-Process`, `Get-NetTCPConnection`,
  `netstat`). Supply-chain hygiene has to cover the code that *tests* the port,
  not only the code it ships.
- **Kit change:** SECURITY-CHECKLIST gained a per-release item — the harness must
  not download-and-execute a binary oracle; use native/OS-shipped commands.
- **Section amended:** SECURITY-CHECKLIST · per-release supply-chain.
