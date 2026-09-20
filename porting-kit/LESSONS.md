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
- **Codebase:** lsof-rs (C `lsof` → Rust, Windows) — Phase 3 self-validation
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

  3. **The research-grade spike-and-gate ritual — lsof-rs's biggest win — was
     underweighted.** The draft only spiked *hazardous modules*, not *capabilities
     that might be impossible*. Those need effort/confidence ratings, a written
     decision gate, and a pivot check (lsof-rs's ETW pivot: couldn't get the real
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
  `unsafe-audit/audit_unsafe.py` against the shipped lsof-rs backend reported
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
- **Codebase:** lsof-rs — dry-run pass 1 (kit run against lsof's *actual* C tree)
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
- **Codebase:** lsof-rs — dry-run pass 2 (kit run against lsof/lsof-rs's real code)
- **What happened:** The unsafe-audit harness documents that it covers `unsafe {}`
  blocks + `unsafe impl`, and *delegates* `unsafe fn` `# Safety`-doc coverage to
  "clippy's `missing_safety_doc`." But grepping the shipped lsof-rs backend found
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
- **Codebase:** lsof-rs — dry-run pass 3 (kit run against lsof's real behavior)
- **What happened:** `diff_run.py` *captured* both binaries' exit codes but its
  verdict was computed from normalized stdout only — the codes were reported and
  ignored. So a rewrite with identical output and a wrong exit status passed as
  MATCH. That is a real fidelity hole: lsof exits 1 on "no matching open files"
  and shell scripts branch on it (`lsof -t … || echo none`); lsof-rs itself had a
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
- **Codebase:** lsof-rs / lsof — the repo's own CI, found while landing the kit
- **What happened:** The kit's PR merged from GitHub `mergeable_state: "unstable"`.
  Nothing was failing — all checks went green — but the C project's `build.yml`
  (a full autotools `configure`/`make`/`make check`/`distcheck` on ubuntu-24.04 +
  ubuntu-22.04 + macOS) triggered on **every push/PR with no path filter**, so a
  *docs-and-scripts-only* `porting-kit/` change (and every `lsof-rs/` change,
  which already has its own path-scoped CI) kicked off three heavyweight C builds
  and left the PR "unstable" until they drained. Wasted CI, and a merge state that
  reads as broken when it isn't. `mergeable_state: "unstable"` means *pending or
  failing non-required checks* — not necessarily failure.
- **Kit change:** added `paths-ignore: ['porting-kit/**', 'lsof-rs/**']` to the
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
- **Codebase:** lsof-rs — the socket differential, promoted to a hard CI gate (PR #29)
- **What happened:** RETROSPECTIVE §5 / LESSONS #4 named "oracle-substitution" as
  the differential mode the kit *needs* when the C binary won't run on the target
  (no lsof on Windows). This session built it: lsof-rs `-i` socket SET vs
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
- **Codebase:** lsof-rs — the safety-gate PR (#30), caught in CI at `etw.rs`
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
- **Codebase:** lsof-rs — the full-port depth gap analysis (PR #31)
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
- **Codebase:** lsof-rs — the Windows backend, un-buildable on the Linux dev host
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
- **Codebase:** lsof-rs — the live smoke harness (`Invoke-LsofRsSmokeTest.ps1`)
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

---

## 011. The matrix-coverage gate — #8 promoted from a discipline to a control

- **Date:** 2026-07-24
- **Codebase:** lsof-rs / lsof — closing the "next target" named by LESSONS #8
  and RETROSPECTIVE §10
- **What happened:** #8 established that a green differential over an incomplete
  matrix is silent about everything the matrix omits, and left the fix as a
  *discipline* ("enumerate the C's feature surface and give each a case") — the
  same kind of unenforced delegation #3 warned about: a rule nothing checks is
  not a control. The enumeration is mechanically extractable from the C: lsof's
  option surface is one `snpf`-built getopt rules string (every `#if` branch a
  string literal in the same call — the union across build configs falls out of
  scanning the call), and the emitted TYPE universe is `lib/print.c`'s
  `snpf(buf, buf_len, "REG")` switch. If a tool can extract it, a gate can diff
  it against the matrix.
- **Kit change:** new harness `coverage/coverage_gate.py` —
  `--extract-options`/`--extract-types` bootstrap a feature inventory from the C
  (validated against the real tree: 45 option letters, 111 TYPE literals →
  `feature-inventory-lsof.toml`, the worked example); the gate diffs
  inventory-minus-waivers against matrix coverage (option letters inferred from
  each case's `args` incl. short-option clusters; fixture-borne TYPE coverage
  declared per case via `covers = [...]`; every waiver requires a reason) and
  exits 1 on anything uncovered — with the #8 scenario (socket-only matrix,
  un-created `type:KEY`) pinned in its self-test. Wired into `make check-kit`;
  referenced from the matrix header, PLAYBOOK gate 2 + controls table, CLAUDE.md
  gates table, and the oracle skill (step 2).
- **Section amended:** harnesses/coverage/ (new); Makefile · check-kit;
  harnesses/differential/input-matrix.example.toml (header); PLAYBOOK · Phase 4
  gate 2 + cross-cutting controls; CLAUDE.md · gates; skills/porting-kit-oracle.

---

## 012. A coverage gate that over-credits is worse than none — and the inventory must hold the WHOLE surface

- **Date:** 2026-07-25
- **Codebase:** lsof-rs — curating the real inventory and wiring the #011 gate
  into CI (the first real use of the harness)
- **What happened:** Applying the new gate to a real port immediately found two
  design defects in the gate itself — neither visible when it was written against
  fixtures, both obvious the moment it met real data (the #2/#3/#4 pattern again:
  *the findings live where the tool meets the actual codebase*).

  1. **False coverage.** Option coverage was inferred by walking every character
     of an argument token, so a matrix case running `-iTCP:80` credited `opt:T`,
     `opt:C` and `opt:P` — the *value's* characters read as option letters. On
     lsof-rs's real suite that inflated coverage by three options. A coverage
     gate that over-credits doesn't merely mis-measure, it **hides the gaps it
     exists to find** — the same failure mode as #2's noisy scanner, inverted.
     The fix was already in the source data: the C's optstring marks
     value-taking options (`c:` vs `a`), so the extractor now records
     `takes_value` and cluster-scanning stops at the first such option.
  2. **The inventory must be the full surface, not the in-scope subset.** The
     first curation listed only what lsof-rs supports and kept the exclusions
     elsewhere — so every waiver referenced an id not in the inventory and the
     tool's own stale-waiver check fired 118 times. Modelling it the other way
     (inventory = the C's *entire* enumerated surface, waivers *subtract*) makes
     the waiver list a reviewable record of every conscious exclusion, and means
     a feature the C gains later shows up as uncovered instead of never being
     noticed at all. The exclusion list is the artifact worth version-controlling.

  Grouped waivers (`ids = [...]` sharing one reason, explicit enumeration, no
  globs) made a 103-entry dialect exclusion writable without letting a waiver
  silently swallow a future feature.
- **Result on the real port:** 163 features (45 C options + 111 C TYPE codes + 7
  Windows-native), 125 waived with reasons, 38 covered, and **7 genuine gaps**
  found — `-u` shipped but never exercised, and five all-handle object types
  (`EVT`/`MUT`/`SECT`/`PROC`/`TOKN`) that PR #31 taught lsof-rs to emit but that
  no fixture creates. Recorded as an explicit, individually-named *coverage debt*
  section the gate prints every run, so today's debt is visible while everything
  else is hard-gated — a newly dropped feature now fails CI.
- **Kit change:** `coverage_gate.py` gained `takes_value` extraction + value-aware
  cluster scanning (pinned: `-iTCP:80` must not credit T/C/P) and grouped `ids`
  waivers; `emit_inventory` emits `takes_value`; the full-surface-minus-waivers
  model is documented in the harness, the lsof inventory header, and lsof-rs's
  `coverage/README.md`. Gate wired into lsof-rs CI as a hard gate.
- **Section amended:** harnesses/coverage/coverage_gate.py (`_optstring_letters`,
  `extract_options`, `matrix_coverage`, `load_inventory`, self-test);
  harnesses/coverage/feature-inventory-lsof.toml; lsof-rs/coverage/ (new);
  .github/workflows/lsof-rs-ci.yml (core-linux).

---

## 013. The smoke-harness arc — observe-first, run end to end (PRs #36–#39)

- **Date:** 2026-07-25
- **Codebase:** lsof-rs — wiring the 55-case live smoke harness into CI,
  fixing what its first run found, and promoting it to a hard gate
- **What happened:** The coverage matrix (#012) credited three test sources,
  but CI executed only two — the smoke harness, source of most declared cases,
  was manual-only. Wiring it in observe-first (the #9 pattern) and driving it
  to enforcement produced four distinct lessons:

  1. **A cited test source must itself run in CI.** Coverage backed by a
     harness nobody executes is the #8 silent gap one layer up: the gate said
     "covered", the covering test never ran. Every source the matrix credits is
     now executed *and* enforced.
     → *Section amended:* input-matrix header ("a case may only cite a test CI
     executes"); lsof-rs/coverage/README.md.

  2. **The CI runner is yet another host — including its *runtime versions*.**
     The first hosted run failed 2/55 for host reasons no dev box showed:
     hosted `%TEMP%` is an 8.3 short name (`C:\Users\RUNNER~1\...`), which
     defeated lsof-rs's literal path-selector matching — a *real product bug*
     (fixed: selectors are canonicalized to the long form the backend reports);
     and the `-o` fixture seeked via .NET `FileStream`, whose .NET 6+
     implementation does positional I/O and never moves the kernel file
     pointer the product actually reads — green under PS 5.1 locally, red on
     pwsh CI, and *the product was right, the fixture was wrong*. Establish
     fixture ground truth at the layer the tool reads it (the fixture now sets
     the kernel position via `SetFilePointerEx`, idempotent under PS 5.1).
     → *Section amended:* PLAYBOOK · Phase 2 "harden the harness for its host".

  3. **While a gate observes, job status is meaningless.** `continue-on-error`
     shows a green job over a failing step, so the observe phase must read the
     step's own log or artifact (`if: always()` upload) — a verdict inferred
     from the job conclusion is theater. Both failures and both later green
     runs were log-verified, never status-inferred.
     → *Section amended:* PLAYBOOK · cross-cutting (CI-only gates, trap c).

  4. **Promote in the gate's own PR.** The bar was consecutive log-verified
     green runs (PR #37's run + the post-merge master run); the flag flip then
     went in its own PR, so the newly-hard gate had to pass on the promotion PR
     itself before merging — the promotion validated by the mechanism it
     enables. Observe-first earned its keep in numbers: promoted on day one,
     the two findings would have broken master; observed, they cost zero red
     builds and yielded one product fix plus one fixture fix.
     → *Section amended:* PLAYBOOK · cross-cutting (promotion mechanics).

  Hygiene coda: workflow-file edits made in this arc (#36/#38) each launched
  the three heavyweight C builds — `build.yml` ignored the lsof-rs *trees* but
  not the lsof-rs *workflow files*; #005's scoping rule extended to them (#39).
- **Kit change:** the PLAYBOOK and matrix-header edits above; the lsof-rs
  fixes themselves live in the port (selector canonicalization + unit tests;
  kernel-pointer fixture; hard-gated smoke step in lsof-rs-ci.yml).
- **Section amended:** PLAYBOOK · Phase 2 + cross-cutting;
  harnesses/differential/input-matrix.example.toml (header);
  .github/workflows/build.yml (`paths-ignore`).

---

## 014. Release mechanics are part of the environment — preflight them like the toolchain

- **Date:** 2026-07-25
- **Codebase:** lsof-rs — cutting v0.3.0 (PRs #41–#42 + the `winlsof-v0.3.0`
  tag/release) from an automated remote session
- **What happened:** Every *code* gate was green and the release commit was
  merged — and then the release stalled on mechanics no gate had ever checked.
  The session's git identity could push branches but **not tags** (proxy 403,
  policy), and its API credential lacked `actions: write`, so
  `workflow_dispatch` was also 403. Both walls were discovered *at release
  time*, the worst moment. Two designed-in properties saved the cut:

  1. **The release workflow had a human-button fallback.** It triggers on a
     tag push *or* `workflow_dispatch` with a tag input — and on dispatch,
     `gh release create --target $GITHUB_SHA` creates the tag server-side, so
     no local git is needed at all. One human click shipped v0.3.0 targeted at
     exactly the intended commit. A tag-push-only workflow would have left the
     release hostage to the sandbox's permissions.
  2. **Public pages are a quota-free oracle.** The same day, the session
     exhausted the user's hourly API quota (a ~55-minute stall on one PR
     merge, cleared by escalating backoff — never by hammering). While the API
     was dark, the *public* release page verified the shipped release (assets,
     target SHA, checksum) and the PR's state — reads that consume no quota
     and, for a release, prove what users actually see rather than what the
     API says.

  A sequencing footnote: the release run raced the action-version bump PR and
  so printed one last `checkout@v4` deprecation warning — harmless, but a
  reminder that a release consumes whatever workflow is on the default branch
  at fire time, not what is merged a minute later.
- **Kit change:** PLAYBOOK Phase 3's environment preflight now includes
  release credentials (can this identity push a tag / dispatch a workflow /
  create a release?) — a ten-second check that belongs next to "does the
  linker work"; Phase 5 gained the human-button-fallback rule, the
  verify-from-the-public-page step, and the API-quota-as-budget note for long
  automated sessions.
- **Section amended:** PLAYBOOK · Phase 3 (environment preflight) + Phase 5
  (release mechanics).

## 015. Hosted CI cannot see real hardware — the field checkpoint is a gate, not a formality

- **Date:** 2026-08-30
- **Codebase:** lsof-rs — v1.0.0 → v1.0.1, the same day
- **What happened:** Every automated gate was green on the 1.0.0 artifact —
  differential, coverage, unsafe audit, fuzz, supply chain, 59-case smoke on
  `windows-latest`. The release's own exit criterion 5 (run the *downloaded*
  artifact on real hardware in both privilege modes) then failed one case:
  `plus-D-directory-tree` took **214 s** elevated. Root cause was a
  `2 s × process-count` serial wait in the per-process extras phase, present
  since Phase 4 and invisible on hosted runners, whose process set is small and
  idle. Not a 1.0 regression; v0.4.0 had passed the same case on timing. The
  fix (concurrent workers under one global budget) had its own defect — a 20 s
  budget where the old bound was 2 s — caught pre-merge by asking what the
  number *replaced* and sizing it against that.
- **Kit change:** Phase 5 gains a required **field checkpoint**: the exact
  release artifact, real target hardware, every privilege mode, a per-case time
  ceiling, results logged in the release doc with the verdict. The playbook now
  says outright that a hosted runner cannot substitute for it.
- **Section amended:** PLAYBOOK · Phase 5.

## 016. Calendar time is not a measurement — write exit criteria in the unit you mean

- **Date:** 2026-08-30
- **Codebase:** lsof-rs — road-to-1.0 exit criterion 4
- **What happened:** The criterion read "14 consecutive green nightly deep-fuzz
  runs". Asked why 1.0 had to wait, no answer survived: the nightly had already
  done 200M+ executions, corpus growth had flattened to +6 %, coverage sat at
  `cov: 1125 / ft: 6790`, zero findings. Elapsed days were a proxy for fuzzing
  effort, and a bad one — the same 14 nights on a faster runner would have
  meant more work, on a broken cron none. Rewritten as the quantities it had
  meant: cumulative effort, coverage plateau, corpus saturation, zero findings.
- **Kit change:** Phase 5's cutover criteria state that any time-based gate
  must name the *measurement* the time stands in for and gate on that instead.
- **Section amended:** PLAYBOOK · Phase 5.

## 017. A second platform where the reference runs is an oracle for every line of shared code

- **Date:** 2026-09-01
- **Codebase:** lsof-rs — Linux backend L0/L1, diffed against C lsof 4.95.0 on
  the same host
- **What happened:** The Windows port had never had a same-host reference
  (Phase 2's oracle-substitution mode). The Linux backend did, and its first
  side-by-side runs found: the DEVICE/NODE cells are filled differently per
  socket family (inode+protocol for inet, kernel-pointer+inode for AF_UNIX);
  `-U` had *never been enforced* in `lsof-core` (declared, never read — the
  Windows ETW path happened to yield only AF_UNIX rows, hiding it); a listening
  AF_UNIX socket is identified by `SO_ACCEPTCON`, not its state column; and
  **three renderer divergences that had shipped in every Windows release since
  v0.2.0** (the `-T` suffix shape, `-Tq` semantics, `COMMAND` width). The Linux
  differential found Windows bugs. None of these was visible to golden tests,
  because a golden test pins what its author believed the C emits.
- **Kit change:** Phase 2 gains the **asymmetric-oracle** case: when a port
  targets several platforms and the reference runs on any of them, that
  platform's C-vs-Rust diff is the oracle for all shared code — build it before
  the second backend's first phase, and treat every finding as cross-platform
  until proven backend-local. The scope doc for the Linux backend had said
  exactly this ("start L3's harness immediately after L0") and it was not
  done; the findings above came from diffs run by hand.
- **Section amended:** PLAYBOOK · Phase 2 (oracle) + Phase 4 step 2.

## 018. A waiver whose reason names a platform expires the day you add that platform — silently

- **Date:** 2026-09-01
- **Codebase:** lsof-rs — coverage inventory, 118 waivers
- **What happened:** Roughly half the waivers read "Unix-only" or "no Windows
  equivalent". True when written. The day the Linux backend merged they became
  false, and **nothing in the file changed**, so the gate stayed green while
  excusing `-Z` (SELinux), `-X` (epoll), the mount-table options and every Unix
  socket family on a port that now targeted Linux. Two were wrong on the day:
  `type:BLK` and `type:FIFO`, waived as having no Windows analogue while the
  Linux backend already emitted both. Once scoped, the Linux run demanded
  `type:LINK`, which the code mapped and **no test asserted** — the assertion
  went in before the coverage claim.
- **Kit change:** `coverage_gate.py` takes `--platform`; a `[[waive]]` may carry
  `platforms = [...]` and stops applying to any platform it does not name.
  Waivers without the list apply everywhere, so single-platform ports are
  unaffected. CI runs the gate once per platform. Seven self-test cases,
  including the real shape of the failure (one inventory, green on `windows`,
  red on `linux`). Linux-side gaps are recorded as `DEBT (Lx)` naming the phase
  that closes them, not re-waived — a waiver claims "never", which was untrue.
- **Section amended:** PLAYBOOK · cross-cutting controls (coverage row) +
  Phase 4 step 2.

## 019. A control the kit asserts but never checks for does not exist — the three missing ledgers

- **Date:** 2026-09-02 (found at retrospective step 0)
- **Codebase:** lsof-rs — after 21 PRs and three releases
- **What happened:** Running every harness against the real tree, as the
  retrospective prompt requires, showed that three artifacts the playbook names
  as exit criteria had **never been created**: `progress.json` (CLAUDE.md "keep
  current"; Phase 4 step 6), `DIVERGENCES.md` (Phase 2 exit; Phase 5 "ship as
  release notes"), and a fuzz target per parse module (Phase 4 step 3 — one
  target exists, `parse_args`; the Linux backend's seven `/proc` text parsers
  have none). The C-flaw scan's own output ends "Triage each… record in
  DIVERGENCES.md" — 127 findings, none triaged. The sanitizer row of the control
  table says "CI"; the port's CI has zero sanitizer mentions. 1.0 shipped
  without any of them, and every gate was green, because no gate looks for
  them. Reading the playbook did not surface this; executing the tools did.
- **Kit change:** `harnesses/ledgers/check_ledgers.py` — a port-side presence
  check for the mandated ledgers (progress file, divergence ledger, ≥1 fuzz
  target, sanitizer job in CI), exit 1 on any absence, with a `--allow` list
  for a documented waiver. Wired into `check-kit`'s self-test and named in
  Phase 3's exit criteria and the CI template, so the assertion becomes a
  failing build.
- **Section amended:** PLAYBOOK · Phase 3 (exit criteria) + cross-cutting
  controls; `harnesses/ci/porting-ci.template.yml`.

## 020. Renaming a project: three passes, because each method finds what the others cannot

- **Date:** 2026-09-01
- **Codebase:** lsof-rs — `winlsof` → `lsof-rs`, 92 files, 73 detected renames
- **What happened:** Pass 1 (do it) missed `Invoke-WinlsofSmokeTest.ps1`
  because `find -name` is case-sensitive. Pass 2 (verify by *executing*, per
  category) found three: a bare `winlsof` used as a Python variable became
  `lsof-rs` and did not parse; CI invoked a script filename that did not yet
  exist; `Add-Type -Namespace Lsof-rsNative` — a .NET namespace cannot contain
  a hyphen — from the PascalCase rule. Pass 3 (adversarial) found the worst:
  the regex protecting published tag names guarded only the *left* side of each
  CHANGELOG compare URL, leaving six dead links. Three things were deliberately
  kept: the six published `winlsof-v*` tags (release trigger now fires on both
  prefixes), `WINLSOF_TRACE` as a live alias, and historical entries — a v1.0.1
  binary only knows the old variable, so telling its reader otherwise is false.
- **Kit change:** PLAYBOOK gains a rename procedure under cross-cutting
  controls: inventory case-insensitively; convert by identifier context
  (SCREAMING/snake/kebab/Pascal), never one rule; protect published tags and
  verify every tag named against the remote; alias user-facing env vars; then
  three passes — mechanical, execute-every-script, adversarial — and a
  self-referential check that the CI path filters still select a code-only
  change.
- **Section amended:** PLAYBOOK · cross-cutting controls (new "Renaming the
  port" subsection).

## 021. The second backend is a new port loop — fuzz its parsers, or Phase 4 step 3 was skipped

- **Date:** 2026-09-02
- **Codebase:** lsof-rs — `lsof-backend-linux`, 1,201 lines, 19 tests
- **What happened:** The Linux backend parses kernel-supplied text: seven
  functions over `/proc/net/*` lines, `/proc/<pid>/status`, fdinfo `flags:`.
  The `Name:` field is attacker-influenced (`prctl(PR_SET_NAME)`), and the
  `/proc/net/unix` path column can contain spaces and arbitrary bytes. Phase 4
  step 3 says fuzz the module's parse surface; it was applied to the Windows
  port's argument parser and to nothing in the second backend. The backend is
  `#![forbid(unsafe_code)]`, so the risk is panic/DoS rather than memory
  safety — but a panic on a hostile `/proc` line is still a release blocker
  under the kit's own rule, and no gate asked.
- **Kit change:** `PROMPTS/20-new-backend.md` — the second-platform prompt —
  makes the six-gate loop explicit *per backend crate*, with "one fuzz target
  per text-parsing module" as an entry to its step 3, and `check_ledgers.py`
  counts fuzz targets. ARCHITECTURE-TEMPLATE now describes one backend crate
  per platform and says a backend may itself be `forbid(unsafe_code)`.
- **Section amended:** ARCHITECTURE-TEMPLATE · "If your port is
  cross-platform"; new PROMPTS/20-new-backend.md.
- **Follow-up, 2026-09-13 — the gate this entry added does not check what the
  entry is about.** `check_ledgers.py` *counts* fuzz targets. lsof-rs has nine,
  so the ledger reads `present` and has done since the day this lesson landed —
  while `lsof-backend-windows`, the crate the six-gate loop is supposed to apply
  to in its own right, has **no** fuzz target at all and exposes no `fuzz_api`
  to write one against. All nine targets cover the Linux backend, the CLI and
  the core. The Windows backend does parse OS-supplied text (device paths to
  drive letters, `\\?\` verbatim prefixes, `\Device\…` normalisation,
  kernel object type names to lsof's codes), so the rule plainly reaches it.
  Counting artifacts is not covering the thing they are artifacts *of* — the
  same shape as LESSONS #019's "declared but never run", one level up. A gate
  for a per-unit rule has to be per-unit: the check should map each crate that
  parses external text to at least one target, and a port should have to waive
  a crate by name to leave it uncovered.

  **Closed the same day.** The obstacle was never difficulty — it was that the
  parsers sat inside `#[cfg(windows)]` while the fuzz job runs on Linux, so
  nobody could have written the target without moving them first. They are pure
  string transforms; hoisting them into an ungated `names` module took an hour,
  the target found two bugs *in its own assertions* within a minute, and the
  crate's unit tests went from running on one platform to running on all of
  them. When a per-unit gate has been unmet for months, check whether the unit
  is simply unreachable from where the gate runs before concluding the work is
  large.
- **Follow-up closed, 2026-09-20, for the sanitizer half.** `check_ledgers.py`
  grew a fifth ledger, `san-crates`: every unit `progress.json` tracks must be
  NAMED by a CI step that runs a sanitizer. It is per *step* rather than per
  job, because a cache-warming `cargo build -p x` added to a sanitizer job
  would otherwise mark `x` sanitized, and it requires a command that BEGINS
  with `cargo`, because an `echo` naming the command is not the command. Run
  against this repository before the matching CI step existed, it fails and
  names `lsof-backend-linux` — while the older `sanitizers` ledger stays green,
  which is the whole point.

  Two things worth carrying:

  **The narrowing rules were found by mutating the check, not by review.** The
  first version accepted `echo "would run -p x under miri"`; the second, which
  only asked whether the line contained "cargo", accepted
  `echo "would run cargo miri test -p a"` — and it was this file's own new
  self-test case that caught it, one commit after LESSONS #31 removed exactly
  that defect from the sibling check. Writing the assertion first and the rule
  second is what made the difference.

  **One mutation still passes and is recorded in the docstring rather than
  hidden:** swapping a step's `cargo miri test -p x` for `cargo build -p x`
  while leaving the step's miri configuration in place still reads as covered.
  No textual rule separates those; settling it needs the job's log, which is a
  different control from a presence ledger. The fuzz half of this follow-up —
  mapping each text-parsing crate to a target — is still open.

**Follow-up, 2026-09-20:** landing that miri arm broke the hard gate it was added beside — an observe-first STEP cannot be observe-first inside a gated job. See **LESSONS #055**.

## 022. Release mechanics II — a workflow that can fire twice will publish two truths

- **Date:** 2026-08-30
- **Codebase:** lsof-rs — v1.0.1 release
- **What happened:** Two dispatches of the release workflow raced. The release
  notes carried one SHA-256 (`9289af7a…`) and the uploaded asset another
  (`0d884147…`). Nothing failed; a user verifying the download would have
  concluded the binary was tampered with. #014 had covered release
  *credentials*; it had not covered release *concurrency*. Fixed with a
  `concurrency` group keyed on the tag and by writing the notes from the same
  run that uploads the asset (`gh release edit --notes`), so there is one
  source of truth per release. The user deleted the bad release; it was re-cut
  once.
- **Kit change:** Phase 5 release mechanics: the release workflow declares a
  `concurrency` group; checksum and notes are produced by the run that uploads
  the asset, never by a second run; verify from the public page that the
  published checksum matches the published asset before announcing.
- **Section amended:** PLAYBOOK · Phase 5 (release mechanics).

## 023. Feed the oracle hostile input — it finds the C's bugs, and it is the only thing that will

- **Date:** 2026-09-04
- **Codebase:** lsof-rs — closing DIVERGENCES.md #10 (control characters in
  COMMAND/NAME printed raw)
- **What happened:** The fix was a port of the C's `safestrprt()`, so the
  differential got fixtures whose comm and file name hold one of every
  character class it escapes (ESC sequence, CR, space, backslash, DEL, TAB,
  `^A`, é, U+009B). Five of the six new cases matched byte for byte. The sixth
  showed the *C* dropping the end of a command even under `+c 0`: `safestrlen()`
  compares a `char` with `0x20`, `char` is signed on x86-64, so every byte
  ≥ 0x80 is sized as 2 columns while the printer emits 4, and the printer then
  truncates to the undersized width. Reading the source had not caught it —
  the two functions look consistent — and `scan_c_flaws.py` has no pattern
  for it. Only running the C on the hostile bytes did. Ledgered as a new entry
  kind, `C-DEFECT`, that the port deliberately does not reproduce (prime
  directive: the C is a specification that may be buggy). Three smaller
  things fell out of the same run, none visible from the source: the C prints
  COMMAND and NAME through *different* functions with different Unicode rules
  (`safestrprtn()` has no wide-char path); `-F` emits the `f` marker only when
  selected; and the fuzz target written to guard the fix had an over-strong
  invariant that the fuzzer disproved in seconds — the second time in two
  days a target, not the code, was what was wrong (#021's `proc_status` was
  the first).
- **Kit change:** (1) When a port closes a divergence by copying the C's
  behavior, add fixtures that exercise the *hostile* input the behavior exists
  for, not just the well-formed case — the C's own bugs live there, and a
  well-formed fixture will match a buggy C. (2) `DIVERGENCES.md` gets a third
  entry kind, `C-DEFECT`, naming the C code, so a permanent DIVERGE reads as a
  triaged finding and not as noise. (3) Candidate `scan_c_flaws.py` rule,
  `signed-char-compare`: a `char` lvalue or `*p` over `char *` compared with a
  numeric literal without an `(unsigned char)` cast. (4) A fuzz target's
  assertions are code under test too: when one fires, first ask whether the
  invariant is right — **three times now the answer was no** — and when it is
  fixed, write down the input that broke it. And re-run every target whose
  module's *contract* the change touched, not only the new one: one PR changed
  what `parse_status` returns (it now decodes the kernel's `\n`), ran only the
  new `render_escape` target locally, and CI's 45-second smoke of `proc_status`
  found its "no newline" invariant stale on the first run.

  **The shape of all three wrong invariants is the same, and it is worth
  naming: each was a *stronger proxy* that happens to hold for kernel-shaped
  input.** "The command holds no `\r`" (the kernel escapes only `\n`).
  "A truncated cell never ends in `^`" (`\n\x1e` escapes to `\n^^`). "The
  name never starts with `anon_inode:`" (the kind of `anon_inode:anon_inode:3`
  legitimately does). Each is easy to write, reads as obviously true, and is
  true of every input the kernel will ever produce — which is exactly why only
  a fuzzer finds it. Write the property the code actually promises: not "the
  result never looks like X" but "the result is the escaped form of the longest
  prefix that fits", "exactly one prefix is dropped". If the precise property
  is hard to state, that is a signal about the code, not a licence to assert a
  convenient approximation.
- **Section amended:** lsof-rs `DIVERGENCES.md` (the `C-DEFECT` kind);
  PLAYBOOK Phase 2/4 candidates for the next kit retrospective, recorded here
  so they are not lost.

## 024. Sweep the option's whole surface — the shape of the output is the contract, not just its content

- **Date:** 2026-09-05
- **Codebase:** lsof-rs — closing DIVERGENCES.md items 5 and 11 (the `-F`
  machine-readable field set)
- **What happened:** The plan was "add the six missing `-F` fields". Instead of
  reading `print.c` and implementing what it says, the session ran a sweep:
  every field letter, several combinations, and `-F0`, against the C oracle on
  a fixture holding a locked file, a directory fd, a TCP listener, a UDP
  socket, an AF_UNIX socket, a pipe, an eventfd, a deleted file and a character
  device. **26 of 62 cases diverged**, and only two of the eight root causes
  were the ones the plan named.

  The other six were all about the *shape* of the stream, and every one of them
  would have survived a careful read of the C:

  * The field **order** was wrong — the `T` tokens belong after `n`, because
    `print.c` calls `print_tcptpi()` once `printname()` has run. Reading the
    function top to bottom shows this; reading it looking for "which fields
    exist" does not.
  * `-F0` **replaced** the last field's NUL with the set-closing newline
    instead of appending it. The C emits `\0` then `\n`. A consumer splitting
    the stream on NUL — the whole reason `-F0` exists — got one set's last
    field glued to the next set's first. The port's own golden test asserted
    the wrong rule in so many words ("the last field of a set is
    NL-terminated, NOT NUL"), which is #019 again: a golden test pins what its
    author believed.
  * `i` and `P` are **one cell under two names**, chosen by a single
    discriminant. Implementing them as two independent fields gave AF_UNIX rows
    both a `P` they should not have and no `i` they should.
  * An AF_UNIX socket's **state was baked into its NAME**, so `-F` reported it
    in two fields at once — and, on the other backend, twice in the same table
    cell.
  * Selecting a field can have a **side effect on collection**: the C's field
    table (`store.c`) gives `T` the entry `&Ftcptpi, TCPTPI_ALL`, which is why
    bare `-F` prints `TQR=`/`TQS=` with no `-T` at all. Nothing in `print.c`
    hints at this; it is a data table three files away.
  * Two **backend** bugs surfaced only because `-F` names each value
    separately: a common AF_UNIX state was missing entirely, and UDP carried
    neither its queues nor its state. Both were invisible in the table, where
    a missing parenthesised suffix reads as "this socket has no state".
- **Kit change:** (1) For an option with an enumerable surface — a field list,
  a format letter set, a sub-flag set — **sweep it against the oracle** rather
  than implementing from the source. Cost here: one ~60-line script, one
  minute per run. Yield: six findings that reading would not have produced.
  (2) The fixture must hold **one row of every shape the option can render**,
  not one row. Half the findings needed the AF_UNIX or UDP row specifically;
  the first fixture had only a TCP socket and matched after two fixes.
  (3) When the port's model splits a value the C keeps in one place (or joins
  two the C keeps apart), that is where the divergences cluster — the C's
  `inp_ty` and `Lf->lts` were each one cell that the port had modelled as two
  and as part of the name.
  (4) `cargo test --workspace` does **not** build `fuzz/`, so a model change
  silently rots the fuzz targets; a target that no longer compiles is a target
  that is not running. Add `cargo fuzz build` to the local verification sweep,
  not only to CI. (Here `parse_status` had grown from a tuple into a struct and
  `proc_status.rs` had not compiled since — caught locally only because the
  sweep ran every target by hand.)

## 025. Triage the flaw scan early — its findings are mostly about the scanner

- **Date:** 2026-09-07
- **Codebase:** lsof-rs — closing the "127 findings, UNTRIAGED" entry that had
  stood through three releases (LESSONS #019 found the absence)
- **What happened:** The kit's rule is that every `scan_c_flaws.py` finding is
  triaged into `DIVERGENCES.md` as "closed by the port" or "not applicable".
  Doing it finally, on a 224-finding run, produced **no exploitable finding in
  the code the port mirrors** — and two defects in the scanner.

  The triage itself was mostly a *reachability* question, and that is the part
  worth generalising. Of 224 findings, 128 were in code this port can never
  execute: 98 in dialects it has no backend for, 30 in portable `lib/` files
  that compile to **empty** in this configuration, 2 in test programs. The
  30 were the interesting ones, because "portable `lib/`" reads like in-scope.
  They were settled by measurement, not by reading `#ifdef`s: `lsof-rnam.o` and
  its four siblings are 3.5 KB with **2 defined symbols** against `lsof-misc.o`'s
  113 KB and 32. An object-size-and-symbol-count check answers "is this code
  even built?" in one command, and no amount of `#if` reading is as convincing.

  Of the 94 live findings, the categories collapsed under inspection:
  `int-overflow-mul` had **zero** with runtime size math (25 were the regex
  matching the `*` in a `(MALLOC_P *)` cast, 14 were `calloc(CONST, sizeof(T))`);
  `toctou` had 20 of 47 matching `stat(2)` inside a **trailing comment**;
  `format-string` had 2 of 4 matching macros that expand to literals. Four
  `unbounded-copy` hits were read line by line and were all allocate-then-copy
  or an explicit reservation.
- **Kit change:** (1) `scan_c_flaws.py` now blanks comments before matching, not
  just skipping comment-only lines. A trailing `/* … stat(2) … */` is the single
  largest noise source in real C, and it took this tree's toctou count from 97 to
  65. (2) A new **`signed-char-compare`** rule (CWE-195), the one LESSONS #023
  said was missing: it collects the identifiers declared `char` in a file and
  flags comparisons of them — or of a deref of them — against a numeric literal
  with no `(unsigned char)` cast. On lsof it finds three, and the first is the
  exact `safestrlen()` defect a hand-run differential had found and the scanner
  had missed. A scanner that misses the bug the porter found by hand has a hole
  in it, and the fix belongs in the kit, not in one port's notes.
  (3) Both are pinned by `--self-test` cases, including the negatives: an
  `(unsigned char)` cast is not flagged, a struct field sharing a `char`
  variable's name is not flagged, and `stat(2)` in a comment is not flagged.
  (4) **Triage the scan at Phase 0, as the playbook says, not at release three.**
  Not because the findings were urgent — none was — but because the exercise's
  real output is a calibrated scanner, and calibrating it after the port is
  written means every hit is re-litigated against code that has already shipped.
  The rule the scan was missing would have flagged, before a line of Rust was
  written, the defect that later cost a differential round to find.
- **Section amended:** lsof-rs `DIVERGENCES.md` (the scan section is now a
  triage table); `porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py`.

## 026. A test that passes for the wrong reason is worse than no test — mutate the ones you just wrote

- **Date:** 2026-09-07
- **Codebase:** lsof-rs — closing DIVERGENCES.md item 18 (thread listing, `-K`)
- **What happened:** Seven differential cases were written for `-K` and all
  seven passed on the first run. Six were real. The seventh,
  `tasks-dash-K-rejects-other-arguments` (`lsof -K x`), was measuring nothing:
  the C rejects `x` as `-K`'s argument and exits 1, while the port did not
  consume `x` at all, treated it as a *filename*, found no match, and also
  exited 1 with no output. Same exit code, same empty stdout, MATCH — for
  opposite reasons.

  It surfaced only under a mutant that made `-K` accept any argument silently.
  That mutant should have killed the case; it did not, which is the signal.
  Chasing why produced the real bug: the C's `-K` takes the next word
  **whatever it is**, pushing it back only when it opens an option, so
  `lsof -K /var/log` is a usage error — and the port had been turning it into a
  bare `-K` plus a name, printing a whole-host thread listing where the C prints
  nothing. A one-character argument could never have shown that; a path could.
  The same mutant round found a second bug (`strcasecmp`, so `-K I` is `-K i`).

- **Why it matters:** The failure mode is specific and common. When a case's
  expected outcome is *silence* — an error exit, an empty listing, a suppressed
  column — there are usually several ways to be silent, and only one of them is
  the behavior under test. Differential harnesses compare stdout and an exit
  code; two wrong implementations agree on both far more often than they agree
  on a populated table. So the cases most likely to be hollow are exactly the
  negative ones the porter adds for completeness.

  The mutant is what tells them apart, and it costs one build. The discipline is
  not "mutation-test the codebase" — it is: **for each case you just wrote, name
  the change it is supposed to catch, make that change, and confirm it goes
  red.** A case no mutant kills is a comment.

- **Kit change:** `PLAYBOOK.md` Phase 3 — when adding differential cases, record
  a kill table alongside them: one row per case, naming the mutant that turns it
  red. A case with an empty row is not done. The lsof-rs ledger now carries one
  for the `-K` work; two of its ten mutants killed cases that had been passing
  accidentally, which is a 25% hollow rate on cases written by someone who was
  trying to be careful.

  The same applies to the **fixture**, not just the case. That work's first
  multi-threaded fixture named both threads `worker1`/`worker2` — seven
  characters, which is exactly what the neighbouring `COMMAND` column sizes to.
  A renderer bug that cut the new column against the wrong width therefore
  printed the right seven characters, and three cases written specifically to
  measure column width measured nothing. Make a fixture's values **lopsided and
  distinguishable from their neighbours'**: if two columns can be confused, no
  value common to both can tell them apart.

  And it applies to the **marker you assert on**. The same work's Windows smoke
  case asserted that `-K` output contains `THRD` — but a thread HANDLE is an
  ordinary handle-table entry that the all-handle scan types `THRD` as well, so
  the case passed with the feature deleted, and two new cases asserting the
  ABSENCE of `THRD` failed with it working. A marker shared with something the
  feature does not control is not evidence of the feature. Pick one the feature
  alone produces (here the FD cell `task`), and where the marker lives on a
  platform your CI cannot exercise, pin it with a portable test that renders
  both shapes side by side.

  The fourth instance was a **fuzz target's own assertion**, and it is the
  sharpest: `proc_maps` asserted that no parsed path ends with ` (deleted)`,
  and its header comment two screens above said, correctly, that "a name a user
  controls can therefore end in that exact string". The assertion accused a
  parser that was matching the C exactly. A fuzz target is code that has never
  been reviewed against the oracle, so its invariants deserve the same "what
  would a real input look like?" scrutiny as the parser's — and when one fires,
  suspect the assertion before the code. Fuzz invariants belong at the level the
  module actually promises (no panic, no invention, a flag that pairs with a
  transformation); an exact-value claim belongs in a unit test, where it can be
  written down next to the measurement that justifies it.

  A fifth instance arrived from **miri**, on a unit test written the same day
  this entry was: it asserted that a stripped errno message never *contains*
  `os error`. Miri's `strerror` shim already ends the message with
  `(os error 2)`, `Display` appends a second, and the function's actual rule —
  strip exactly one, never greedily — correctly leaves one behind. Note the
  shape: this is the `/proc/maps` ` (deleted) (deleted)` case again, in another
  file, written by someone who had just finished writing that one up. Knowing
  the pattern is not the same as applying it, so make the check mechanical:
  **when an assertion says "never contains X", ask what legitimate input
  contains X** — and prefer pinning a transformation with constructed inputs
  over asserting an absolute about a live one.
- **Section amended:** `porting-kit/PLAYBOOK.md` (Phase 3, differential cases);
  lsof-rs `DIVERGENCES.md` (the `-K` section carries the kill table).

---

## 027. Reachability is a build result, not a search result

- **Date:** 2026-09-16
- **Codebase:** lsof-rs (C `lsof` → Rust) — repository hygiene pass, PR #81
- **What happened:** A side quest removed 128 files / 31,088 lines of inherited C
  and vendor tooling from the port's repository. The deletions were chosen by
  compiling the tree, and that choice is the whole lesson: **two candidates that
  every reference search called dead were load-bearing, and both were caught only
  by deleting them and running the build.**

  1. **`tests/{Makefile,TestDB,CkTestDB}`** look exactly like the pre-autotools
     harness the project migrated off. They are live, because two test cases
     invoke them as `cd tests && make`. That reference contains no filename —
     it is a directory change plus `make`'s implicit default — so **no textual
     search for `tests/Makefile` can find it**, and the file's own content gives
     no hint it is a target. Deleting them turned `case-14-classic-opt` red on
     the legacy path.
  2. **`lib/ptti.c` is 0 bytes.** Every content-based "is this used?" heuristic
     says dead. It is named three times in `lib/Makefile.skel`, a template the
     legacy generator consumes, so removing it broke the build with
     `No rule to make target 'ptti.c'`.

  The inverse trap sits right next to it: **`AUTHORS` and `NEWS` are also 0 bytes
  and are mandatory.** `AM_INIT_AUTOMAKE` carries no `foreign`, so gnu strictness
  applies and `autoreconf` fails with `required file './AUTHORS' not found`.
  Zero bytes is evidence of nothing in either direction.

  What made the local result *interpretable* was running an untouched control of
  the same commit alongside. `make check` failed 2 of 41 cases on the trimmed
  tree — meaningless on its own, and exonerating once the control failed the
  identical two. CI later passed all 41 on clean runners, confirming both as
  container artifacts.

  One more, about proof standards: an earlier draft of this pass shipped a
  **"residual risk — `make check` could not be evaluated here, CI must close it"**
  note, because the container lacked `soelim`. Closing it cost one
  `apt-get install groff-base`. **A gate you cannot run locally is often one
  package away; reach for the package before writing the caveat.**

  Measured outcome, for honesty about what a deletion buys: the kit's own
  `scan_c_flaws.py` over the C tree went **195 → 172 potential flaw sites**
  (−20 `int-overflow-mul`, −3 `toctou`), all inside the removed dialects. That is
  a reduction in review and maintenance surface, **not** a security fix — the
  code was never compiled by any build in the repo, so none of those sites was
  ever reachable. Say which one you mean.
- **Kit change:** `PLAYBOOK.md` Phase 2 gains a bullet stating that the oracle
  lives in the tree and reads as legacy, that the boundary is participation
  (*does this build, test or document the oracle or the port?*) rather than
  "C vs Rust", and that the genuinely-dead subset is established by deleting and
  building against an untouched control — not by searching for references.
- **Section amended:** `porting-kit/PLAYBOOK.md` · Phase 2 "Do"

## 028. A checked-in manifest of the tree is a control that inverts

- **Date:** 2026-09-16
- **Codebase:** lsof-rs (C `lsof` → Rust) — repository hygiene pass, PR #81
- **What happened:** The inherited tree carried `00MANIFEST`, a literal listing of
  every file in the distribution, and `Inventory`, a script that walks it and
  reports anything missing. Audited against the tree as it actually stood,
  **223 of `00MANIFEST`'s 280 entries were already dangling** — it still described
  a pre-autotools layout with a `dialects/` directory, root-level `main.c` and
  `arg.c`, and `scripts/*.perl5` filenames that had been renamed to `*.pl`.
  Running `./Inventory` on untouched `master` printed:

      +  SOME FILES OR DIRECTORIES MAY BE MISSING!  +

  So the repository shipped, for however long since the autotools migration, a
  self-check that could only ever fail. Nothing noticed, because the script is
  interactive and no CI job runs it — and a control nothing runs is
  indistinguishable from one that passes.

  The general shape is worth naming: **a hand-maintained inventory of the tree
  starts as a check and decays into a liar**, and its decay is silent because the
  thing it checks (the file layout) is exactly the thing that changes underneath
  it. This is LESSONS #19 ("a control the kit asserts but never checks for does
  not exist") seen from the other end — there the control was absent, here it was
  present, executable, and inverted. Both are invisible to a green CI board.

  Either generate the manifest from the tree at build time so it cannot drift, or
  delete it and let the build system be the single statement of what the project
  contains. This pass took the second option: `00MANIFEST`, `Inventory` and the
  `.ck00MAN` marker went together, since `Makefile.am`'s `EXTRA_DIST` already
  enumerates what ships.
- **Kit change:** none to a harness — the lesson is a review question, recorded
  here and reachable from Phase 2's new bullet. When a port inherits a
  tree-manifest file, treat it as **drift-prone state, not documentation**: check
  whether anything executes it, and whether it is still true, before trusting or
  preserving it.
- **Section amended:** `porting-kit/LESSONS.md` (this entry); cross-references
  `PLAYBOOK.md` · Phase 2 "Do"

## 029. The kit's own integrity gate was never wired to CI — and it lost a lesson

- **Date:** 2026-09-16
- **Codebase:** lsof-rs (C `lsof` → Rust) — retrospective follow-up to PR #81/#82
- **What happened:** This is the answer to the question
  [`PROMPTS/90-retrospective.md`](PROMPTS/90-retrospective.md) ends with —
  *the single failure that, in hindsight, the kit still would not have
  prevented* — and it is about the kit rather than the port.

  `make -C porting-kit check-kit` is the kit's integrity gate. The
  retrospective skill's own Integrity section instructs every port to run it
  after editing the kit. **No workflow ran it.** `grep -rn "check-kit"
  .github/workflows/` returned nothing. So the kit asserted a control and
  enforced it only by asking people to remember — which is LESSONS #19 ("a
  control the kit asserts but never checks for does not exist") turned on the
  kit itself, and is why that entry keeps recurring in different disguises.

  It had already cost something. Commit `15d7a03`, whose subject is about
  promoting a sanitizer job, also removed two lines from `LESSONS.md`: the
  blank line before entry 022 and **the entry's heading**. The body stayed. Its
  commit message never mentions `LESSONS.md`; the stat reads
  `14 insertions(+), 2 deletions(-)`. The result sat in `master` for three days:
  entry 021's closing sentence ran `…before concluding the work is large.
  Release mechanics II — a workflow that can fire twice will publish two
  truths`, entry 022's body (a v1.0.1 release incident) sat under entry 021 as
  if it were 021's own, entry 021 carried two `- **Date:**` blocks, and
  `PLAYBOOK.md`'s Phase 5 citation `(LESSONS #22)` resolved to nothing. In a
  file whose first rule is **"Append only — never rewrite history."**

  Then PR #82 — a retrospective that edited `PLAYBOOK.md` and `LESSONS.md` —
  merged with **zero checks**, because the one workflow watching
  `porting-kit/` filtered on `harnesses/**` and then excluded `**.md`. A
  markdown-only path through the kit was unguarded end to end.

  Three things this says that are worth carrying:

  1. **A gate's trigger is part of the gate.** `check-kit` worked perfectly the
     whole time; it simply was never invoked. Reviewing whether a control
     exists and whether anything *runs* it are different reviews, and only the
     second one would have caught this.
  2. **Excluding docs from CI assumes docs cannot break.** For a kit whose
     product *is* documents, the markdown exclusion removed exactly the files
     that matter. The new workflow triggers on `porting-kit/**` with no
     extension filter for that reason.
  3. **A check that reads text cannot tell prose from code.** Writing the new
     workflow, its header mentioned the memory-safety tools by name while
     explaining what it was *not* doing, and `check_ledgers.py` — which
     regex-matches those names across workflow files — immediately reported
     that file as the evidence satisfying the memory-safety ledger, for a
     workflow that runs none of them. The names were removed and the evidence
     points back at `lsof-rs-ci.yml`. **The harness's comment-blindness is not
     fixed**, and is the next candidate: a ledger should be satisfied by a job
     that runs the thing, not by any file that says its name.
- **Kit change:** new `.github/workflows/porting-kit.yml` running
  `make -C porting-kit check-kit` on every `porting-kit/**` change including
  markdown, as its own lightweight workflow rather than a job in
  `lsof-rs-ci.yml` (whose Windows / memory-safety / differential matrix must not
  fire on a prose edit). New harness
  `harnesses/lessons/check_lesson_refs.py`, wired into `check-kit`, asserting
  that every prose `LESSONS #NN` citation resolves and that entry numbers are
  unique and contiguous — verified non-vacuous by running it against the
  corrupted `master`, where it reports exactly the two real defects.
- **Section amended:** `.github/workflows/porting-kit.yml` (new);
  `porting-kit/Makefile` · `check-kit`;
  `porting-kit/harnesses/lessons/check_lesson_refs.py` (new)

## 030. Building is not enough if you build the way CI builds

- **Date:** 2026-09-19
- **Codebase:** lsof-rs (C `lsof` → Rust) — the repository cleanup arc, PRs #81–#84 and #86
- **What happened:** LESSONS #27, written four days earlier, says *reachability is
  a build result, not a search result*. I followed it. I deleted the files, ran
  the reference tree's gates against an untouched control, got clean results, and
  **still shipped a broken `./Configure`.**

  The deletion removed three helper scripts (`Inventory`, `Customize`,
  `AFSConfig`) that `Configure` still called behind `exit 1` guards. Every
  verification run used `./Configure -n linux`, because that is what CI runs —
  and `-n` is documented, in the very script being edited, as **"avoid AFS,
  customization, and inventory checks"**. The one build that proved the deletion
  safe was the one build that could not observe the break. `./Configure linux`
  went from rc=0 to rc=1, and that is the invocation `00.README.FIRST` hands a
  new builder.

  The rule this yields is mechanical, which is the point — #27's "run the build"
  was not, and that is why it failed to fire:

  > **A verification run carrying a flag documented as "skip X" proves nothing
  > about removing X.** Enumerate the entry points that *reach* what you
  > removed, and run those. The one CI happens to use is the least informative,
  > because CI's coverage is exactly what was already true before your change.

  Two things generalize past the specific flag.

  **A green board after a deletion is a narrow claim.** It says the deletion did
  not break what CI covers. It says nothing about what CI does not cover, and a
  cleanup's whole purpose is to touch things nobody exercises — so a cleanup is
  precisely the change for which CI's coverage is least representative.

  **Budget for the audit of your own finished work.** This arc ran four passes,
  and each one found the previous one's defect: the cleanup found `00MANIFEST`
  had been lying for months; its retrospective found `check-kit` was never wired
  to CI; acting on that found `LESSONS.md` silently corrupted and then, on the
  new gate's first CI run, a harness fixture whose behaviour depended on which
  `awk` was installed; and auditing the cleanup's own fallout found this
  regression. Every one was invisible to a green board. Each pass looked
  complete and verified when it shipped — including this one's parent, whose PR
  body I wrote myself.

  A smaller corollary, from the same pass: **fixing a script is not finishing
  with it.** The repair that removed those call sites left `Configure`'s own
  `-n` help text advertising "avoid AFS, customization, and inventory checks"
  for another three days, describing two things that no longer existed. The
  thing you edit describes itself, and that description is part of the edit.
- **Kit change:** `PLAYBOOK.md` Phase 2's removal bullet (added by #27) now ends
  with the entry-point rule and the `./Configure -n` worked example, so the
  instruction to "prove every removal with the tree's own gates" carries the
  qualifier that makes it real.
- **Section amended:** `porting-kit/PLAYBOOK.md` · Phase 2 "Do"

## 031. A control that reads text cannot tell a claim from a fact

- **Date:** 2026-09-19
- **Codebase:** lsof-rs (C `lsof` → Rust) — `check_ledgers.py`, the sanitizers ledger
- **What happened:** LESSONS #19 built `check_ledgers.py` so the playbook's
  asserted controls would be *checked* rather than assumed. Its sanitizers
  ledger asks whether CI runs a sanitizer, and answered it by regex-searching
  the raw text of every workflow file.

  Those are different questions, and they came apart the first time something
  pushed on them. A workflow added in PR #83 named the tools in a header
  comment **while explaining that it ran none of them**, and that alone
  satisfied the ledger. Reduced to its essence, this passed:

      name: decoy
      # runs no miri, no asan and no sanitizer of any kind
      jobs:
        n:
          steps:
            - run: echo hi

  A control that reads text cannot distinguish a fact from a claim about a
  fact, or from a denial of one. **Point the check at the position where the
  thing would actually happen** — here, the values a workflow runs or
  configures (`run:`, `env:`, `with:`, `uses:`) rather than its prose. Three
  kinds of text are now excluded: comments; `name:` values, because
  `lsof-rs-ci.yml` really does carry a step called *"ledgers exist (… sanitizer
  job)"*; and bare mapping keys, because a job called `miri:` is a label too.
  Stripping comments alone would have left the weaker two-thirds of the bug.

  **Writing the test found the opposite defect in the same check.** A case
  asserting that `RUSTFLAGS: -Zsanitizer=address` counts as evidence *failed*:
  the pattern was `\b(miri|asan|ubsan|tsan|sanitizer)`, and `\b` cannot match
  between the `Z` and the `s`. The ledger had been structurally blind to the
  canonical way of enabling a sanitizer in Rust — a false negative sitting
  beside the false positive, in a five-token regex, unnoticed since #19. The
  check accepted workflows that ran nothing and would have rejected one that
  ran ASan and nothing else.

  So: **when a control is wrong in one direction, test the other direction in
  the same pass.** The two failures share a cause — a pattern written to be
  *lenient enough to pass the repo it was written in* — and finding one is the
  cheapest moment to look for the other.

  A third, smaller instance turned up while writing this entry, in a control I
  added four days ago. `check_lesson_refs.py` matches `LESSONS\s+#(\d{1,3})`,
  so in a citation list — `(LESSONS #29, #31)` — it validates the first number
  and silently ignores the rest. It reported `0 problems` on a comment citing
  an entry that did not exist. The citation here is written
  `(LESSONS #29; LESSONS #31)` so that both resolve and the check can see both;
  **teaching the checker to read a list is the next candidate**, and is left
  undone rather than folded into a PR about a different harness.
- **Kit change:** `harnesses/ledgers/check_ledgers.py` gains `executable_text()`
  — a stdlib-only, quote-aware scanner that yields the configuring/running
  parts of a workflow — and the sanitizers pattern now matches `-Zsanitizer`.
  Eight self-test cases pin both directions, each one a shape taken from a real
  workflow in this repository.
- **Section amended:** `porting-kit/harnesses/ledgers/check_ledgers.py`

## 032. The tool you scope a fix with can have the defect you are fixing

- **Date:** 2026-09-19
- **Codebase:** lsof-rs (C `lsof` → Rust) — `check_lesson_refs.py`, citation lists
- **What happened:** LESSONS #31 named this as the next candidate: the lesson
  cross-reference checker matched `LESSONS\s+#(\d{1,3})` and stopped, so a
  citation *list* — `(LESSONS #29, #31)` — was validated on its first number
  only. The kit writes citations three ways, and only the first was ever read:

      LESSONS #6, #8    LESSONS #017, #019, #021      a list
      LESSONS #9/#13                                  a list, slashed
      LESSONS #6–#10    LESSONS #017–#021             a RANGE: 6,7,8,9,10

  A range is the sharper case, because the number of entries it claims is not
  the number of `#` tokens it contains: `#017–#021` asserts that five entries
  exist and the checker confirmed one. Across the kit, **19 individual
  citations were invisible to the gate** — a quarter of the 79 it reported.

  The instructive part is how the scope was measured. I enumerated the citation
  shapes with `grep -rnoE`, found ten, and predicted the fix would make 17 more
  citations visible. It made 19. The two I missed were a range written

      ... the kit's three post-ship dry-runs (LESSONS
         #2–#4) each found a defect *in a harness* ...

  **wrapped across a line break — the one shape `_flatten()` exists in this very
  file to handle, and the one shape a line-oriented `grep` cannot see.** The
  tool I scoped the fix with had the same blind spot as the code I was fixing,
  so it under-reported the thing it was measuring, and it under-reported it
  *silently* and *plausibly*. Had I trusted the survey instead of diffing the
  two parsers over the real corpus, the PR would have shipped with a confident,
  specific, wrong number in it.

  So: **a survey that scopes a fix is itself a measurement, and it fails the
  same way the target does.** Verify scope by running the old and new
  implementations over the real corpus and diffing, not by grepping for what
  you expect to find. The diff is cheap, it is exhaustive, and it does not
  share the defect.

  A second, smaller trap: this harness scans `.py` files inside the kit, so it
  **scans its own source**, and a deliberately-malformed fixture written as a
  string literal became a real finding against the kit — the gate failed on its
  own test data. Then the *expected error message* (`"cites LESSONS #9–#2 — a
  range that runs backwards"`) failed it a second time, because the message
  describing a bad citation is itself a bad citation. The malformed fixtures
  now assemble the keyword at run time; the valid ones stay literal, since they
  resolve and cost nothing. This is LESSONS #31's shape from the other side:
  there, prose was mistaken for a fact; here, a fixture was.

- **Kit change:** `harnesses/lessons/check_lesson_refs.py` gains `expand()`,
  which walks a citation's continuations and expands ranges, and `CONT_RE`,
  which deliberately allows padding around a list separator but not around a
  range dash — so the ordinary sentence `LESSONS #26 — #5 says otherwise` is
  not read as a backwards range. Seventeen self-test cases pin both directions,
  including three that assert the parser does *not* over-read: `PR #86`
  following a citation, a padded dash, and a following sentence.
- **Section amended:** `porting-kit/harnesses/lessons/check_lesson_refs.py`

## 033. Writing a lesson does not put it in force; a check does

- **Date:** 2026-09-20
- **Codebase:** lsof-rs (C `lsof` → Rust) — `check_lesson_refs.py`, scan scope
- **What happened:** The lesson cross-reference checker walked `porting-kit/`
  and nothing else. But a citation is a claim that an entry exists, and that
  claim is no weaker for being written outside the kit. Measured across this
  repository:

  | | citations |
  |---|---|
  | inside `porting-kit/` (checked) | 162 in 25 files |
  | **outside it (checked by nothing)** | **52 in 25 files** |

  A quarter of the repository's citations were unverified — in CI workflows, in
  `lsof-rs/DIVERGENCES.md` and `CHANGELOG.md`, in backend sources, in Cargo
  manifests, in fuzz targets. `--also-scan DIR` now widens the walk while
  `LESSONS.md` still comes from KIT_ROOT, because that is what a citation
  resolves *against*.

  **The part worth keeping is how badly I described this gap before fixing it.**
  When I named it as the next candidate I called it *"one citation, at
  `lsof-rs-ci.yml:104`"* — because that is the single instance I had happened to
  see in a grep. The real number was 52, in 25 files. LESSONS #032, written the
  day before, says in as many words: *verify scope by running the old and new
  implementations over the real corpus and diffing, not by grepping for what you
  expect to find.* I had just written that sentence. I did not apply it to the
  very next scoping claim I made, because that claim was made in prose, to a
  person, and nothing checks prose.

  So: **an entry in this file changes nothing by existing.** #032 did not stop
  me repeating #032. What stops it is a harness that fails. Every lesson in this
  arc that actually held — #019's ledgers, #022's cross-references, #026's
  fixture probe — held because something executable enforced it, and every one
  that did not was carried only by intention. When you write a lesson, the
  question to answer before closing the PR is *what will fail if I forget this?*
  If the answer is "nothing", you have written a note, not a control.

  A second trap, caught in the same change: widening what a gate *inspects*
  while leaving what *wakes* it alone. `porting-kit.yml` triggered on
  `porting-kit/**`, which covered the whole gate while the gate only read the
  kit. The moment it began reading `lsof-rs/**`, that trigger became a blind
  spot — deleting an entry and breaking a citation in `lsof-rs/` would have been
  two commits that each passed. **A gate's reach and its trigger have to move
  together** (LESSONS #019). The filter is gone; check-kit is python3 + bash and
  runs in seconds, so it costs nothing to run on everything.

  The new gate then immediately caught a dangling `LESSONS #033` in the workflow
  comment written for *this* entry, before the entry existed — the same mistake
  as the fabricated `PRs #81–#85` citation, this time found by machine in a file
  the old scan never opened.

- **Kit change:** `harnesses/lessons/check_lesson_refs.py` gains `--also-scan`
  (repeatable, may name a directory containing KIT_ROOT; files de-duplicated by
  real path) and `report_base()`, so findings are reported from the roots'
  common ancestor — `.github/workflows/ci.yml`, not a `../` walk out of the kit.
  A `--also-scan` naming a missing directory is a hard failure rather than a
  silent empty scan. The run line now prints the file count, so a scan that
  quietly covered less than you think is visible without reading the code.
  `make check-kit` passes `--also-scan ..`, and `.github/workflows/porting-kit.yml`
  drops its path filter to match.
- **Section amended:** `porting-kit/harnesses/lessons/check_lesson_refs.py`,
  `porting-kit/Makefile`, `.github/workflows/porting-kit.yml`

## 034. A path filter fails in two directions and they look identical from outside

- **Date:** 2026-09-20
- **Codebase:** lsof-rs (C `lsof` → Rust) — `build.yml` / `lsof-rs-ci.yml` triggers
- **What happened:** `build.yml` ignored `porting-kit/**` but not
  `.github/workflows/porting-kit.yml`, so a PR whose four files were *all* kit
  files ran the entire C matrix — macOS, `make distcheck`, twice over — because
  one of them happened to be the kit's own workflow. Adding the missing entry is
  a two-line fix, and the file's own header had already written the argument for
  it about `lsof-rs-*.yml`.

  That is the cheap direction. **Auditing it turned up the expensive one in the
  same pass**, which is the point of this entry. `lsof-rs-ci.yml` builds the
  differential oracle *from this tree*:

      autoreconf -vif && ./configure && make -j lsof

  and then diffs 87 cases against it. Its trigger is `lsof-rs/**`,
  `porting-kit/harnesses/**`, and its own file. **The C tree is not in that
  list.** A change to a C source, a dialect header, `configure.ac` or
  `Makefile.am` can change what the oracle *is*, and the gate that compares the
  port against the oracle does not re-run.

  Not hypothetical: PR #86 edited `lib/dialects/linux/machine.h`, a header the
  oracle compiles. It has four check runs and `differential (linux, vs the C)`
  is not among them. That edit was safe because I preprocessed the translation
  unit before and after by hand and got byte-identical output — **CI had no
  opinion**. The port's specification can move without the gate that enforces
  conformance to it firing.

  So: **a path filter has two failure modes and a green board shows the same
  thing for both.** Over-triggering wastes runner minutes and is obvious the
  moment anyone looks at a PR's check list. Under-triggering removes a gate and
  is invisible precisely when it matters — the absent job looks exactly like a
  job that had nothing to complain about. When you touch one filter, enumerate
  what each job actually *reads* and compare it against what wakes that job;
  the two failures are found by one audit and fixed by opposite edits
  (LESSONS #031: when a control is wrong in one direction, test the other
  direction in the same pass).

  **This entry does not close the second gap, and by LESSONS #033's own standard
  that makes it a note rather than a control.** Widening `lsof-rs-ci.yml` to the
  C tree makes the heavy Rust matrix fire on every oracle edit, which is a cost
  the repository's owner should choose rather than one I should assume. It is
  named here so the next person does not have to rediscover it, and it stays
  unenforced until someone wires it.

- **Kit change:** none — this is a host-repo CI fix. `.github/workflows/build.yml`
  ignores `.github/workflows/porting-kit.yml`. The ignore list is enumerated
  rather than generalised to "every workflow but this one", and `build.yml` is
  deliberately absent from its own list: a gate that ignores edits to itself
  cannot be re-verified when you change it.
- **Section amended:** `.github/workflows/build.yml`

## 035. A differential gate's trigger must cover both sides of the comparison

- **Date:** 2026-09-20
- **Codebase:** lsof-rs (C `lsof` → Rust) — `lsof-rs-ci.yml`, and the kit's own CI template
- **What happened:** LESSONS #034 named this and left it unfixed. Fixing it found
  that the kit was **teaching** it.

  `lsof-rs-ci.yml`'s differential job builds the C oracle from this tree —
  `autoreconf -vif && ./configure && make lsof` — and diffs 87 cases against it.
  Its trigger listed `lsof-rs/**`, `porting-kit/harnesses/**` and its own file.
  The C sources were not in it. So a change to `src/**`, `lib/**`, a dialect
  header, `configure.ac` or `Makefile.am` could change **what the oracle is**
  while the gate that enforces conformance to the oracle did not re-run: the
  port drifts from its own specification and every check is green.

  Verified against history rather than asserted. PR #86 edited
  `lib/dialects/linux/machine.h`, a header the oracle compiles; it has four
  check runs and the differential is not among them. Simulating GitHub's `paths`
  matching — validated first against what GitHub actually did on five real PRs,
  two of them negatives — #86's exact file set goes from not-triggering to
  triggering under the corrected filter.

  **The kit shipped the same defect as advice.** `harnesses/ci/porting-ci.template.yml`
  has a `differential vs C oracle` job that builds the oracle, a trigger of
  `['crates/**', 'Cargo.toml', 'Cargo.lock', ...]` with no C paths at all, and a
  header telling the reader to

  > *"Scope this Rust workflow to the Rust paths, and scope the C workflow to the
  > C paths, so each change triggers only the pipeline that can be affected by it."*

  That sentence is the bug stated as a principle. "The pipeline that can be
  affected by it" is exactly right and the inference drawn from it is exactly
  wrong: a C change **does** affect the Rust pipeline, because the Rust pipeline
  compiles the C. Every port that copied this template inherited a differential
  gate blind to its own reference. The same framing had spread to
  `OPERATING-GUIDE.md` and the audit skill.

  So: **scope a workflow to what it builds, not to the language its directory
  implies.** For each job, list what it actually reads and confirm every one of
  those paths wakes it. And the two directions of a path-filter bug are not
  symmetric, which is why the audit has to be deliberate: over-triggering wastes
  minutes and announces itself in every PR's check list, while under-triggering
  removes a gate and is invisible, because **an absent job looks exactly like a
  passing one**. When unsure, include the path.

- **Kit change:** `harnesses/ci/porting-ci.template.yml` carries C source globs in
  its trigger as a labelled, required part of the differential gate rather than
  omitting them, and its header now says why. `OPERATING-GUIDE.md`'s path-scoping
  bullet and `skills/porting-kit-audit/SKILL.md`'s CI-hygiene step both gained the
  second direction: enumerate what each job reads and confirm it is in the trigger.
- **Section amended:** `porting-kit/harnesses/ci/porting-ci.template.yml`,
  `porting-kit/OPERATING-GUIDE.md`,
  `porting-kit/skills/porting-kit-audit/SKILL.md`,
  `.github/workflows/lsof-rs-ci.yml`

---

## 036. Gates fail open on "nothing ran" — self-test the degenerate case, not just detection

- **Imported:** from the c2rust-port lineage of this kit, where it is #006. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Date:** 2026-07-19
- **Codebase:** the Porting Kit itself (full-repo code review + fix pass; PR #1
  of the lifted `c2rust-port` repo, 26 findings, all fixed)
- **What happened:** All six High findings were safety gates that *passed when
  nothing meaningful ran* — and `make check-kit` was green through every one of
  them. Both binaries timing out produced identical `<<TIMEOUT>>` sentinels and
  a `MATCH` verdict (a faithfully re-ported hang — the kit's founding bug class
  — sailed through the liveness backstop PLAYBOOK explicitly promised would
  fail it). `golden.py` enshrined a hung oracle's `<<TIMEOUT>>` as golden truth
  and dropped the exit-code half of the verdict on exactly the
  oracle-substitution path it exists for. The scanner's skip-`*`-lines
  heuristic silently never scanned `*out = malloc(a * b);`. The CI template's
  fuzz job looped over an empty `cargo fuzz list` and reported green with zero
  targets, and its sanitizer job could never succeed (no `rust-src` for
  `-Zbuild-std`) — an always-red gate that would have been deleted, not fixed.
  The pattern: every self-test proved its tool *detects* the bad case it was
  built for; none proved the tool *refuses to pass* when its inputs degenerate
  (a hang on both sides, an empty target list, a missing component). Detection
  was tested; fail-closed was not.
- **Kit change:** every hole fixed with the degenerate case pinned in the same
  change: rust-side/both-side timeouts are a non-ledgerable `TIMEOUT` verdict;
  capture refuses a timed-out golden; `.rc` sidecars restore exit-code
  fidelity; real comment masking replaces the `*`-prefix skip; the fuzz CI job
  fails on an empty target list; sanitizers install `rust-src`. The general
  rule — **a gate that finds nothing to check must fail, not pass; add the
  degenerate-input case to its self-test in the same change** — is now in the
  playbook, and the retrospective prompt's step 0 requires probing each gate's
  fail-closed behavior, not just its signal-to-noise.
- **Section amended:** PLAYBOOK · cross-cutting controls ("Gates fail closed");
  PROMPTS/90 · step 0; harnesses/differential/diff_run.py,
  harnesses/golden/golden.py, harnesses/c-flaw-scan/scan_c_flaws.py,
  harnesses/ci/porting-ci.template.yml (+ their self-tests).

---

## 037. An allow-list must ASSERT the accepted state, not merely SUPPRESS it

- **Imported:** from the c2rust-port lineage of this kit, where it is #014. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #6 -> #036 “Gates fail open on \"nothing ran\" — self-test the degenerate case, not just detection”; source #8 -> #043 “An acceptance list that matches by name becomes a permanent mute button”; source #13 -> #033 “Writing a lesson does not put it in force; a check does”.
- **Date:** 2026-07-24
- **Codebase:** the Porting Kit itself (comprehensive multi-lens audit → v1.x)
- **What happened:** A six-lens adversarial audit found the deepest hole in the
  whole kit, in the v1.0 exit test itself: **a ledgered divergence is pure
  suppression — it never asserts the divergence still occurs.** A ledger entry
  says "this case intentionally differs from C because we fixed a C bug," yet
  `compare_one` evaluated `MATCH` *before* `name in known`, so if a ledgered case
  *stopped* diverging it was silently downgraded to `MATCH` and passed. Reverting
  the adler32 overflow fix with `wrapping_add` (C-identical output — what a dev
  "matching C" writes) made the flagship exit test go **green, full success
  banner, exit 0**, in BOTH library differentials. The port's entire reason to
  exist could be deleted and every gate stayed green. This is distinct from #043
  (which pins a *changed* divergence): #043 caught a divergence that *mutated*; this
  is a divergence that *vanished*. The fingerprint pin never fires on a vanish,
  because there is no divergence left to fingerprint. Generalizes: any allow-list
  entry (a ledgered divergence, a suppressed lint, an ignored advisory, an
  expected-failure test) that only *suppresses* rots into a blind spot — it must
  also *assert* that the condition it accepts is still present, or accepting a
  thing becomes not-looking-at it.
- **Kit change:** a ledgered case that now MATCHes is a new **`LEDGER-STALE`**
  verdict — a hard failure (never passes, never ledgerable), in the shared
  `compare_one` (diff_run + cando + diff-fuzz) and independently in `lib_diff`'s
  `compare_call` (it has its own comparison path — the fix had to be applied
  twice, which is itself why the audit checked *both* differentials). Pinned in
  three self-tests and proven end-to-end: reverting the adler32 fix now fails the
  exit test. **Same audit, recurrences of #036 (fail-closed) fixed and cited in
  place, not minted as new lessons:** an empty/mis-keyed matrix made every
  differential exit 0 over a wrong binary (now refused); invalid-UTF-8 stdout
  collapsed to `MATCH` via `decode(replace)` → U+FFFD (now `backslashreplace`,
  bytes stay distinct); the fuzzer latin-1-decoded then utf-8-re-encoded its bytes,
  never feeding the high bytes it targets (now `stdin_bytes`, verbatim); a
  `SAFETY:` substring inside a string literal passed the unsafe gate (now checked
  in a real comment span); and `scan_c_flaws` had no `memcpy`/`memmove` check and
  missed pre-computed overflow (`t=n*w; malloc(t)`) and a UAF across a nested
  block — a Phase-0 scanner reporting "0 flaws" on vulnerable C (all added). And
  the pass tripped one more, in the gate that enforces *this very field*: the
  lessons-pinned check (LESSONS #033) silently skipped any `Section amended` path a
  markdown line-wrap split after a `/` (`harnesses/cando/`⏎`cando_diff.py`) —
  matching neither half — so `audit_unsafe.py` here went unchecked until it too
  was flagged. The extractor now rejoins wrapped paths (pinned self-test); the gate
  meant to make pinning fail-closed had itself been failing open.
- **Section amended:** harnesses/differential/diff_run.py (`compare_one`
  LEDGER-STALE + `run_one` byte fidelity + `load_matrix` empty-guard);
  harnesses/library-differential/lib_diff.py (`compare_call`);
  harnesses/cando/cando_diff.py; harnesses/diff-fuzz/diff_fuzz.py;
  harnesses/unsafe-audit/audit_unsafe.py;
  harnesses/c-flaw-scan/scan_c_flaws.py;
  harnesses/doc-check/check_lessons_pinned.py (rejoin wrapped paths + self-test);
  and RETROSPECTIVE-kit-audit.md (the finding inventory + the v1.x backlog of
  what was NOT fixed).

---

## 038. The C is a SPEC, and only the oracle knows what it says

- **Imported:** from the c2rust-port lineage of this kit, where it is #017. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #13 -> #033 “Writing a lesson does not put it in force; a check does”; source #15 -> by title “An inherited environment constraint is a dated observation, not a fact” (no entry in this log).
- **Date:** 2026-07-25
- **Codebase:** cJSON v1.7.18 (C JSON parser → Rust) — the kit's first FOREIGN port
- **What happened:** Every non-trivial behavior I got *wrong* on the first try, I
  got wrong by **reasoning about what the C must do** instead of **running it**.
  Four instances, all caught by executing the oracle, none findable by reading:
  1. **`print(DBL_MAX)` is lossy.** I wrote the unit test asserting the reasoned
     answer (15 digits can't round-trip DBL_MAX → the 17-digit fallback fires).
     The oracle refuted it: the `%1.15g` form `1.79769313486232e+308` reparses as
     **inf**, and cJSON's `compare_double(inf, d)` = `|inf−inf| ≤ inf·ε` =
     `nan ≤ inf` = **true**, so the C *accepts* the failed round-trip and keeps
     the lossy form — and `print → reparse → print` yields `null`.
  2. **`cJSON_Compare` says a value ≠ its own duplicate** for an inf/nan number
     (same `compare_double` quirk) and for any object with **duplicate keys** (the
     O(n²) first-match lookup can't resolve the second key). Surfaced by the
     `dup-eq` matrix's C-baseline validation, which *refused my vectors* because
     they asserted `"true"`.
  3. **`cJSON_Minify` doesn't track escape parity** — a `\` before a `"` escapes
     that quote even when the backslash is itself escaped, so `"\\" "` keeps its
     space. My "correct" escape-tracking implementation dropped it. Found by
     differential fuzzing, not by reading `minify_string`.
  4. **`parse_hex4` returns 0 on INVALID hex**, so `"\uZZZZ"` parses as a NUL
     byte rather than failing; and the printer then truncates at that NUL.
  The through-line: a mature C library's observable behavior is a **thicket of
  accreted quirks**, several of which look like bugs and some of which *are* — and
  a port that "cleans them up" silently is not safer, it is *differently wrong*.
  Faithfulness is a decision to make per-quirk with the C's actual bytes in hand.
- **Kit change:** `PROMPTS/40-port-module.md` and the module skill now open with
  **probe-then-port**: before writing a module, run the oracle on its edge cases
  and paste the observed bytes into the module's doc comment; write unit-test
  expectations from that transcript, never from reasoning about the C source. The
  kit already said "execution beats reading" for *harness* validation (LESSONS
  #033, and the source lineage's "an inherited environment constraint is a dated
  observation, not a fact"); this extends it to the **translation act itself**.
  `PLAYBOOK.md` Phase
  4 gains the same line as an entry criterion.
- **Section amended:** PROMPTS/10-module-port.md · step 0; PLAYBOOK · Phase 4
  entry criteria; skills/porting-kit-module/SKILL.md; RETROSPECTIVE-cjson.md · §2.

---

## 039. A gate that has nothing to check is not a passing gate

- **Imported:** from the c2rust-port lineage of this kit, where it is #018. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Date:** 2026-07-25
- **Codebase:** cJSON port — the `unsafe-audit` and `sanitized` gates
- **What happened:** For six of the port's seven increments, `audit_unsafe.py`
  reported **"unsafe blocks: 0, documented: 0, undocumented: 0" and exited 0** —
  and I read that as the gate passing. It wasn't: the safe core is
  `#![forbid(unsafe_code)]`, so there was **nothing for that gate to audit**, and
  its green was structurally uninformative right up until the FFI crate landed
  (33 blocks, all documented — the first run where the gate said anything). The
  same shape, worse: I asserted "miri/asan need toolchains this environment
  lacks" across five increments and left `sanitized` unset — **an inherited
  environment claim I never re-tested**, which is precisely the "an inherited environment constraint is a dated observation" lesson, written
  by me, in this same session. The retrospective's step-0 probe took one command:
  `rustup toolchain install nightly --component miri` **succeeded**, miri ran
  clean over the port, and the gate I'd written off as impossible was available
  the whole time. The generalization is sharper than "re-verify claims": a gate
  reporting **0 of 0** and a gate **not installed** are the same failure — a
  *believed-covered* control that inspected nothing — and both render as green.
- **Kit change:** `audit_unsafe.py` now reports `NOTHING-TO-AUDIT` when it finds
  zero blocks across the scanned paths (still exit 0, but never silently
  green-looking) and its `--json` carries `"blocks_found": 0`, so
  `progress.py ingest` can refuse to advance `unsafe_audited` on a vacuous
  report. The port's `check.sh` models the discipline for a gate that cannot run
  here: miri is toolchain-OPTIONAL and **`sanitized` advances only when miri
  actually ran** (never on a SKIP), with nightly+miri added to the CI job so it
  runs for real. Verified fail-closed both ways: clean code passes; an injected
  out-of-bounds read makes miri exit nonzero.
- **Section amended:** harnesses/unsafe-audit/audit_unsafe.py (NOTHING-TO-AUDIT +
  `blocks_found`); harnesses/progress/progress.py (`_clean_unsafe` refuses a
  0-block report); ports/cjson/check.sh; .github/workflows/check-kit.yml;
  RETROSPECTIVE-cjson.md · §3.

---

## 040. Scope each increment's differential to what it can decide

- **Imported:** from the c2rust-port lineage of this kit, where it is #019. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #2 -> #002 “A noisy Phase-0 scanner is worse than none — it gets ignored”.
- **Date:** 2026-07-25
- **Codebase:** cJSON port — the module-tagged corpus
- **What happened:** The kit's loop says "every module is diffed against the
  oracle the moment it lands," but a 7-module port has a period where the Rust
  **cannot parse most of the corpus** — module 2 lands and 60 of 79 vectors
  involve strings, arrays, or objects that don't exist yet. Running the full
  matrix would fail them all for "not ported yet," which is **schedule, not
  divergence** — noise that trains you to ignore red, the LESSONS #002 failure mode
  in a new place. Tagging each vector with the modules whose behavior determines
  it (`mods: ["scalar"|"string"|"tree"|"minify"]`) and emitting
  `matrix-ported.json` = "every case my ported modules fully decide" made each
  increment's differential **meaningful and 100% green**, growing 25 → 44 → 69 →
  79 as modules landed. The corpus is written ONCE against the C (all 86 vectors
  validated up front); only the *filter* moves.
- **Kit change:** `PLAYBOOK.md` Phase 2 now prescribes tagging corpus vectors by
  the module(s) that decide them and running each increment against the
  ported-subset filter, with the full matrix as the cutover gate;
  `PROMPTS/20-oracle.md` and the oracle skill carry the recipe.
  `ports/cjson/oracle/gen_corpus.py` is the worked reference implementation.
- **Section amended:** PLAYBOOK · Phase 2 "Do"; PROMPTS/00-new-port-kickoff.md;
  skills/porting-kit-oracle/SKILL.md; ports/cjson/oracle/gen_corpus.py (the worked
  reference); RETROSPECTIVE-cjson.md · §4.

---

## 041. Generate test expectations from the oracle — a convention is not a control

- **Imported:** from the c2rust-port lineage of this kit, where it is #021. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #17 -> #038 “The C is a SPEC, and only the oracle knows what it says”; source #13 -> #033 “Writing a lesson does not put it in force; a check does”.
- **Date:** 2026-07-25
- **Codebase:** the kit itself (post-cJSON), closing RETROSPECTIVE-cjson.md §6
- **What happened:** LESSONS #038 established probe-then-port as a *convention*:
  run the C on the module's edge cases, paste the transcript, write expectations
  from it. But every §2 mistake on the cJSON port had already shown what happens
  without enforcement — wrong unit tests written from reasoning happily agreed
  with wrong Rust until a gate outside the tests disagreed — and LESSONS #033 is
  explicit that conventions decay: two logged lessons recurred in code written
  after them. Nothing stopped the *next* port's author from hand-writing an
  expectation that contradicts the C, or from quietly editing a pasted
  transcript to match their code.
- **Kit change:** `harnesses/probe/probe.py` mechanizes the convention end to
  end: `run` executes the probes against the C oracle and pins the observed
  (rc, stdout) byte-faithfully under a fingerprint; `gen` **generates** the Rust
  `#[test]` expectations from the transcript (one hand-written glue fn maps
  driver modes to the crate's API — the expectations themselves are never
  hand-written, so one that contradicts the C cannot exist); `verify` fails
  closed on oracle drift (every probe re-run, behavior re-compared — never
  hash-trusted), on a tampered transcript (fingerprint), and on a hand-edited
  or stale generated file (byte-compare against a fresh regeneration).
  Fail-closed per the kit's characteristic bug: zero probes, a hanging oracle,
  and a missing artifact are all failures, never passes. Wired: `make check-kit`
  self-test, a gate-mutation entry (neutralized drift-verdict → self-test red),
  and the worked integration — the cJSON port's eight §2 quirks are now pinned
  in `ports/cjson/oracle/probes-quirks.json`, generated into
  `crates/core/tests/probes_quirks.rs`, and verified in `ports/cjson/check.sh`
  step 1b.
- **Section amended:** harnesses/probe/probe.py (the harness + self-test);
  harnesses/gate-mutation/mutate_gates.py (probe entry); ports/cjson/check.sh
  (step 1b); PLAYBOOK · Phase 4 entry criteria; PROMPTS/10-module-port.md ·
  step 0; skills/porting-kit-module/SKILL.md · step 0.

---

## 042. Verifying the artifacts that exist says nothing about the one that is missing

- **Imported:** from the c2rust-port lineage of this kit, where it is #023. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #6 -> #036 “Gates fail open on \"nothing ran\" — self-test the degenerate case, not just detection”; source #14 -> #037 “An allow-list must ASSERT the accepted state, not merely SUPPRESS it”; source #18 -> #039 “A gate that has nothing to check is not a passing gate”; source #19 -> #040 “Scope each increment's differential to what it can decide”; source #20 -> by title “A harness meets its real bugs only on a real port” (no entry in this log).
- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/probe/probe.py` (one day old)
- **What happened:** `probe.py` was built to fail closed everywhere: zero probes
  in a file is an error, a hanging oracle is an error, a tampered transcript or
  hand-edited generated test is an error. All true — and all irrelevant to the
  question nobody asked: *which probes files exist at all?* That was a hand-edited
  line in the port's `check.sh` naming one file. A module could land with **no
  probes whatsoever** and every gate stayed green, because `run`/`gen`/`verify`
  only ever see the files they are handed. The kit's characteristic 0-of-0
  (LESSONS #036/#037/#039, and the source lineage's "a harness meets its real bugs
  only on a real port"), displaced one level up into the *wiring* — committed
  by me in the same change that mechanized the lesson about conventions decaying.
  A gate hardened against everything inside its input is still trusting whoever
  chose the input.
- **Kit change:** `probe.py coverage` takes the module list from the port's own
  `progress.json` (so it cannot drift from the list the gates track) and fails
  naming any module with no probes file; an empty module list is itself a failure.
  Probes files carry `modules: [...]` tags, reusing the corpus tagging idiom of
  LESSONS #040. Wired into `ports/cjson/check.sh`. Writing the missing probes for
  the two uncovered cJSON modules immediately pinned **four behaviors reasoning
  would have gotten wrong** — cJSON accepts a leading UTF-8 BOM, accepts trailing
  garbage after a complete value (`[1] xyz` → `[1]`), treats an **embedded NUL as
  whitespace** (`buffer_skip_whitespace` tests `<= 32`), and prints an empty
  object as `{\n}` while an empty array prints `[]`. The port already matched all
  four (the differential and fuzzer had driven it there); they are now *named*, so
  a future "cleanup" of NUL-as-whitespace breaks a test instead of drop-in parity.
- **Section amended:** harnesses/probe/probe.py (`cmd_coverage` + self-test);
  ports/cjson/check.sh (step 1b coverage); PLAYBOOK · Phase 4 entry criteria;
  PROMPTS/10-module-port.md · step 0; RETROSPECTIVE-probe-harness.md · §3.

---
## 043. An acceptance list that matches by name becomes a permanent mute button

- **Imported:** from the c2rust-port lineage of this kit, where it is #008. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Date:** 2026-07-19
- **Codebase:** the Porting Kit itself (same review pass)
- **What happened:** The divergence ledger suppressed by *case name alone*:
  once `json-format` was ledgered for an intentional fix-of-C-defect, any
  future, unrelated regression in that case — wrong values, new crash output —
  reported `DIVERGE(ledgered)` and exited 0, forever. The most-exercised cases
  are the most likely to be ledgered, so the differential gate was weakest
  exactly where behavior changes most. This generalizes: any allow-list entry
  that names a *thing* rather than an *instance* (a case, a file, a finding
  id) rots from "we accepted this divergence" into "we no longer look at this
  case."
- **Kit change:** ledger entries can pin the accepted divergence's fingerprint
  — `- [x] <case> [sha256:<12-hex>]: <why>` — hashed over the normalized diff
  text. A pinned case re-fails with an explicit "the divergence changed;
  re-triage" when the diff no longer matches; unpinned (legacy) entries still
  suppress but the tool prints the exact pin to add. Pin-accept and
  stale-pin-refail are self-tested.
- **Section amended:** harnesses/differential/diff_run.py (`load_ledger`,
  `compare`, output hint, self-test); skeleton/DIVERGENCES.md · format.

---

## 044. A template must pass the gates it ships — or every copy starts red

- **Imported:** from the c2rust-port lineage of this kit, where it is #009. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #6 -> #036 “Gates fail open on \"nothing ran\" — self-test the degenerate case, not just detection”; source #7 -> by title “Documented commands are code — phantom flags and paste-broken examples drift silently” (no entry in this log).
- **Date:** 2026-07-20
- **Codebase:** the Porting Kit itself (installing real CI for the kit repo; PR #3)
- **What happened:** Wiring meaningful CI meant running the kit's own gates, and
  the shipped **skeleton did not pass them**. It was not `cargo fmt`-clean, and its
  example parser/CLI used `i + 1` on loop indices — which trips the workspace's own
  `clippy::arithmetic_side_effects` lint under `-D warnings`. Both `cargo fmt
  --check` and `cargo clippy --all-targets -- -D warnings` are in the kit's CI
  template, so a fresh copy of the skeleton started **red** under the kit's own CI:
  a starting-point that fails the gates it configures. Nothing caught it because
  `make check-kit` is toolchain-free and never built or linted the skeleton — the
  one artifact every port begins by copying was the one artifact no gate checked.
  Same family as #036 and the source lineage's "documented commands are code": the
  kit's own artifacts must satisfy the kit's own rules.
- **Kit change:** (a) fixed the skeleton to a clean exemplar — fmt-clean, and
  `i.saturating_add(1)` (the checked/saturating idiom the playbook prescribes, so
  the skeleton now *models* its own lint instead of violating it); (b) added
  `harnesses/skeleton-check/check_skeleton.sh` to `make check-kit` — it runs the
  real fmt/clippy/build/test when a Rust toolchain is present and SKIPs cleanly
  otherwise, so a skeleton regression is caught locally even where CI can't run,
  without breaking check-kit's python3+bash-only minimum; (c) Phase 3 exit criteria
  now require the workspace/skeleton to pass the gates it configures.
- **Section amended (source lineage):** skeleton/crates/{core,cli};
  harnesses/skeleton-check/check_skeleton.sh (new) + Makefile · check-kit;
  README · harness table; PLAYBOOK · Phase 3 exit criteria. **Here:** not yet —
  `skeleton-check` is a later stage of this refresh; this entry is the standing
  reason to do it.
- **Closed 2026-09-20** (appended, not rewritten — a forward-looking "not yet" in
  an append-only log goes stale, and leaving it to read as current is the kind of
  claim this kit exists to prevent). `skeleton-check` is imported and wired into
  `make check-kit`. Its first real run failed: this lineage's skeleton was not
  `cargo fmt`-clean (four files) **and** used `i + 1` in `crates/core/src/parser.rs`
  and `crates/cli/src/main.rs`, tripping the `clippy::arithmetic_side_effects` that
  the skeleton's own `[workspace.lints]` denies. Both defects this entry names,
  verbatim, sitting here the whole time — every port that copied this skeleton
  started red under the CI the skeleton itself configures. Fixed to a clean
  exemplar with `i.saturating_add(1)`; the gate now reports `PASS  skeleton passes
  the gates it ships`.

---

## 045. A process-driving harness must be hermetic — control stdin, don't inherit it

- **Imported:** from the c2rust-port lineage of this kit, where it is #011. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #1 -> #001 “The kit's own dry-run against lsof's failure inventory”.
- **Date:** 2026-07-20
- **Codebase:** the Porting Kit itself (found while validating the perf gate, #P0)
- **What happened:** `run_one` — the shared runner behind the differential, golden,
  diff-fuzz, perf, and cando harnesses — passed no stdin for a case without a
  `stdin` key, so the child **inherited the parent's stdin**. A stdin-reading binary
  (the skeleton `port` reads stdin unconditionally) then blocked forever on an
  interactive/TTY parent: a differential/perf run that hangs or passes depending on
  *who launched it*. Latent since the differential shipped; it only surfaced when
  the new perf gate ran a real stdin-reading binary from an interactive shell. This
  is the hostile-host rule (#001) extended from encoding/quoting to the
  process-launch surface — inherited fds/stdin/env are ambient state a test harness
  must not depend on.
- **Confirmed here before porting the fix,** because a hazard read rather than run
  is the one that turns out to be wrong. Two identical Python scripts that echo
  their stdin, run through this repo's `diff_run.py` with no `stdin` key and the
  parent's stdin a pipe carrying `PARENT-SECRET`: the ORACLE child consumed the
  pipe and printed `b'PARENT-SECRET'`, the RUST child ran second, found it empty,
  and printed `b''` — verdict **DIVERGE**. So the inherited-stdin bug is not only a
  hang risk; on a pipe it manufactures a divergence between two copies of the same
  program out of nothing but ambient parent state.
- **Kit change:** `run_one` feeds `subprocess.DEVNULL` when a case provides no
  stdin (deterministic EOF, hermetic), pinned in the diff_run self-test. Generalized
  in the playbook: a harness that spawns processes controls stdin/env/cwd explicitly
  and inherits nothing.
- **Section amended:** harnesses/differential/diff_run.py (`run_one` + self-test);
  PLAYBOOK · Phase 2 "harden the harness for its host".

---

## 046. A re-cited number resolves, and still means another lesson

- **Date:** 2026-09-20
- **Codebase:** the Porting Kit vendored here (refreshing it from the c2rust-port
  lineage — stage 1's own output, reviewed one stage later)
- **What happened:** This kit's `LESSONS.md` and the one in the `c2rust-port`
  lineage are both **append-only**. They share `#001`–`#005` and then diverge, so
  from `#006` up the same number names a different lesson on each side. Importing
  an entry therefore means rewriting every `#N` in its body to this log's
  numbering, and stage 1 of the refresh set out to do exactly that — the PR said
  so, in those words.

  It re-cited the *heads* and missed the *members*. `(LESSONS #6/#14/#18/#20)`
  became `(LESSONS #036/#14/#18/#20)`: one number translated, three carried over.
  Two more entries kept a bare `#8` and `#6` from the source lineage. Five of the
  seven imported entries had at least one unaccounted cross-reference.

  **Every gate stayed green**, and not by accident — by construction.
  `check_lesson_refs.py` asks "does `#14` resolve to an entry?" It does. It is
  simply a different lesson than the sentence means. A citation checker built
  around existence cannot see a *wrong* citation, and existence is the only thing
  a destination log knows. Worse, the checker's list/range expansion parsed
  `#036/#14/#18/#20` correctly and then validated all four — the more capable the
  parser, the more confidently it blessed the error.

- **Why the obvious controls don't reach it:** the failing claim is *semantic* and
  its truth-maker lives in another repository. A checker in this tree has nothing
  to compare against; a checker that fetches the source log only works where the
  source log is checked out, which is not where CI runs. Review does not catch it
  either: `#14` reads exactly like a correct citation, and there is no local
  evidence it is wrong.

- **What does reach it:** make the import carry its own truth-maker. An imported
  entry now records what each source citation was re-cited **to, and the title it
  had** — `source #8 -> #043 "An acceptance list that matches by name…"`. That
  turns an unverifiable cross-repo claim into a local one: the destination entry
  either has that title or it does not. Two properties are then checkable offline
  and mechanically — **resolution** (the destination exists and is the lesson
  named) and **completeness** (no number in the body escaped the mapping). The
  second is the one that catches carry-over, and it is the one a human reviewer
  cannot do by reading, because carried-over numbers look right.

  The general form: **when a value is translated between two namespaces, the
  translation must record the meaning, not just the new number — otherwise a
  missed translation is indistinguishable from a correct one.** Any renumbering
  across forks has this shape: issue ids, CVE aliases, error codes, test ids.

- **Also found, and worth its own line:** the first cut of the new checker
  required a *straight*-quoted title, and its self-test dutifully used one. Green
  self-test, and `no parseable mapping` on every real entry — because a real
  lesson title may quote a phrase of its own (`Gates fail open on "nothing ran"`),
  so real mappings are written with curly quotes. A fixture written in a form the
  real data does not use measures the fixture. Both quote styles are now accepted
  and both are pinned.

- **Kit change:** `harnesses/lessons/check_imports.py` (new) — enforces the
  `- **Re-cited:**` mapping on every entry carrying `- **Imported:**`, with a
  `by title` escape hatch for a source lesson that has no counterpart here (itself
  refused if an entry with that title does exist). Wired into `make check-kit`,
  self-test and real-log run both. Proven against the real file by mutation: the
  stage-1 body text and a plausible wrong-destination re-cite each turn it red.
  The five entries stage 1 imported now carry their mappings, and their three bad
  cross-references are corrected.
- **Section amended:** harnesses/lessons/check_imports.py (new); Makefile ·
  check-kit; README · harness table; LESSONS.md · #037, #038, #040, #041, #042
  (mappings added, `#8`/`#6`/`#13`/`#15`/`#14`/`#18`/`#20` corrected).

---

## 047. A marker a document can mention is a marker a document can claim

- **Date:** 2026-09-20
- **Codebase:** the Porting Kit vendored here (refresh stage 2 — `diff-fuzz`, and
  the control written one commit earlier in #046)
- **What happened:** #046 made an imported *entry* record what it re-cited to.
  Imported **files** — harnesses, skills — have the same hazard and no heading to
  hang a mapping on, so they carry a `KIT-IMPORT:` header declaring theirs. Two
  things went wrong building that, and both are about the marker being *text*.

  **1. The checker marked itself.** Its docstring shows an example marker and its
  fixtures contain more; scanning for the string anywhere in a file, it found 16
  citations in its own examples and reported them as carried-over. The fix is that
  a marker is a *position*, not a string: it must open its line, within the file's
  header. Then, one commit later, the README gained a sentence explaining
  `KIT-IMPORT:` — and the README was immediately counted as an imported file. The
  same mistake, in a document *describing* the fix, minutes after making it.
  Generalizes: **any in-band marker that documentation must be able to discuss
  needs a rule that distinguishes using it from mentioning it** — a shape, a
  position, a delimiter. Without one, writing the docs breaks the tool.

- **What the file-level check found immediately:** stage 1's `probe.py` import had
  the same carry-over as the LESSONS entries — `(LESSONS #036/#14/#18/#20)` and
  `LESSONS #038/#21`, heads re-cited, members not. One of those is emitted into
  *generated Rust test files*, so the wrong citation would have propagated into
  port source. Porting `diff-fuzz` produced two more (`LESSONS #036, #14` and
  `LESSONS #001/#6`). Four of the six survivors this refresh has found were
  continuation members: **the failure lives in the part of a citation a grep for
  `LESSONS #14` cannot see.** What finds them is expanding each citation through
  `check_lesson_refs`'s own list/range rules — the same expansion that, asking
  only "does it resolve?", had been blessing them.

- **Kit change:** `check_imports.py` also checks `KIT-IMPORT`-marked files: every
  citation, expanded, must land in the header's declared destination set; the
  header is read only from the marker's own block, so a mapping written elsewhere
  in the file cannot widen it. Six pinned self-tests, including both self-marking
  cases. The five imported files carry markers and are clean.
- **Section amended:** harnesses/lessons/check_imports.py (`check_files`, marker
  rules, self-tests); harnesses/probe/probe.py (two carried-over members);
  README · banner + harness table.

---

## 048. An append-only log is a shared counter, and two branches will take the same number

- **Date:** 2026-09-20
- **Codebase:** the Porting Kit vendored here (refresh stage 2 meeting master)
- **What happened:** `master` appended two lessons at `#034`/`#035` while the kit
  refresh branch appended twelve at `#034`–`#045`. Neither side did anything
  wrong; "append-only" is a rule about not *rewriting* entries, and both branches
  obeyed it. But the next number is **shared mutable state**, and git cannot merge
  a counter — it saw two different texts at the same offset and produced a
  conflict. The real conflict is semantic: `#034` now names two different lessons
  depending on which branch you read.

  This is #046's cross-lineage collision arriving from inside one repository, and
  it is more likely, not less: two branches of the same log diverge by days, not
  by a fork.

- **What `check_lesson_refs` would and would not have caught:** it detects a
  duplicate `## NNN.` heading, so the crude "keep both" resolution fails loudly.
  It cannot detect the subtler one — renumber the headings, miss a citation, and
  every number still resolves, now to the wrong entry. The renumber is where the
  damage happens, not the merge.

- **Two non-obvious properties a renumber needs**, both load-bearing here:
  1. **Simultaneous, not sequential.** Shifting `#034`→`#036` and then applying
     `#036`→`#038` catches the entry just moved. One pass, one map.
  2. **It must distinguish a reference to THIS log from a number that merely
     looks like one.** The `Re-cited` and `KIT-IMPORT` mappings added in #046/#047
     are full of *source-lineage* numbers, and `#36`, `#42` and `#43` sit inside
     the shift range. Rewriting one of those turns a source number into a
     destination number — the same corruption as a carried-over citation, arriving
     from the opposite direction, and it would have read as correct. What saved it
     was a shape rule that was already there for other reasons: this log writes
     its own entries zero-padded to three digits (`#036`) and source numbers bare
     (`#36`), so matching only `#\d{3}` separates them. That was luck as much as
     design; the general rule is to **give the two namespaces different surface
     forms before you need to tell them apart**, and to verify a renumber by
     diffing a strict pass against a loose one rather than trusting either.

- **Kit change:** none to the harnesses — `check_lesson_refs` (duplicate/missing
  headings) plus `check_imports` (re-citation resolution and completeness) between
  them cover the failure modes a merge can produce, and both ran green on the
  resolved tree. What this entry buys is the *procedure*: when two branches of an
  append-only log collide, the side that landed first keeps its numbers, the other
  block shifts as a unit, and the shift is applied in one simultaneous pass under
  a pattern that cannot match a foreign namespace. Recorded here because the next
  refresh stage will hit this again.
- **Section amended:** none — this is procedure, and the controls that enforce it
  already exist (harnesses/lessons/check_lesson_refs.py, check_imports.py).

---

## 049. The status list you read is one provider's view, not the set of gates

- **Date:** 2026-09-20
- **Codebase:** lsof-rs / lsof — the dialect-deletion near-miss
- **What happened:** The cleanup arc's last deferred item was six "wired but
  unused" C dialects — `aix`, `darwin`, `freebsd`, `netbsd`, `openbsd`, `sun`,
  82 files and 35,637 lines, all reachable from `configure.ac`'s `AS_CASE` on
  `$host_os`. The instruction was to delete them. Measuring first turned the
  task inside out:

  | dialect | built by | what actually runs |
  |---|---|---|
  | `darwin` | GitHub Actions | `Configure -n darwin`, `make`, `check.bash darwin`, autotools, dist |
  | `freebsd` | **Cirrus CI** | two FreeBSD images, `check.bash freebsd`, autotools, `make check`, **`make distcheck`** |
  | `netbsd` | **sourcehut** | netbsd/9.x, autoreconf, configure, make |
  | `openbsd` | **sourcehut** | openbsd/7.2, `Configure`, `make`, `check.bash openbsd` |
  | `aix` | — | nothing, on any provider |
  | `sun` | — | nothing, on any provider |

  **Four of the six were live, tested oracle platforms, and three of those are
  tested by CI that never appears in this repository's GitHub check list.**
  FreeBSD's Cirrus job is a more thorough C build than the Linux GitHub job —
  it is the only place `make distcheck` runs on a BSD. Delete those trees and
  every GitHub check stays green.

  This is LESSONS #035 with the comfortable assumption removed. That entry says
  an absent job looks exactly like a passing one. **The job need not be absent.
  It can be running — passing or failing — on a provider whose results never
  enter the list you are reading.** Nine PRs of this arc were judged safe by
  reading GitHub check runs. That list is a *view over one provider*, and I had
  been treating it as the set of gates for days.

  The evidence was never hidden. `.cirrus.yml`, `.builds/netbsd.yml` and
  `.builds/openbsd.yml` sit at the repository root, tracked, in plain sight —
  and **no workflow, harness, document or skill in this kit references any of
  them.** A gate that nothing points at is one you will not think to look for,
  which is why finding it has to be a step rather than a hope.

  So, before removing anything a build system can select: **enumerate CI
  providers by finding their config files, not by reading a status list**, then
  map each config to what it builds.

      git ls-files | grep -E '^\.github/workflows/|^\.cirrus|^\.builds/|^\.travis|appveyor|gitlab-ci|woodpecker|\.drone'

  A second thing worth recording: the deletion did not happen. The measurement
  went to the repository's owner with the table above and the answer was to keep
  all six — **untested is not the same as irrelevant.** `aix` and `sun` are
  unbuilt here but they are functional source with a wired build path, not stale
  files or dangling references, which is the boundary this whole arc worked to.
  The investigation was the deliverable; the diff was empty and that was the
  right outcome.

- **Kit change:** `skills/porting-kit-audit/SKILL.md`'s CI-hygiene step now starts
  by enumerating provider configs, because its previous two checks — is each
  workflow path-scoped, and does each job's trigger cover what that job reads —
  both silently assume you can see every job.
- **Honest limit (LESSONS #033):** this is a procedure in a skill, not a harness.
  Nothing fails if someone skips it, which by #033's own standard makes it a note
  with a checklist attached rather than a control. The executable version would be
  a ledger asserting that every platform the build system can select is either
  built by some CI config or explicitly waived — named here, not built.
- **Section amended:** `porting-kit/skills/porting-kit-audit/SKILL.md`

---

## 050. A multi-defect fixture pins only the union — mutate the gates to prove them

- **Imported:** from the c2rust-port lineage of this kit, where it is #016. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Date:** 2026-07-25
- **Codebase:** the Porting Kit itself (gate-mutation verification)
- **What happened:** Every fail-open that lineage of the kit ever shipped — the
  both-hang MATCH, LEDGER-STALE, the wrapped-path skip, the fenced-block harvest
  — was a gate that *passed while checking nothing*, and every one was found by a
  human probing by hand. The gate-mutation harness makes that probe mechanical:
  neutralize each gate's crown verdict in a scratch copy (`is_match = True`,
  `return []`, `if False:`) and require its own self-test to go red. **Its first
  sweep found a survivor.** `check_skills.py`'s missing-path detection could be
  deleted outright with the suite staying green, because its "bad skill" fixture
  bundled TWO defects — a name mismatch and a missing path — into one
  `exit == 1` assertion: the name mismatch alone drove the exit code, so the
  path check was pinned by nothing. The general form: **a fixture that carries N
  defects pins only their union — any N−1 of the checks can silently die.** The
  sweep also showed diff-fuzz's self-test *crashing* (unguarded `findings[0]`)
  instead of failing when findings vanish; crash-red is indistinguishable from
  harness-broken-red, so the mutation harness treats a Traceback as a hard
  error, not a catch.
- **Kit change (source lineage):** `harnesses/gate-mutation/mutate_gates.py` — a
  mutation table wired into `make check-kit`. Fail-closed at every joint: a stale
  or ambiguous table entry, a syntax-breaking mutation, a Traceback under
  mutation, or a red baseline are all hard errors, so the sweep can neither rot
  silently nor claim fake coverage.
- **Here:** the harness is imported and its table rebuilt against *this* kit's
  harnesses — twelve rows dropped for harnesses this lineage does not have, five
  authored for the ones it has that the source kit does not (`coverage_gate`,
  `check_ledgers`, `check_lesson_refs`, and `check_imports` twice, because its
  resolution and completeness verdicts are independent and one row would pin
  only their union — this lesson applied to itself).
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (new here);
  Makefile · check-kit; README · harness table.

---

## 051. A gate that can never pass is as broken as one that can never fail

- **Imported:** from the c2rust-port lineage of this kit, where it is #022. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #6 -> #036 “Gates fail open on \"nothing ran\" — self-test the degenerate case, not just detection”; source #15 -> by title “An inherited environment constraint is a dated observation, not a fact” (no entry in this log).
- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/sanitizers/run_sanitizers.sh`,
  `harnesses/gate-mutation/mutate_gates.py`
- **What happened:** `run_sanitizers.sh ubsan` ran
  `RUSTFLAGS=-Zsanitizer=undefined`. **rustc has no `undefined` sanitizer** —
  Rust's UB detector is miri — so the mode exited 1 on every codebase in the
  world, and `all` (which included it) was **permanently red no matter how clean
  the code**. The kit's whole doctrine is fail-closed, but a gate that cannot go
  green teaches its users to skip it, and a skipped control is a broken control.
  It survived a 26-finding review, a whole foreign port, and **every
  gate-mutation sweep**. Three reasons, each its own hole: (1) `--check`
  validated bash *syntax* and printed `self-test: OK` — the identical root cause
  as the original never-runnable sanitizer job (LESSONS #036), recurring inside
  the very harness that lesson was about; (2) `mutate_gates._run` hardcoded
  `sys.executable`, so **no bash harness could be in the mutation table at all**
  while the sweep kept printing "15 gate(s) mutated, 0 survivor(s)" — a summary
  that reads as the whole gate set and silently covered only the python half;
  (3) the port that used it **hand-rolled its own `cargo +nightly miri test`**
  instead of calling the harness, so in the kit's entire life this harness had
  never once executed against real code. Found by running it — `--check` says OK,
  the actual mode says rc=1.
- **Kit change (source lineage):** modes map through `is_valid_san` against the
  sanitizer list rustc accepts, `--check` pins that validator with a **negative
  fixture** (it must reject `undefined`, the exact value that shipped);
  `ubsan` delegates to miri; `all` = miri + asan. `mutate_gates._run` dispatches
  by extension, making **bash gates sweep-able for the first time**.
- **Here:** this kit's `run_sanitizers.sh` is its own, and its modes were checked
  against this entry before the harness landed. The `_run` extension dispatch
  comes across with the harness, so this lineage's three bash gates are in the
  table from the start rather than added after a sweep missed them.
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (`_run` dispatch);
  harnesses/sanitizers/run_sanitizers.sh (verified against this entry).

---

## 052. A hand-maintained coverage table reports on itself

- **Imported:** from the c2rust-port lineage of this kit, where it is #025. Renumbered here because the two logs are append-only and diverge from #006; internal cross-references are re-cited to this log's numbering.
- **Re-cited:** source #6 -> #036 “Gates fail open on \"nothing ran\" — self-test the degenerate case, not just detection”; source #22 -> #051 “A gate that can never pass is as broken as one that can never fail”.
- **Date:** 2026-08-22
- **Codebase:** the kit itself — `harnesses/gate-mutation/mutate_gates.py` and the
  three bash harnesses it could not see
- **What happened:** the gate-mutation sweep prints *"N gate(s) mutated, 0
  survivor(s)"*, which reads as a statement about the gate set. It is a statement
  about **the hand-written table**. Nothing required a harness to be in it, so
  the count was silently partial — and because `_run` assumed python, the missing
  ones were precisely the bash harnesses, one of which (LESSONS #051) was shipping
  a mode that could never pass. Fixing the interpreter made them *sweepable*, not
  *swept*: adding entries for the remaining three immediately produced **three
  survivors**. All three self-tests only ever exercised the happy path — an
  always-present template, an always-present config, an always-present skeleton
  dir — so neutralizing each verdict changed nothing they observed. Proves
  detection, never refusal: LESSONS #036's root cause, alive in three more places.
- **Kit change:** `coverage_gaps()` walks `harnesses/` and `skills/` for anything
  exposing a self-test and fails the sweep naming any harness with no mutation
  entry; exemptions must be written down with a reason in `COVERAGE_EXEMPT`.
- **Why it bites hardest on an IMPORTED table:** a table inherited from another
  lineage describes *that* lineage's harnesses. Ported verbatim it would print a
  confident survivor count over a gate set it was never written for, and the
  harnesses this lineage grew on its own — the coverage gate, the ledger check,
  both lesson checkers — would sit outside it. `coverage_gaps()` is what turns
  that from a silent omission into a failed run, and it is the reason the table
  had to be rebuilt rather than copied.
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (`coverage_gaps` +
  the rebuilt table).

---

## 053. The first run of an imported gate measures the tree that imported it

- **Date:** 2026-09-20
- **Codebase:** the Porting Kit vendored here (refresh stage 3 — `gate-mutation`)
- **What happened:** importing the gate-mutation sweep was supposed to be a
  transplant. It was an audit. The harness arrives with a hand-written table of
  one crown verdict per gate, and that table describes the **source** lineage's
  harnesses. Against this tree:

  * **6 of 13** inherited entries were STALE — the target text does not exist in
    this lineage's copy of the same harness. The shared harnesses have diverged
    on both sides, so `golden.py`, `progress.py`, `scan_c_flaws.py` and all three
    bash gates needed their crown verdict located here rather than copied. A
    harness that fails closed on a stale entry is what made that visible instead
    of silently mutating dead code and reporting a catch.
  * **5 harnesses this lineage grew on its own** — the coverage gate, the ledger
    check, and both lesson checkers — had no entry at all and would have sat
    outside a confident "N gates mutated, 0 survivors". `check_imports` needed
    two rows, not one, because its resolution and completeness verdicts are
    independent: one row would have pinned only their union, which is #050
    applied to the tool built for #046.

- **What the first sweep found, in a kit that had been green for months:**
  1. **A gate that could never pass.** `run_sanitizers.sh ubsan` ran
     `-Zsanitizer=undefined`, and `all` — which is the **default mode** —
     included it. Verified by running rustc, not by trusting the imported entry:
     `-Zsanitizer=undefined` is rejected at option-parse time, rc=1, on any input.
     So the default invocation of the memory-safety gate had never once been able
     to go green. `--check` validated bash *syntax* and printed `self-test: OK`
     over it. This is the whole of #051, sitting in this tree the entire time.
  2. **Two survivors.** `check_skills.py`'s missing-path detection could be
     deleted with the suite staying green — the same bundled two-defect fixture
     #050 describes finding in the source lineage, never fixed here. And
     `progress.py`'s `ingest` verdict could be inverted, because `ingest` had
     **no self-test at all**: neutralized, it would advance a module to its final
     gate on an audit report showing undocumented `unsafe`.
  3. **A quieter fail-open.** `run_supply_chain.sh` checked its policy file with
     `test -f ... && echo PASS` — under `set -e` a false left-hand side of `&&`
     does not exit, so a MISSING cargo-deny policy printed nothing and the check
     went on to say `self-test: OK`.

- **The lesson:** a control imported from a sibling lineage is not "already
  proven" — its proof belongs to the tree it was proven in. **What it reports on
  arrival is a measurement of the importing tree**, and that is the reason to
  import it, not an obstacle to doing so. Budget the import as an audit: expect
  the inherited table to be wrong about your code, expect it to name things that
  have been green for months, and re-derive rather than re-run. The corollary is
  that a *clean* first run is the suspicious one — it more likely means the table
  never pointed at your code at all.

- **Kit change:** `harnesses/gate-mutation/mutate_gates.py` imported and its table
  rebuilt against this kit (12 rows dropped for harnesses not here, 6 re-aimed at
  this lineage's verdicts, 5 authored for harnesses the source kit lacks); wired
  into `make check-kit` as self-test plus full sweep, ~20s. `run_sanitizers.sh`
  now validates modes against the sanitizer list rustc accepts, with a negative
  fixture pinning `undefined` and a live cross-check against nightly; `ubsan`
  delegates to miri and `all` is miri + asan. `gen_fuzz_target.sh` and
  `run_supply_chain.sh` had their crown verdicts extracted into predicates with
  negative fixtures. `check_skills.py` now uses one fixture per defect and
  `progress.py` has an `ingest` self-test covering refusal as well as detection.
  Sweep: 18 gates, 0 survivors, 0 table gaps.
- **Section amended:** harnesses/gate-mutation/mutate_gates.py (new here);
  harnesses/sanitizers/run_sanitizers.sh; harnesses/fuzz/gen_fuzz_target.sh;
  harnesses/supply-chain/run_supply_chain.sh; harnesses/progress/progress.py;
  skills/check_skills.py; Makefile · check-kit; README · harness table.

---

## 054. A harness written to enforce a lesson can contain the lesson it enforces

- **Date:** 2026-09-20
- **Codebase:** lsof-rs / lsof — `harnesses/platforms/check_platforms.py`
- **What happened:** LESSONS #049 ended by naming its own executable form and not
  building it: *"a ledger asserting that every platform the build system can
  select is either built by some CI config or explicitly waived — named here, not
  built."* By #033's standard that made #049 a note. This entry is written after
  building it, and the build is the interesting part.

  `check_platforms.py` discovers platforms from the **tree** (`lib/dialects/*`),
  discovers CI configs from the **filesystem** across every provider, and asserts
  each platform is either matched by evidence in some config or waived. On the
  real repository:

      built  darwin   .github/workflows/build.yml:93   run: ... ./Configure -n darwin
      built  freebsd  .cirrus.yml:5                    - image_family: freebsd-15-0-amd64-zfs
      built  linux    .github/workflows/build.yml:55   run: ./Configure linux </dev/null
      built  netbsd   .builds/netbsd.yml:1             image: netbsd/9.x
      built  openbsd  .builds/openbsd.yml:1            image: openbsd/7.2
      waived aix, sun

  **The first run certified `darwin` from a COMMENT.** Not the job step at
  `build.yml:93`, but the line 47 rows above it — a comment *about* `-n` that
  quotes `./Configure -n darwin` while explaining what that flag skips. The
  harness written to enforce "an absent job looks like a passing one" had, in its
  own first execution, accepted prose as proof a job ran: LESSONS #031's defect
  reproduced inside the control built to prevent #049's.

  Two things made that visible rather than shipped:

  1. **The harness prints its evidence, not a count.** `5 built by CI` would have
     read as a clean pass. `build.yml:46 # job's ./Configure -n darwin` cannot.
     **A gate that reports only a verdict cannot be audited by the person reading
     it** — print what convinced you, and a wrong reason announces itself.
  2. **The fix was to reuse, not to reimplement.** `executable_text()` already
     existed in `check_ledgers.py`, written for exactly this after #031. Importing
     it cost three lines; writing a second comment-stripper would have produced a
     second thing to get wrong. A subtlety worth knowing: it strips the key from
     `key: value`, so evidence patterns must match the VALUE — `netbsd/`, not
     `image: netbsd`.

  So: **when you build the harness for a lesson, check the harness against that
  same lesson before trusting it.** The code written to stop a mistake is written
  by someone currently thinking about that mistake, which feels like immunity and
  is not.

- **Mutation-tested rather than assumed** — three failure modes, each induced
  against the real tree and then reverted:

  | mutation | caught |
  |---|---|
  | `.cirrus.yml` removed | `'freebsd' claims CI builds it, but none of [...] appears in any of the 7 CI config(s)` |
  | `lib/dialects/hpux/` added | `the build system can select 'hpux' and the ledger does not mention it` |
  | `aix` given a CI job | `'aix' is waived as unbuilt, but .builds/aix.yml:1 mentions it — stale waiver` |

  The third is the one that keeps a waiver honest: a waiver is a falsifiable
  claim that nothing builds this, not permission to stop looking (LESSONS #037).
  Zero discovered platforms and zero discovered CI configs are both hard
  failures, because a glob that quietly stops matching is how this control would
  rot into a green tick (LESSONS #036, #039).

- **Kit change:** `harnesses/platforms/check_platforms.py` (14 self-tests, three
  of which pin that a comment, a `name:` label and a bare key are NOT evidence
  while the same string in a `run:` line IS) plus `harnesses/platforms/platforms.toml`,
  wired into `make check-kit`. `skills/porting-kit-audit/SKILL.md` now runs the
  ledger instead of describing the procedure.
- **Section amended:** `porting-kit/harnesses/platforms/`, `porting-kit/Makefile`,
  `porting-kit/skills/porting-kit-audit/SKILL.md`

## 055. `continue-on-error` is a step property; `timeout-minutes` is a job property

**What happened.** The observe-first miri arm for `lsof-backend-linux` was
added as a `continue-on-error: true` STEP inside the existing, promoted miri
job. It ran long, the job's `timeout-minutes: 25` fired at 25m15s, and the
**hard gate went from `success` to `cancelled`** — broken by a step explicitly
marked as not blocking, on its first run.

**Why the exemption did not hold.** `continue-on-error` exempts a step's own
*failure*. It cannot exempt anything the runner does to the **job**: a
timeout, a lost runner, a cancellation. Those cross the step boundary, so an
observe-first step inside a gated job is not actually observe-first — it is a
new way for the gate to fail, wearing a label that says it is not.

**The rule.** *A trial arm gets its own job, never a step in a gated one.*
Isolation is the only thing that makes "this does not block" true, because it
is the only thing that puts the job-level failure modes on the trial arm's
side of the fence. A generous `timeout-minutes` on that job is then free: the
job cannot take anything else down with it.

**Worth noticing about the cost, too.** The same command finishes in ~295s
locally and had emitted no `test result:` line after ~24 minutes on the
runner, because miri prints a
`files in /proc can bypass the Abstract Machine` warning — with a backtrace —
for every access a `/proc`-reading crate makes. A sanitizer arm over a crate
whose whole job is reading `/proc` is not priced like one over a pure library,
and that is a reason to isolate it rather than a reason to skip it.

**Kit change:** PLAYBOOK Phase 4 — the observe-first promotion rule
(LESSONS #013) now says *job*, not *step*, and says why.
**Section amended:** PLAYBOOK · Phase 4 gate 4.

## 056. A fuzz target can name a parser it never reaches — plant a fault and watch

**What happened.** `/proc/net/packet` got a parser, and the repository's
`proc_net` fuzz target got a line calling it. Sixty seconds, 133,262 runs, no
crashes. The target's header comment now listed `packet` among the tables it
covers, CI ran it on every push, and the whole thing was worth nothing.

The parser **validates the table's header line** before reading a row, because
the C does (`get_pack()`) and because a table read by fixed column index needs
it. That header is about sixty specific bytes. libFuzzer starts from an empty
corpus and mutates; it is not going to produce
`sk               RefCnt Type Proto  Iface R Rmem   User   Inode` by chance,
and coverage feedback cannot help because nothing rewards getting the first
four bytes right when the fifth still fails.

Measured, by planting `assert!(inode == 0)` inside the row loop — a fault that
fires the instant any row parses:

```
with the valid header prepended to the input    panic in seconds
input passed bare, same budget                  81,567 runs / 46 s, never fired
```

**The general shape.** A parser with a *gate* at its entrance — a magic number,
a version field, a checksum, a header line — is unreachable to a fuzzer that
has to guess the gate. The target compiles, runs, reports coverage and finds
nothing, and every signal you have says it is working. This is LESSONS #019
(*a control the kit asserts but never checks for does not exist*) wearing the
one costume that survives a code review: the call **is** there.

**What to do.** Feed the gate, and keep the bare input too — they test
different things:

```rust
t.parse_packet(&text);                       // the header check itself
t.parse_packet(&format!("{HEADER}\n{text}")); // everything behind it
```

A seed corpus or a libFuzzer `-dict=` would also work where the corpus is
checked in. This repository's is not — it is grown from empty and cached
between nightly runs — so the fix has to live in the target, where it cannot
be lost by a cache eviction.

**How to know.** The only reliable check is the one above: **plant a panic at
the deepest point the target claims to reach, and confirm the fuzzer finds it
inside the CI time budget.** Not that the target compiles, not that coverage
went up, not that the corpus grew. Do it once per target, when it is written.
Same discipline as LESSONS #026 for tests and #027 for build reachability: a
gate you have not seen fail is a gate you have not tested.

- **Kit change, found while writing this entry and the same shape as it.** Two
  sessions working this repository in parallel both wrote a lesson `032` — one
  as `## 032.`, the canonical heading, and one as `### #032`, invented on the
  spot for a follow-up placed inside an earlier section. Every `LESSONS #032`
  citation in the tree then resolved to the wrong lesson, and
  `check_lesson_refs.py` was **green throughout**.

  It has a duplicate-number check. It could not fire: `ENTRY_RE` reads
  `^## (\d{3})\.` and nothing else, so the off-style heading was never an
  entry at all. The gap check could not fire either, for the same reason. **A
  checker that recognises one form of the thing it counts is blind to every
  other form, and blind in the direction that reads as success** — the file
  looked like it held the lesson, the citations looked like they resolved, and
  both were false.

  So the checker now also rejects a heading that *looks* like an entry and is
  not one: `### #034 —`, `## 34.`, `#### 007:`. Zero of those exist in the
  current file, which is the only reason the rule can be strict. The stray
  entry is renumbered and moved into the series, and the section it used to sit
  under keeps a one-line pointer to it.

  **Then it happened again, twice, on the merge that carried this entry.**
  Master had meanwhile gained its own `034` and `035` from the parallel branch,
  so the two numbers written here — one of them *this* entry — collided the
  moment the branches met, and moved again at every merge with master since.
  A number a branch assigns is provisional until the branch lands; an entry
  does not know its own number. The next number in an append-only log is
  shared mutable state that git cannot merge, and two sessions days apart
  will take it twice; this is not a rare race.

  What caught it was **git**, not a harness: both branches appended at the end
  of the same file, so the merge conflicted. That defence is real but partial —
  it works only because both wrote at the same place. The original `032` was
  inserted *mid-file* and merged cleanly, which is exactly why it went
  unnoticed. The checker is the part that covers that case: after this change
  any duplicate number fails, in either heading style, wherever it sits.
- **Section amended:** `porting-kit/harnesses/lessons/check_lesson_refs.py`

## 057. A procedure carried out by hand five times is a harness that was not written

- **Date:** 2026-09-20
- **Codebase:** the Porting Kit vendored here — `LESSONS.md` itself, on a branch
  that met master five times before landing
- **What happened:** #048 recorded the collision procedure — the side that landed
  first keeps its numbers, the other block shifts as a unit, every citation to it
  is repointed — and chose procedure over tooling: *"the controls that enforce it
  already exist."* They enforce *existence*. On one pull request the procedure
  then ran five times by hand. The fourth run used `sed`, in two sequential
  passes, and repointed three of four citations to the wrong entry with
  `check_lesson_refs` green, because a wrong citation still resolves (#046).
  Mechanising the fifth run, and then **replaying the real conflict through the
  mechanism**, found two more things the four hand runs had carried unseen:

  1. **A displaced paragraph.** Nine lines of #021 (*"Closed the same day…"*)
     had been cut out of their entry by an ordinary edit in this branch's own P3
     commit — not by a merge — and were riding at the tail of whatever the
     branch's newest entry was, through four merges and a green board. Nothing
     reads entry *content*: the duplicate and gap checks are satisfied by
     headings, and a paragraph that moves leaves both intact.
  2. **A stale in-log cross-reference.** The follow-up appended to #021 said
     `See LESSONS #034` — the number this branch's continue-on-error lesson had
     carried two renumberings earlier. It resolved, to an unrelated entry.
     `check_lesson_refs` deliberately does not read the log as a *source* of
     citations, and every hand repoint grepped for the number the lesson had
     *just* left, never the one before that.

  Both have #046's shape: text that is wrong resolves, so no existence check can
  see it, and to a reader `#034` looks like any other citation.

- **Why a tool and not a better checklist:** the procedure needs one input a
  reader cannot supply reliably — **which side wrote each `#050`**. In a
  collision the token is on both sides and means a different lesson on each;
  nothing in the text tells them apart. git does. `resolve_collision.py` rebuilds
  the merge from BASE, KEEP and MOVE: the shared entries three-way merged (a
  conflict there is refused as an edit conflict, not a collision), KEEP's block
  verbatim, MOVE's block renumbered — headings, citations and re-cited
  destinations rewritten in one pass computed on the original text — and every
  other file's citations repointed by **line provenance**: a line KEEP has is
  KEEP's and stays, a line it lacks is MOVE's and moves, a line both sides added
  that the fork lacked is refused. Then the strict-against-loose list #048 asked
  for: every `#N` on a moving-side line that names a moved number and was not
  rewritten is printed for a human. Finding 1 is now a refusal (text deleted
  from a shared entry on the moving side that reappears in its block); finding 2
  is what provenance repoints, pinned by a fixture that adds a moving-side
  citation to an *old* entry.

- **Proven on the real conflict, not only on fixtures:** replaying this branch
  against master in a scratch clone, the tool first **refused**, naming #021 and
  eight of its nine lines (the ninth, `large.`, is shorter than the check's
  floor) — that is how finding 1 surfaced. With the moving side repaired it
  produced `LESSONS.md`, `CHANGELOG.md`, the L2 plan and `PLAYBOOK.md`
  **byte-identical** to the hand resolution plus the repair. Its 26-check
  self-test was then mutated ten ways — provenance always-keep, ambiguity never
  refused, displaced text never refused, split range never refused, contiguity
  unchecked, prefix conflict taken silently, arrow destinations left alone,
  range members unwalked, edits applied front-to-back, prefix tail unnormalised
  — and every mutant failed it, none by Traceback. The first draft refused the
  real conflict for a *wrong* reason: the three prefixes differed only in their
  trailing bytes (`` `\n`` / `` `\n\n---\n\n`` / `` `\n\n``) and a line-based
  merge called that both sides editing one line. That is why "replay the real
  thing" is in this entry and not just "write fixtures".

- **First live run, the same day** — the sixth collision: another branch had
  landed on the very number this branch's first new entry carried, with two
  more behind it. The plan was right on every file it scanned and silent about
  one it never visited: the walk's suffix list had no entry for `Makefile`, so
  the check-kit comment citing *this* entry was invisible to `check_lesson_refs`
  and to the resolver alike. Scanned, the same comment surfaced a second
  blindness in the REVIEW list: the citation wraps onto a second comment line,
  and the `@#` between the separator and the member meant the member was never
  read — by either tool, for as long as the kit has had that comment. The
  flatten step both tools share now swallows a continuation line's comment
  marker (and only that: `\n#8)` keeps its hash, which is the member's own).
  It also offered to renumber a real-looking example `Local:` marker in the
  tool's own comment — examples now read `#NNN`. Two findings the loose pass
  made and the strict rules could not have: the list exists so that what the
  rules do not recognise is seen rather than kept.
- **Kit change:** `harnesses/lessons/resolve_collision.py` (new); `make check-kit`
  runs its self-test; three rows in the gate-mutation table, one per verdict,
  because one row would pin only their union (#050).
- **Section amended:** README · harness table and the vendoring note; Makefile ·
  check-kit; harnesses/gate-mutation/mutate_gates.py · MUTATIONS;
  OPERATING-GUIDE · closing note.
- **Follow-up, 2026-09-20 — the cherry-pick case.** A picked commit's base is a
  *branch* commit, not a master one, so a citation in it means what the **fork**
  called that number — and the fork's own appended lessons have since landed
  under other numbers. Mapping only the appended block would leave such a
  citation resolving, silently, to whatever KEEP holds at that number today:
  the #046 shape, produced by the tool meant to prevent it. The resolver now
  follows a fork entry into KEEP **by title** and repoints the picked commit's
  citations with it; a fork entry KEEP no longer has under any title is
  *orphaned*, and citations of it go to the review list rather than being
  guessed. In a plain merge both sets are empty by construction — the fork is
  a KEEP commit, and a landed entry never moves. Pinned by two fixtures
  (self-test 28 → 31). Reasoned out before the first cherry-pick that could
  have hit it, which turned out to cite none of the moved entries — the first
  change to this tool made ahead of the failure instead of after it.
