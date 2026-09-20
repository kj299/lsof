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

---

### #032 — `continue-on-error` is a step property; `timeout-minutes` is a job property

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

  **Closed the same day.** The obstacle was never difficulty — it was that the
  parsers sat inside `#[cfg(windows)]` while the fuzz job runs on Linux, so
  nobody could have written the target without moving them first. They are pure
  string transforms; hoisting them into an ungated `names` module took an hour,
  the target found two bugs *in its own assertions* within a minute, and the
  crate's unit tests went from running on one platform to running on all of
  them. When a per-unit gate has been unmet for months, check whether the unit
  is simply unreachable from where the gate runs before concluding the work is
  large.

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
