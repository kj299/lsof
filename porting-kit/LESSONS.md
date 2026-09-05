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
