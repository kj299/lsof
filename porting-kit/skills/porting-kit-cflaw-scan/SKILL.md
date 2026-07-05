---
name: porting-kit-cflaw-scan
description: Hunt vulnerability classes in C source before porting, and triage each into the divergence ledger. Use during Phase 0, before translating a module, or whenever the user wants to find memory-safety / injection / TOCTOU risks in C code that a Rust port should fix rather than faithfully reproduce.
---

# Porting Kit — C vulnerability hunt + triage

Wraps `porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py`. Grounds the prime
directive "the C may be buggy — don't re-port a CVE" (RETROSPECTIVE §9).

## Procedure
1. **Scan** the C tree:
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py <c-src-dirs>`
   Categories: unbounded-copy (CWE-120), format-string (CWE-134),
   int-overflow-mul (CWE-190), command-exec (CWE-78), toctou (CWE-367),
   stack-vla-alloca (CWE-770).
2. **Check signal-to-noise before trusting it** (LESSONS #2 — this exact tool once
   produced 828 false format-string positives on lsof, burying ~215 real
   candidates, until it was fixed to locate the true format-position argument).
   If a category is implausibly large, inspect a sample; a scanner that cries wolf
   gets muted. If you improve the scanner, run its self-test:
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py --self-test`
3. **Triage every hit**: does the Rust port close it? For each confirmed flaw, add a
   `DIVERGENCES.md` entry — `- [x] <case>: <why + CWE>` — so the fix is (a) planned,
   (b) surfaced (never silently patched — the most dangerous UB option), and (c)
   shipped as a release note. This is the "decide in writing what you do with UB"
   policy, mechanized.
4. Feed confirmed flaws into `THREAT-MODEL.md` §6 and into the module's test vectors
   (add a boundary/hostile-input case that exercises the fix).

## Note
This is a fast heuristic, not a full SAST pass — it bootstraps the flaw inventory in
minutes. For depth, add clang-analyzer / CodeQL / cppcheck; this skill just makes
sure the hunt *happens* before translation, not after a CVE is faithfully reproduced.

## Integrity
Paths/flags/categories must match `scan_c_flaws.py`. If they drift, fix the reference
and re-run `make -C porting-kit check-kit`.
