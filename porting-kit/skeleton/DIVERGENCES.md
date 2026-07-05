# Intentional divergences from the C original

Every place the Rust port **deliberately** behaves differently from the C. The
differential harness (`diff_run.py --ledger DIVERGENCES.md`) reads this file:
a case listed here as `- [x]` is a *known-intentional* divergence and is
suppressed (reported as `DIVERGE(ledgered)`, not a failure). Everything else that
diverges is an unexplained regression and fails CI.

**This file is a feature, not an apology.** The prime directive is that the C may
be buggy; where you fixed a C defect, the Rust *should* diverge — record it here
and ship it as a release note. Seed this from the Phase-0 C-flaw scan.

Format — one bullet per case name, ticked when reviewed and accepted:

```
- [x] <matrix-case-name>: <why the Rust intentionally differs; CWE if a security fix>
```

## Security fixes (C defect closed by the port)

- [ ] _example_ `oversized-token`: C `strcpy`'d into a 16-byte stack buffer
      (CWE-120 stack overflow); Rust bounds the copy and returns an error. The
      normalized outputs differ because C crashed/garbled and Rust reports
      cleanly.

## Behavioral improvements (not security, but deliberate)

- [ ] _example_ `json-format`: Rust emits RFC-8259-strict JSON (escaped control
      chars); C emitted raw bytes. Downstream parsers get valid JSON now.

## Platform / environment differences

- [ ] _example_ `version`: version string carries the Rust build metadata.
