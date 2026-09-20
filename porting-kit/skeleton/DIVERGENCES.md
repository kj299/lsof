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
- [x] <matrix-case-name> [sha256:<12-hex>]: <why the Rust intentionally differs; CWE if a security fix>
```

**Pin the fingerprint.** Without the `[sha256:…]` the entry suppresses by case
*name*, forever — any future, unrelated regression in that case reports
`DIVERGE(ledgered)` and exits 0. The most-exercised cases are the most likely to
be ledgered, so an unpinned ledger makes the gate weakest exactly where behavior
changes most. `diff_run.py` prints the exact pin to paste for every unpinned
entry; with it, a divergence that *changes shape* fails again and asks for
re-triage.

A ledger entry **asserts** a divergence, it does not merely suppress one: a
ledgered case that stops diverging is reported `LEDGER-STALE` and fails, because
the likeliest cause is that the fix the port exists for got reverted.

If a case name contains a `:`, backtick-quote it — ``- [x] `parse:header`
[sha256:…]: why`` — or it truncates at the colon and silences the wrong case.

Lines inside a ``` fence (like the one above) are format documentation and are
not harvested as entries.

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
