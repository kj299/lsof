# Side quest — what in this repository is not part of the rewrite

**Status: executed 2026-09-16.** This document is now a record, not a proposal.
It was a side quest: it closed no DIVERGENCES entry and no gate, and it did not
preempt [`linux-l2-plan.md`](linux-l2-plan.md).

## The rule that governed the exercise

The instinct on seeing 218 files of C in a Rust rewrite is that they are the
old thing being replaced. **They are not. They are the oracle.** The
`differential (linux, vs the C)` job builds `lsof` from this tree on every run
and diffs it against `lsof-rs` over 87 cases — the strongest correctness signal
this project has, and the one the Windows backend structurally cannot have.

So the boundary was never *C vs Rust*. It was: **does this file participate in
building, testing, or documenting the oracle and the port?**

## What was removed

128 files, 31,088 lines (523 → 395 tracked files).

| Group | Files | Why it was unreachable |
|---|---|---|
| `lib/dialects/{hpux,osr,uw}` | 66 | In neither `configure.ac` nor `Makefile.am`; every other dialect has an `AM_CONDITIONAL` **and** a `LSOF_DIALECT_DIR` branch |
| `support/` | 35 | Purdue's FTP/rdist release machinery — dead mirror URLs, an `install.log` for lsof 4.84, a 0-byte `.xls`. Zero inbound references |
| `scripts/` | 13 | Contributed Perl/AWK field-output examples, not even in `EXTRA_DIST`. The two pointing sentences in `docs/{faq,tutorial}.md` went with them |
| `00MANIFEST`, `Inventory`, `.ck00MAN`, `tests/Add2TestDB` | 4 | See below |
| `AFSConfig`, `Customize`, `zipme`, `Doxyfile`, `HOW_TO_*.rst`, `0..README.BEFORE.README.FIRST` | 7 | Unreachable under `Configure -n` (what CI uses), or hardcoded to a maintainer's machine, or redirect stubs nothing links to |
| `.travis.yml`, `.circleci/`, `.readthedocs.yaml` | 3 | CI and docs builds this fork does not own |

**The inventory triangle is worth singling out.** `00MANIFEST` is a literal file
listing that still described the pre-autotools layout — `dialects/`, root-level
`main.c`, `scripts/*.perl5`. **223 of its 280 entries already dangled** before
anything was deleted. `Inventory` walks that list, so running it on the
*unmodified* tree printed `SOME FILES OR DIRECTORIES MAY BE MISSING!`. A check
that can only fail is not a check.

## Two things inspection would have condemned, and the build spared

This is the argument for compiling the tree rather than reading filenames.

- **`tests/{Makefile,TestDB,CkTestDB}`** look like a dead pre-autotools harness.
  They are live: `tests/case-13-classic.bash` and `case-14-classic-opt.bash` do
  `cd tests && make`, and `check.bash` runs both on the macOS job. Deleting them
  flipped `case-14` to failing. **Kept.**
- **`lib/ptti.c` is 0 bytes**, but `lib/Makefile.skel` names it three times, so
  removing it breaks the legacy build (`No rule to make target 'ptti.c'`).
  **Kept** — not worth two build-file edits for an empty file.

Relatedly: `AUTHORS` and `NEWS` are empty and **must stay**. `AM_INIT_AUTOMAKE`
carries no `foreign`, so gnu strictness applies and `autoreconf` fails with
`required file './AUTHORS' not found`. Same for `ChangeLog`, `INSTALL`,
`README`, `COPYING`.

## Verification

Every row run on the resulting tree, with the unmodified tree as control:

| check | result |
|---|---|
| `autoreconf -vif && ./configure` | rc=0 |
| `make` | rc=0, binary reports `4.99.6` |
| `make check` | 36 PASS / 3 SKIP / 2 FAIL — **identical case set to the control** |
| `make dist` | rc=0 |
| `make distcheck` | dist/unpack/reconfigure/rebuild clean; dies only at the same 2 cases |
| `./Configure -n linux && make` (the legacy path `build.yml`'s macOS job uses) | rc=0; `check.bash` case-13/case-14 match control |
| 17 `lsof` invocations, new binary vs control binary, same live process | **0 differ** |

The 2 failures (`case-20-mmap`, `case-20-ux-socket-endpoint`) are pre-existing
container-environment failures present on the unmodified tree.

## Not taken, deliberately

`lib/dialects/{aix,darwin,freebsd,netbsd,openbsd,sun}` — **81 files, 35,531
lines** — are wired into `Makefile.am`. `make lsof` survives their deletion and
the differential still passes 87/87, but **`make dist` does not**:

```
make[2]: *** No rule to make target 'lib/dialects/darwin/ddev.c', needed by 'distdir-am'.
```

Removing them means editing `Makefile.am` and `configure.ac` to drop six
conditionals **and** deleting `build.yml`'s macOS job, `.cirrus.yml` (FreeBSD)
and `.builds/*` (NetBSD/OpenBSD). It converts the repo from *"lsof, forked,
carrying a Rust port"* into *"a Linux/Windows lsof port with a Linux-only C
oracle"*, and permanently forecloses diffing against the C on macOS or BSD.
That is a product decision, not a tidiness one, and it remains open.

Also untouched: the oracle itself (`lib/` non-dialect, `lib/dialects/linux/`,
`src/`, `include/`), the build system, `Lsof.8`, `tests/`, and the licence and
attribution files. **`COPYING`, `AUTHORS` and `00CREDITS` are not negotiable** —
this is a fork of a licensed work.

## Not a deletion, and the highest-value item

The root `README.md` was still upstream's: four CI badges pointing at
*lsof-org's* CircleCI, Cirrus, sr.ht and ReadTheDocs — none of them this
repository's CI — and no mention of the Rust rewrite that has been the
repository's entire activity. Rewritten in its own commit, ahead of every
deletion here.

## Housekeeping note

`lsof-rs/target` and `lsof-rs/fuzz/target` are ~1.8 GB of gitignored build
output. Irrelevant to the repository, relevant to a container's fixed disk
allowance: `cargo clean` in both reclaims it when a session runs short.
