# Side quest — what in this repository is not part of the rewrite

**This is a side quest.** It is not the porting objective, nothing in it closes
a DIVERGENCES entry or a gate, and it should never preempt
[`linux-l2-plan.md`](linux-l2-plan.md). Written 2026-09-15 by measuring the
tree and building it, not by reading filenames.

## The rule that governs the whole exercise

The instinct on seeing 218 files of C in a Rust rewrite is that they are the
old thing being replaced. **They are not. They are the oracle.** The
`differential (linux, vs the C)` job builds `lsof` from this tree on every run
and diffs it against `lsof-rs` over 87 cases, and that is the strongest
correctness signal this project has — the one the Windows backend structurally
cannot have. Deleting the C to "clean up the rewrite" would destroy it.

So the boundary is not *C vs Rust*. It is: **does this file participate in
building, testing, or documenting the oracle and the port on the two platforms
this project targets?**

## What the repository actually is

522 tracked files. The 1.8 GB on disk is **not** repository content — it is
`lsof-rs/target` (1.1 GB) and `lsof-rs/fuzz` (725 MB), both correctly
gitignored. Every autotools artefact at the root (`configure`, `Makefile.in`,
`libtool`, `config.status`, `aclocal.m4` …) is untracked build residue.
There is no upstream remote: `origin` is the fork, and the history has no
upstream merges, so nothing here is protecting a future sync.

Two CI workflows are live over the C tree, and they constrain everything below:

| workflow | what it does to the C | consequence |
|---|---|---|
| `lsof-rs-ci.yml` → `differential-linux` | `autoreconf && ./configure && make lsof` | needs the **Linux** dialect and the build system |
| `build.yml` → `linux` | `make`, **`make check`**, **`make distcheck`** | needs every file in automake's DIST list — *including inactive conditional branches* |
| `build.yml` → `macos` | `./Configure -n darwin`, `bash ./check.bash darwin` | needs the **legacy `Configure`**, `check.bash`, `tests/`, and `lib/dialects/darwin/` |

That third row is why this is not a filename exercise. `make dist` pulls in
sources from *all* `Makefile.am` conditionals, not just the active one.

## Tier 0 — never touch

The oracle's sources (`lib/` non-dialect, `lib/dialects/linux/`, `src/`,
`include/`), its build system (`configure.ac`, `Makefile.am`, `m4/`,
`autotools/`, `version*`), `Lsof.8` (cited throughout the coverage inventory
and every `-F`/`-T` measurement), the C test suite `tests/` (it is `make
check`), and `lsof-rs/` + `porting-kit/` themselves.

**`COPYING`, `AUTHORS`, `00CREDITS` are not negotiable** — this is a fork of a
licensed work, and attribution stays regardless of tidiness.

## Tier 1 — safe to delete, proven by building it

`lib/dialects/hpux`, `lib/dialects/osr`, `lib/dialects/uw` — **66 files,
21,634 lines.**

They appear **nowhere** in `configure.ac` or `Makefile.am`. Every other dialect
has an `AM_CONDITIONAL` and a `LSOF_DIALECT_DIR` branch; these three have
neither. They are pre-autotools carry-over, unreachable by any build this repo
performs.

Evidence, on a scratch clone with all three deleted:

| check | result |
|---|---|
| `autoreconf -vif && ./configure` | rc=0 |
| `make lsof` | rc=0, binary reports `revision: 4.99.6` |
| `make dist` | rc=0, produced `lsof-4.99.6.tar.gz` |
| the full 87-case differential against that oracle | **0 unexplained divergences** |

**One residual risk, stated plainly:** `make check` could not be evaluated
here — it dies at `soelim: command not found` because this container has no
groff. A control run on the *pristine* tree fails at the identical line, so the
deletion is exonerated of causing it, but "no regression signal" is not the
same as "passes". CI must close that, which it does for free on the first push.

Deleting them makes stale: `00MANIFEST` (a literal file listing, and in
`EXTRA_DIST`), `00DIALECTS`, `00DCACHE`, `00DIST`, `00FAQ`, `00PORTING`,
`00README`, `00TEST`, `00XCONFIG`, `Configure`, `Lsof.8`, and five files under
`docs/`. Most references are prose or `#ifdef HPUX` guards that are harmless to
leave; **`00MANIFEST` is the one that must actually be edited**, because
`Inventory` checks the tree against it.

## Tier 2 — needs a decision, not just a deletion

`lib/dialects/{aix,darwin,freebsd,netbsd,openbsd,sun}` — **81 files, 35,531
lines.**

`make lsof` succeeds without them and the differential still passes 87/87 — but
**`make dist` fails**:

```
make[2]: *** No rule to make target 'lib/dialects/darwin/ddev.c', needed by 'distdir-am'.
```

So deleting them means editing `Makefile.am` and `configure.ac` to drop six
conditionals, **and** deleting `build.yml`'s macOS job (it builds darwin),
`.cirrus.yml` (FreeBSD) and `.builds/*` (NetBSD/OpenBSD).

That is a real decision and it is the owner's: it converts the repo from *"lsof,
forked, carrying a Rust port"* into *"a Linux/Windows lsof port with a
Linux-only C oracle."* The port targets two platforms, so nothing is lost
functionally — but it forecloses ever diffing against the C on macOS or BSD,
which is the only way those dialects could ever serve this project.

**Recommendation: do not do this yet.** Tier 1 gets 21,634 lines for no
argument; Tier 2 gets 35,531 more in exchange for a door closing. Take Tier 1,
see whether the repo still feels cluttered, and decide Tier 2 separately.

## Tier 3 — foreign CI, dead for this fork

`.travis.yml`, `.circleci/config.yml`, `.cirrus.yml`, `.builds/netbsd.yml`,
`.builds/openbsd.yml`, `.readthedocs.yaml` — 6 files. None runs; this fork uses
GitHub Actions only. Note the last three pair with Tier 2 dialects, so if Tier 2
is declined, `.cirrus.yml` and `.builds/*` are arguably still *documentation* of
where those dialects get tested upstream. `.travis.yml` and `.circleci/` have no
such defence — Travis is defunct and the CircleCI badge points at `lsof-org`.

## Tier 4 — updates, which matter more than the deletions

**The root `README.md` is the highest-value item in this document.** It is
upstream's, it opens with four CI badges pointing at *lsof-org's* CircleCI,
Cirrus, sr.ht and ReadTheDocs — none of which is this repo's CI — and it does
not mention the Rust rewrite at all. It is the GitHub landing page for a
repository whose entire activity for months has been `lsof-rs/`.

Also stale, already noted in the L2 plan and repeated here so this side quest
has one list:

- `lsof-backend-linux/src/lib.rs` — header still opens "Phase L1" and lists five
  shipping features as deferred
- `docs/linux-backend-scope.md` — its L2 row is superseded by `linux-l2-plan.md`
  and should say so
- `00MANIFEST` — if anything in Tier 1 lands

## Tier 5 — not repository content

`lsof-rs/target` and `lsof-rs/fuzz/target` are 1.8 GB of gitignored build
output. Irrelevant to the repo, relevant to this container's fixed disk
allowance: `cargo clean` in both reclaims it when a session runs short.

## Recommended execution order

1. **Tier 4's README** on its own. One file, no build risk, largest visible
   effect. Do it first and independently of every deletion below.
2. **Tier 1 + its `00MANIFEST` edit**, in one PR, with the PR body carrying the
   four build results above so a reviewer is not asked to take "unused" on
   faith. Expect `build.yml` to run — this touches the C tree — and treat its
   `make check` / `make distcheck` as the gate that closes the residual risk.
3. **Tier 3's `.travis.yml` and `.circleci/`** — trivial, can ride with (2).
4. **Tier 2 only on an explicit decision**, and if taken, in its own PR with
   the `Makefile.am`, `configure.ac` and workflow edits together, because
   splitting them leaves `make dist` broken in between.
5. **Tier 4's remaining doc fixes** fold into the L2 plan's P1 pass; they are
   the same edits and should not be done twice.

## What this side quest should not do

Touch the oracle, the Linux dialect, `tests/`, `Lsof.8`, the licence files, or
anything under `lsof-rs/` and `porting-kit/` beyond the doc fixes named in
Tier 4. And it should not run before P1 of the L2 plan — that pass ships a real
feature (`-H`) and fixes a coverage gate that is currently wrong on both
platforms. Tidiness does not outrank a live gap.
