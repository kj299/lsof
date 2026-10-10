# CI and release mechanics

Detail pushed out of [`PLAYBOOK.md`](PLAYBOOK.md), which keeps a summary of
each and the lessons it cites. Every rule here was bought by lsof-rs; the
lesson behind each is cited where it is stated.

## Gates that can only run in CI

**When a gate can only run in CI** — a platform backend you can't build on the
dev host (lsof-rs's Windows crate on a Linux box) — land it *observe-first*
(continue-on-error) and read a few real runs before promoting it to a hard gate,
so a flaky harness doesn't wedge every PR (LESSONS #9). Two traps: (a) give an
infra/harness error a **distinct exit code** from a real failure, or the noise
trains you to ignore red; (b) **a superseded CI run is not a passed run** — rapid
pushes cancel in-flight runs, so "I saw green" can mean an *earlier* commit while
the head commit's gate never finished. Before calling a CI-only-validated change
green, confirm the head SHA has a *completed* run — lsof-rs's `too_many_arguments`
clippy error slipped in exactly this way: its Windows run was cancelled by the
next push and the lint surfaced only two commits later. And (c) **while a gate
is in observe mode, job status is meaningless** — `continue-on-error` shows a
green job over a failing step, so verdicts must be read from the step's own
log or uploaded artifact (upload results with `if: always()`, or observing is
theater). And (d) **put the trial arm in its own JOB, never a step inside a
gated one** — `continue-on-error` exempts a step's own failure, but
`timeout-minutes`, runner loss and cancellation are *job* properties and cross
that boundary. lsof-rs added an observe-first miri step to its promoted miri
job; the step ran long, the job's 25-minute timeout fired, and the hard gate
went from success to **cancelled** on the trial arm's first run — broken by
something labelled as not blocking (LESSONS #055). Isolation is what makes
"this does not block" true, and it makes a generous timeout on the trial arm
free. Promotion mechanics that worked (LESSONS #13): the bar is
*consecutive log-verified green runs*; flip the flag **in its own PR**, so the
newly-hard gate must pass on the promotion PR itself before it can merge — the
promotion is validated by the mechanism it enables.

## Releasing

- **Design the release trigger with a human-button fallback** (LESSONS #14):
  lsof-rs's release workflow fires on a tag push *or* `workflow_dispatch` with a
  tag input, and the dispatch path — where `gh release create --target` makes
  the tag server-side — is what shipped v0.3.0 when the automated session
  turned out to lack both tag-push and dispatch permission. Target the tag's
  own commit when the tag exists, not `$GITHUB_SHA`, the branch a dispatch ran
  from: a dispatch for an existing tag otherwise republishes that branch's head
  under the old version. lsof-rs's workflow builds from the tag, and replaces a
  published release only when its `replace` input is ticked.
  Preflight those permissions before declaring release-ready (Phase 3), and
  verify the *published* release from its public page rather than the API — a
  quota-free check that also proves what users actually see (assets, target
  SHA, checksum).
- Long automated sessions: treat the platform **API quota as a budgeted
  resource**. lsof-rs's release day stalled a merge for ~an hour on an
  exhausted hourly limit; back off in growing intervals rather than hammering,
  and prefer public-page reads (no quota) for state checks while it recovers.
- **A release workflow that can fire twice will publish two truths** (LESSONS
  #22): lsof-rs's 1.0.1 notes carried one SHA-256 and the asset another, from a
  double dispatch. Declare a `concurrency` group keyed on the tag; produce the
  checksum and the notes in the *same run* that uploads the asset; and confirm
  from the public page that the published checksum matches the published file
  before announcing.

## Renaming the port

A mechanical rename fails quietly, so it gets three passes (LESSONS #20 —
lsof-rs's `winlsof` → `lsof-rs`, 92 files, four breakages found *after* pass 1):

1. **Inventory case-insensitively** (`find -iname`, `git grep -i`); pass 1
   missed `Invoke-WinlsofSmokeTest.ps1` on a case-sensitive `find`.
2. **Convert by identifier context, never one rule**: `SCREAMING_` → `NEW_`,
   `snake_` → `new_`, kebab → kebab, PascalCase → PascalCase. One rule produced a
   Python variable named `lsof-rs` (does not parse) and a .NET namespace
   `Lsof-rsNative` (hyphens are illegal there).
3. **Protect what must keep the old name** and verify it against the remote:
   published tags (rewriting them makes dead links — the protection regex must
   cover *both* sides of a compare URL), user-facing env vars (alias, don't
   rename — a v1.0.1 binary only knows `WINLSOF_TRACE`), historical entries
   that describe a shipped artifact. Fire the release trigger on both prefixes.
4. **Pass 2 — verify by executing, per category**: syntax-check every tracked
   script (`py_compile`, `bash -n`), build, run every harness, resolve every
   path a workflow names. Reading the diff found none of the four.
5. **Pass 3 — adversarial**: grep for the old name and justify every survivor;
   resolve every markdown link; then push a code-only change and confirm the CI
   path filters still select it — the failure that never announces itself.
