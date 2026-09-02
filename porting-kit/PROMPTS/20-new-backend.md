# Prompt — add a backend for a second platform

Paste this when a port that already ships on one platform is to gain another.
It exists because lsof-rs's second backend (Linux, after Windows) was run as
"a few PRs" and not as a port loop, and the retrospective found the difference:
the loop's gates were applied to the first backend and skipped for the second
(LESSONS #017, #019, #021).

---

The `[PROJECT]` port ships on `[PLATFORM A]`. Add a `[PLATFORM B]` backend.

0. **Decide what a second platform changes, before code.** Write a scoping note
   (lsof-rs: `docs/linux-backend-scope.md`) that answers, with numbers: which
   crates are untouched (the portable core should be), which `core` types need
   a variant the new platform has and the old one lacks, an effort estimate per
   phase, and the two questions the kit knows will come up —
   - **the project's name**, if it encodes the first platform. Decide it *here*;
     lsof-rs decided after phase L1 and paid one more release under the old
     prefix and a 92-file rename PR (LESSONS #020).
   - **the coverage inventory's waivers.** Any reason that names a platform
     ("Unix-only", "no `[A]` equivalent") is about to become false. Scope them
     with `platforms = [...]` and run the gate with `--platform` for each
     platform *before* the new backend's first phase, or the gate will excuse
     exactly the features you are about to build (LESSONS #018).

1. **Ask whether the reference implementation runs on `[B]`.** If it does, you
   have something the `[A]` backend never had: a same-host oracle for *every*
   line of shared code. Build the C-vs-Rust differential for `[B]` **first** and
   treat its findings as cross-platform until proven backend-local — lsof-rs's
   found three renderer bugs that had shipped in every `[A]` release (LESSONS
   #017). Do not run it by hand and call it done; wire it as the differential
   gate for `[B]`.

2. **One backend crate per platform.** `[PROJECT]-backend-[b]`, gated
   `#[cfg(target_os = "...")]` at the crate root so every other target compiles
   it to an empty shell (the existing cross-check CI must stay green with both
   crates in one workspace). It may be `#![forbid(unsafe_code)]` — if `[B]`'s
   data source is a filesystem or a documented API, it should be. The unsafe
   audit runs per crate.

3. **Run the six-gate loop per module of the new backend**, exactly as
   `10-module-port.md` describes, with one entry made explicit because it was
   the one skipped: **a fuzz target per text-parsing module.** A backend that
   parses kernel- or OS-supplied text (`/proc`, registry values, `sysctl`
   output) is parsing input it does not control; a panic there is a release
   blocker under the kit's own rule, whether or not the crate has `unsafe`.

4. **Create the ledgers on day one, not at 1.0** — `progress.json`, the
   divergence ledger, the fuzz targets — and run
   `harnesses/ledgers/check_ledgers.py` in CI so their absence fails the build
   (LESSONS #019). The first backend shipped 1.0 without any of them.

5. **Field checkpoint for `[B]`** (LESSONS #015): the exact release artifact on
   real `[B]` hardware, every privilege mode, per-case time ceiling, logged.

6. **Degrade honestly.** Where the new backend cannot yet classify something
   (lsof-rs L0: sockets), emit the truthful unresolved row and say so at
   startup — never an empty result that looks like a filter working. Record
   each gap as coverage **debt** naming the phase that closes it, not as a
   waiver: a waiver claims "never".

Report: the scoping note's estimate versus actual, every cross-platform finding
the `[B]` differential produced, and which of the six gates each new module has
cleared — then run `90-retrospective.md`.
