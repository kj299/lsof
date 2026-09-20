#!/usr/bin/env python3
"""Platform ledger — every platform the build system can select is built by some
CI provider, or waived on the record.

This is the executable form of the control LESSONS #049 named and did not build.
That entry found four of six `lsof` dialects were live, tested platforms and that
three of them are tested by Cirrus and sourcehut, which never appear in a GitHub
check list. The procedure it left behind — "enumerate CI providers, not check
runs" — was a sentence in a skill, and by LESSONS #033's standard a sentence
nothing executes is a note, not a control. This fails a build instead.

**The question it answers is not "do the CI files look right".** It is: *for each
platform this build system can select, does some CI configuration actually build
it, and if not, did someone say so on purpose?*

Four properties, each bought by a lesson:

  1. **Platforms are DISCOVERED from the tree, never read from the ledger**
     (LESSONS #042: verifying the artifacts that exist says nothing about the one
     that is missing). Add a dialect and forget the ledger, and this fails —
     which is the only reason the ledger can be trusted to be complete.
  2. **A waiver must ASSERT, not suppress** (LESSONS #037). A waived platform that
     CI turns out to mention is a *stale waiver* and a problem. Waiving is not a
     way to stop looking; it is a claim that nothing builds this, and the claim is
     checked.
  3. **Zero is not a pass** (LESSONS #036, #039). Discovering no platforms, or
     finding no CI configuration at all, is a hard failure. A glob that silently
     stops matching is precisely how this control would rot into a green tick.
  4. **Evidence is reported, not just counted.** Each satisfied platform prints
     the file and line that satisfied it, so a reader can tell a real gate from a
     pattern that happens to match a comment.

Usage:  check_platforms.py [--manifest PATH] [--repo ROOT]
            --manifest defaults to platforms.toml beside this file.
            --repo defaults to the manifest's `repo_root` or the kit's parent.
        check_platforms.py --self-test
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import tomllib

_HERE = os.path.dirname(os.path.abspath(__file__))

# Reused, not reimplemented: the kit's rule is that a second copy of a control
# is a control that will diverge. `executable_text()` is what check_ledgers.py
# learned to do after its sanitizers ledger accepted a header comment as proof a
# job ran (LESSONS #029; LESSONS #031). This harness asks the same shape of
# question — "does CI actually build X" — so it must not accept prose either,
# and the first run of this file proved that is not hypothetical: it certified
# `darwin` on the strength of a COMMENT in build.yml that mentions
# `./Configure -n darwin` while describing something else entirely.
sys.path.insert(0, os.path.join(_HERE, "..", "ledgers"))
from check_ledgers import executable_text  # noqa: E402


def load_manifest(path):
    with open(path, "rb") as fh:
        return tomllib.load(fh)


def discover_platforms(repo, patterns):
    """Every platform the build system can select, read from the TREE.

    Deliberately not read from the ledger: the ledger is the claim under test.
    """
    found = {}
    for pat in patterns:
        for p in sorted(glob.glob(os.path.join(repo, pat))):
            if os.path.isdir(p):
                found[os.path.basename(p)] = os.path.relpath(p, repo)
    return found


def discover_ci(repo, globs):
    """Every CI provider config, found by looking for files (LESSONS #049).

    Not by reading a status list, and not limited to one provider's directory.
    """
    out = []
    for pat in globs:
        for p in sorted(glob.glob(os.path.join(repo, pat))):
            if os.path.isfile(p):
                rel = os.path.relpath(p, repo)
                if rel not in out:
                    out.append(rel)
    return out


def _search(ci_files, repo, patterns):
    """First (relpath, lineno, line) where a pattern matches EXECUTABLE text.

    Each line is passed through `executable_text()` before matching, so a
    comment, a `name:` label or a bare mapping key cannot stand as evidence that
    CI builds something. The reported line number and text are the ORIGINAL
    ones, so a reader sees the real file, not the filtered form.

    Note for anyone writing patterns: the filter strips the key from a
    `key: value` line, so match the VALUE — `netbsd/` rather than
    `image: netbsd`.
    """
    for rel in ci_files:
        try:
            text = open(os.path.join(repo, rel), encoding="utf-8",
                        errors="replace").read()
        except OSError:
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            runnable = executable_text(raw).strip()
            if not runnable:
                continue
            for pat in patterns:
                if re.search(pat, runnable, re.I):
                    return (rel, lineno, raw.strip())
    return None


def run(manifest_path, repo=None):
    if not os.path.isfile(manifest_path):
        print(f"FAIL  no manifest at {manifest_path}")
        return 1
    man = load_manifest(manifest_path)

    if repo is None:
        repo = man.get("repo_root")
        repo = (os.path.join(os.path.dirname(manifest_path), repo) if repo
                else os.path.dirname(os.path.dirname(_HERE)))
    repo = os.path.abspath(repo)

    problems = []

    disc = man.get("discover", {})
    dirs = disc.get("dirs") or []
    if isinstance(dirs, str):
        dirs = [dirs]
    platforms = discover_platforms(repo, dirs)

    # Property 3: zero is not a pass. A glob that stops matching must fail
    # loudly, not report a clean sweep of nothing (LESSONS #036, #039).
    if not platforms:
        print(f"FAIL  discovered no platforms under {repo} via {dirs} — "
              f"a ledger over nothing is not a passing ledger")
        return 1

    ci_globs = man.get("ci", {}).get("globs") or []
    ci_files = discover_ci(repo, ci_globs)
    if not ci_files:
        print(f"FAIL  found no CI configuration under {repo} via {ci_globs} — "
              f"refusing to certify platforms against an empty provider set")
        return 1

    ledger = man.get("platforms", {})

    # Property 1: the TREE decides what must be accounted for.
    for name in sorted(platforms):
        if name not in ledger:
            problems.append(
                f"{platforms[name]}: the build system can select '{name}' and "
                f"the ledger does not mention it")
    for name in sorted(ledger):
        if name not in platforms:
            problems.append(
                f"ledger names '{name}', which the build system cannot select "
                f"(stale entry, or the discover globs no longer match it)")

    rows = []
    for name in sorted(platforms):
        entry = ledger.get(name)
        if entry is None:
            continue
        built_by = entry.get("built_by")
        waived = entry.get("waived")
        aliases = [name] + list(entry.get("aliases", []))

        if bool(built_by) == bool(waived):
            problems.append(
                f"ledger entry '{name}' must have exactly one of built_by or "
                f"waived (has {'both' if built_by else 'neither'})")
            continue

        if built_by:
            hit = _search(ci_files, repo, built_by)
            if hit:
                rows.append(("built", name, f"{hit[0]}:{hit[1]}", hit[2][:58]))
            else:
                problems.append(
                    f"'{name}' claims CI builds it, but none of {built_by} "
                    f"appears in any of the {len(ci_files)} CI config(s)")
        else:
            # Property 2: a waiver is a falsifiable claim, not a mute button
            # (LESSONS #037). If CI mentions it, the waiver is stale.
            hit = _search(ci_files, repo, [rf"\b{re.escape(a)}\b" for a in aliases])
            if hit:
                problems.append(
                    f"'{name}' is waived as unbuilt, but {hit[0]}:{hit[1]} "
                    f"mentions it: {hit[2][:60]!r} — stale waiver, or it is "
                    f"built after all")
            else:
                rows.append(("waived", name, "—", waived[:58]))

    width = max((len(r[1]) for r in rows), default=8)
    for state, name, where, note in rows:
        print(f"  {state:6s} {name:{width}s}  {where:34s} {note}")
    for p in problems:
        print("PROBLEM:", p)
    built = sum(1 for r in rows if r[0] == "built")
    print(f"\n{len(platforms)} selectable platform(s), {built} built by CI, "
          f"{len(rows) - built} waived, {len(ci_files)} CI config(s), "
          f"{len(problems)} problem(s)")
    return 1 if problems else 0


def _self_test():
    import tempfile
    import textwrap
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def build(tmp, platforms, ci, ledger, dirs='"dialects/*"'):
        """A miniature repo: platform dirs, CI files, and a manifest."""
        for p in platforms:
            os.makedirs(os.path.join(tmp, "dialects", p), exist_ok=True)
        os.makedirs(os.path.join(tmp, "ci"), exist_ok=True)
        for fn, body in ci.items():
            open(os.path.join(tmp, "ci", fn), "w").write(body)
        mpath = os.path.join(tmp, "m.toml")
        open(mpath, "w").write(textwrap.dedent(f"""
            [discover]
            dirs = [{dirs}]
            [ci]
            globs = ["ci/*.yml"]
        """) + ledger)
        return mpath

    # --- the happy path, and that acceptance is not vacuous -----------------
    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux", "bsd", "aix"],
                  {"gh.yml": "runs-on: ubuntu\nrun: ./Configure linux\n",
                   "other.yml": "image: bsd/9.x\nrun: make\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.bsd]\nbuilt_by = ["bsd/"]\n'
                  '[platforms.aix]\nwaived = "no runner"\n')
        check("a complete ledger passes", run(m, t) == 0)

    with tempfile.TemporaryDirectory() as t:
        # the second provider is the ONLY evidence for bsd — drop it and bsd
        # must fail, which is what makes the pass above mean something. This is
        # also the whole point of the harness: a provider GitHub never shows.
        m = build(t, ["linux", "bsd"],
                  {"gh.yml": "runs-on: ubuntu\nrun: ./Configure linux\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.bsd]\nbuilt_by = ["bsd/"]\n')
        check("a platform no CI config builds is caught", run(m, t) == 1)

    # --- property 4: prose is not evidence (LESSONS #031) -------------------
    # Not hypothetical. The first run of this harness against the real repo
    # certified `darwin` from build.yml:46 — a COMMENT mentioning
    # `./Configure -n darwin` while describing what -n skips — rather than from
    # the actual job step 47 lines further down.
    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux", "bsd"],
                  {"gh.yml": "run: ./Configure linux\n",
                   "c.yml": "# we do not run ./Configure -n bsd here\nrun: true\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.bsd]\nbuilt_by = ["Configure -n bsd"]\n')
        check("a COMMENT naming the platform is not evidence it is built",
              run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        # a `name:` label is a human string, not a thing that runs
        m = build(t, ["linux", "bsd"],
                  {"gh.yml": "run: ./Configure linux\n",
                   "c.yml": "- name: build for bsd/9.x\n  run: true\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.bsd]\nbuilt_by = ["bsd/"]\n')
        check("a job NAME naming the platform is not evidence either",
              run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        # and the converse, so the two tests above cannot pass by rejecting
        # everything: the same string in a run: line IS evidence
        m = build(t, ["linux", "bsd"],
                  {"gh.yml": "run: ./Configure linux\n",
                   "c.yml": "- name: build for bsd\n  run: ./Configure -n bsd\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.bsd]\nbuilt_by = ["Configure -n bsd"]\n')
        check("the same string in a run: line IS evidence", run(m, t) == 0)

    # --- property 1: the tree decides -------------------------------------
    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux", "newly_added"],
                  {"gh.yml": "run: ./Configure linux\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n')
        check("a selectable platform missing from the ledger is caught",
              run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux"],
                  {"gh.yml": "run: ./Configure linux\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.deleted]\nwaived = "gone"\n')
        check("a ledger entry the build system cannot select is caught",
              run(m, t) == 1)

    # --- property 2: a waiver asserts, it does not suppress ----------------
    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux", "aix"],
                  {"gh.yml": "run: ./Configure linux\n",
                   "aix.yml": "image: aix/7.2\nrun: make\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.aix]\nwaived = "no runner"\n')
        check("a STALE waiver — waived but CI builds it — is caught",
              run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux", "sun"],
                  {"gh.yml": "run: ./Configure linux\n",
                   "s.yml": "image: solaris-11\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  '[platforms.sun]\nwaived = "no runner"\naliases = ["solaris"]\n')
        check("a stale waiver is caught through an alias", run(m, t) == 1)

    # --- property 3: zero is not a pass ------------------------------------
    with tempfile.TemporaryDirectory() as t:
        m = build(t, [], {"gh.yml": "run: make\n"}, "", dirs='"nosuch/*"')
        check("discovering NO platforms fails, it does not pass", run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        os.makedirs(os.path.join(t, "dialects", "linux"))
        mpath = os.path.join(t, "m.toml")
        open(mpath, "w").write('[discover]\ndirs = ["dialects/*"]\n'
                               '[ci]\nglobs = ["nosuch/*.yml"]\n'
                               '[platforms.linux]\nwaived = "x"\n')
        check("finding NO CI config fails, it does not pass", run(mpath, t) == 1)

    # --- manifest hygiene ---------------------------------------------------
    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux"], {"gh.yml": "run: ./Configure linux\n"},
                  '[platforms.linux]\nbuilt_by = ["Configure linux"]\n'
                  'waived = "also waived"\n')
        check("an entry with BOTH built_by and waived is caught", run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        m = build(t, ["linux"], {"gh.yml": "run: ./Configure linux\n"},
                  '[platforms.linux]\n')
        check("an entry with NEITHER is caught", run(m, t) == 1)

    with tempfile.TemporaryDirectory() as t:
        check("a missing manifest fails", run(os.path.join(t, "nope.toml"), t) == 1)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manifest", default=os.path.join(_HERE, "platforms.toml"))
    ap.add_argument("--repo")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    return run(args.manifest, args.repo)


if __name__ == "__main__":
    sys.exit(main())
