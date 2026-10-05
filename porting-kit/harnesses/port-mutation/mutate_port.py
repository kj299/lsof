#!/usr/bin/env python3
"""Port mutation runner — break the PORT on purpose, one rule at a time, and
require its gates to go red; and keep the mutants as data, committed with the
change, so the kill table can be run again.

PLAYBOOK Phase 4 step 2 asks for it: name the change each new case is meant to
catch, make it, confirm the case turns red, and record a kill table (LESSONS
#026). Done by hand that is a throwaway script per change. lsof-rs ran at least
233 mutants across 16 changes that way, and none of them can be run again: the
kill tables survive as prose, and a later change that left one of those cases
checking nothing would go unnoticed (LESSONS #083). The hand scripts also
re-learned two failures each time: an edit that does not apply reads as a
survivor (LESSONS #059), and a mutant that is not reverted reads as a kill
(LESSONS #066). Here neither can happen.

Mutants file (TOML; paths and commands relative to `run.dir`, itself relative
to the file):

    [run]
    dir = ".."
    build = [["cargo", "build", "--release"]]    # each must exit 0
    [[run.gate]]
    name = "unit"
    cmd = ["cargo", "test"]
    [[run.gate]]
    name = "differential"
    cmd = ["python3", "differential/diff.py"]
    infra = [2]          # exit codes that mean "could not judge", never a kill
    timeout = 900        # seconds; a gate that overruns it killed the mutant

    [[mutant]]
    name = "path-cut-at-tab"
    rule = "a maps path keeps its TAB (DIVERGENCES 103)"
    [[mutant.edit]]
    file = "src/maps.rs"
    old = "..."          # must occur exactly once, after the edits before it
    new = "..."

Verdicts, per mutant:
  KILLED          a gate exited non-zero with a code that is not `infra`
  SURVIVED        every gate exited 0: the cases cannot see this rule
  DOES-NOT-APPLY  an edit's `old` occurs 0 times, or more than once (#059)
  NOBUILD         a build command failed: the mutant models no program
  INFRA           no gate killed it, and one could not judge
The BASELINE, unmutated, must build and pass every gate first, or no kill can
be attributed (exit 2). Every file a mutant touches is restored from a snapshot
after it and its bytes checked against the snapshot (#066), on SIGINT and
SIGTERM as well; and the build runs once more at the end, so the last mutant's
binary is not left behind for the next command to test.

Usage:
  mutate_port.py MUTANTS.toml [MUTANTS.toml ...] [--only NAME[,NAME..]]
                 [--apply-only] [--first-kill] [--json]
  mutate_port.py --self-test
  --apply-only  only apply and revert each mutant: does every one still apply
                to the tree? No build, no gate; seconds, so it suits every PR.
                It says the evidence still fits the code, not that it still
                holds: only a full run says that.
  --first-kill  stop a mutant's gates at the first that kills it (faster; the
                table then names one killer, not all of them)
Exit: 0 every mutant killed (with --apply-only: every mutant applies); 1 any other
verdict; 2 usage, an unreadable file, or a red baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    sys.exit("error: mutate_port.py needs Python 3.11+ (tomllib)")

TIMEOUT_CODE = 124  # what a gate that overran its timeout is recorded as


class Usage(Exception):
    """A mutants file this runner cannot trust: exit 2, never a verdict."""


class Interrupted(Exception):
    pass


def verdict(applied, built, codes, infra):
    """One mutant's verdict. `codes` maps each gate that ran to its exit
    status; `infra` maps a gate to the codes that mean it could not judge."""
    if not applied:
        return "DOES-NOT-APPLY"
    if not built:
        return "NOBUILD"
    killers = [g for g, rc in codes.items() if rc != 0 and rc not in infra.get(g, ())]
    if killers:
        return "KILLED"
    if any(rc != 0 for rc in codes.values()):
        return "INFRA"
    return "SURVIVED"


# ------------------------------------------------------------------ loading --

_RUN_KEYS = {"dir", "build", "gate"}
_GATE_KEYS = {"name", "cmd", "infra", "timeout"}
_MUTANT_KEYS = {"name", "rule", "edit"}
_EDIT_KEYS = {"file", "old", "new"}


def _strs(v):
    return isinstance(v, list) and v and all(isinstance(x, str) for x in v)


def _unknown(where, d, allowed):
    extra = set(d) - allowed
    if extra:
        # A misspelt key is not ignored: `infra` spelt `infras` would turn an
        # exit that means "could not judge" into a kill, and read as coverage.
        raise Usage(f"{where}: unknown key(s) {sorted(extra)} (allowed: {sorted(allowed)})")


def load(path):
    """The mutants file as {dir, build, gates, mutants}; Usage on anything
    malformed. Every edit's file must lie inside `dir`."""
    try:
        with open(path, "rb") as fh:
            doc = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Usage(f"{path}: {e}")
    _unknown(path, doc, {"run", "mutant"})
    run = doc.get("run")
    if not isinstance(run, dict):
        raise Usage(f"{path}: no [run] table")
    _unknown(f"{path} [run]", run, _RUN_KEYS)
    base = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(path)),
                                         run.get("dir", ".")))
    if not os.path.isdir(base):
        raise Usage(f"{path}: run.dir {run.get('dir')!r} is not a directory")
    build = run.get("build", [])
    if not isinstance(build, list) or not all(_strs(c) for c in build):
        raise Usage(f"{path}: run.build must be a list of commands (lists of strings)")
    gates = run.get("gate")
    if not isinstance(gates, list) or not gates:
        raise Usage(f"{path}: no [[run.gate]]: with no gate every mutant would survive")
    names = set()
    for g in gates:
        _unknown(f"{path} [[run.gate]]", g, _GATE_KEYS)
        if not isinstance(g.get("name"), str) or not _strs(g.get("cmd")):
            raise Usage(f"{path}: a gate needs a name and a cmd (a list of strings)")
        if g["name"] in names:
            raise Usage(f"{path}: gate {g['name']!r} named twice")
        names.add(g["name"])
        if not all(isinstance(c, int) for c in g.get("infra", [])):
            raise Usage(f"{path}: gate {g['name']!r}: infra must be exit codes")
        if 0 in g.get("infra", []):
            raise Usage(f"{path}: gate {g['name']!r}: 0 cannot mean 'could not judge'")
    mutants = doc.get("mutant")
    if not isinstance(mutants, list) or not mutants:
        raise Usage(f"{path}: no [[mutant]]")
    seen = set()
    for m in mutants:
        _unknown(f"{path} [[mutant]]", m, _MUTANT_KEYS)
        name = m.get("name")
        if not isinstance(name, str) or not name:
            raise Usage(f"{path}: a mutant has no name")
        if name in seen:
            raise Usage(f"{path}: mutant {name!r} named twice")
        seen.add(name)
        edits = m.get("edit")
        if not isinstance(edits, list) or not edits:
            raise Usage(f"{path}: mutant {name!r} has no [[mutant.edit]]")
        for e in edits:
            _unknown(f"{path} mutant {name!r} edit", e, _EDIT_KEYS)
            if not all(isinstance(e.get(k), str) for k in _EDIT_KEYS) or not e["old"]:
                raise Usage(f"{path}: mutant {name!r}: an edit needs file, old (non-empty) and new")
            if e["old"] == e["new"]:
                raise Usage(f"{path}: mutant {name!r}: an edit whose new is its old changes nothing")
            full = os.path.realpath(os.path.join(base, e["file"]))
            if os.path.commonpath([full, base]) != base:
                raise Usage(f"{path}: mutant {name!r}: {e['file']!r} is outside run.dir")
            e["path"] = full
    return {"path": path, "dir": base, "build": build, "gates": gates, "mutants": mutants}


# ------------------------------------------------------------------ running --

def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _read(p):
    try:
        with open(p, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _write(p, data):
    with open(p, "wb") as fh:
        fh.write(data)


class Tree:
    """The files any mutant touches, snapshotted before the first one runs and
    put back, byte for byte and checked, after each one and on exit."""

    def __init__(self, spec):
        self.snap = {}
        for m in spec["mutants"]:
            for e in m["edit"]:
                if e["path"] not in self.snap:
                    self.snap[e["path"]] = _read(e["path"])

    def apply(self, mutant):
        """(applied, why): write the mutant into the tree, or nothing at all."""
        cur = {}
        for i, e in enumerate(mutant["edit"], 1):
            text = cur.get(e["path"], self.snap[e["path"]])
            if text is None:
                return False, f"edit {i}: {e['file']} cannot be read"
            n = text.count(e["old"].encode())
            if n != 1:
                return False, f"edit {i}: `old` occurs {n} times in {e['file']}"
            cur[e["path"]] = text.replace(e["old"].encode(), e["new"].encode(), 1)
        for p, data in cur.items():
            _write(p, data)
        return True, ""

    def restore(self):
        for p, data in self.snap.items():
            if data is None:
                continue
            if _read(p) != data:
                _write(p, data)
            if _sha(_read(p) or b"") != _sha(data):
                raise RuntimeError(f"could not restore {p}: the tree is left mutated")


def _run(cmd, cwd, timeout=None):
    """(exit code, tail of output). Its own process group, killed whole on
    timeout or interrupt, so no grandchild outlives the gate."""
    try:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                             start_new_session=True)
    except OSError as e:
        return 127, f"cannot run {cmd[0]}: {e}"
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out.decode(errors="replace")[-2000:]
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        out, _ = p.communicate()
        return TIMEOUT_CODE, out.decode(errors="replace")[-2000:] + f"\n[timeout after {timeout}s]"
    except BaseException:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except OSError:
            pass
        p.communicate()
        raise


def _build(spec):
    for cmd in spec["build"]:
        rc, out = _run(cmd, spec["dir"])
        if rc != 0:
            return False, f"{' '.join(cmd)} exited {rc}\n{out}"
    return True, ""


def _gates(spec, first_kill):
    codes, said = {}, {}
    infra = {g["name"]: tuple(g.get("infra", ())) for g in spec["gates"]}
    for g in spec["gates"]:
        rc, out = _run(g["cmd"], spec["dir"], g.get("timeout"))
        codes[g["name"]], said[g["name"]] = rc, out
        if first_kill and rc != 0 and rc not in infra[g["name"]]:
            break
    return codes, said, infra


def run(spec, only=None, apply_only=False, first_kill=False):
    """Every selected mutant's record. Raises Usage for a red baseline."""
    tree = Tree(spec)
    chosen = [m for m in spec["mutants"] if not only or m["name"] in only]
    if only and len(chosen) != len(only):
        raise Usage(f"--only names no mutant: {sorted(set(only) - {m['name'] for m in chosen})}")
    records = []
    if not apply_only:
        ok, why = _build(spec)
        if not ok:
            raise Usage(f"baseline does not build: {why}")
        codes, said, _ = _gates(spec, False)
        red = {g: rc for g, rc in codes.items() if rc != 0}
        if red:
            g = next(iter(red))
            raise Usage(f"baseline is red, so no kill can be attributed: gate {g!r} "
                        f"exited {red[g]}\n{said[g]}")
    try:
        for m in chosen:
            t0 = time.time()
            applied, why = tree.apply(m)
            built, codes, infra, said = applied, {}, {}, {}
            try:
                if applied and not apply_only:
                    built, bwhy = _build(spec)
                    if built:
                        codes, said, infra = _gates(spec, first_kill)
                    else:
                        why = bwhy
            finally:
                tree.restore()
            v = ("APPLIES" if applied else "DOES-NOT-APPLY") if apply_only else \
                verdict(applied, built, codes, infra)
            killers = [g for g, rc in codes.items() if rc != 0 and rc not in infra.get(g, ())]
            records.append({"name": m["name"], "rule": m.get("rule", ""), "verdict": v,
                            "killed_by": killers, "codes": codes,
                            "why": why or ("" if v in ("KILLED", "APPLIES") else
                                           "\n".join(said.values())[-600:]),
                            "seconds": round(time.time() - t0, 1)})
    finally:
        tree.restore()
        if not apply_only:
            ok, why = _build(spec)
            if not ok:
                print(f"warning: the rebuild after restoring failed; the build "
                      f"artifacts may not match the source: {why}", file=sys.stderr)
    return records


def _report(path, records, apply_only):
    print(f"## {path}\n")
    print("| mutant | verdict | killed by | rule |\n|---|---|---|---|")
    for r in records:
        print(f"| {r['name']} | {r['verdict']} | {', '.join(r['killed_by']) or '—'} | {r['rule']} |")
    bad = [r for r in records if r["verdict"] not in ("KILLED", "APPLIES")]
    for r in bad:
        print(f"\n{r['verdict']}: {r['name']}")
        for line in r["why"].strip().splitlines()[-12:]:
            print(f"    {line}")
    counts = {}
    for r in records:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    by = {}
    for r in records:
        for g in r["killed_by"]:
            by[g] = by.get(g, 0) + 1
    alone = {}
    for r in records:
        if len(r["killed_by"]) == 1:
            alone[r["killed_by"][0]] = alone.get(r["killed_by"][0], 0) + 1
    print(f"\n{len(records)} mutant(s): " + ", ".join(f"{n} {v}" for v, n in sorted(counts.items())))
    if by and not apply_only:
        print("killed by: " + ", ".join(f"{g} {n} ({alone.get(g, 0)} alone)" for g, n in sorted(by.items())))
    return not bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--only", help="comma-separated mutant names")
    ap.add_argument("--apply-only", action="store_true")
    ap.add_argument("--first-kill", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.files:
        ap.error("name a mutants file")

    def interrupted(signum, frame):
        raise Interrupted(f"signal {signum}")
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(s, interrupted)
    only = set(a.only.split(",")) if a.only else None
    ok, out = True, []
    try:
        for f in a.files:
            spec = load(f)
            records = run(spec, only, a.apply_only, a.first_kill)
            out.append({"file": f, "mutants": records})
            if not a.json:
                ok = _report(f, records, a.apply_only) and ok
            else:
                ok = ok and all(r["verdict"] in ("KILLED", "APPLIES") for r in records)
    except Usage as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Interrupted as e:
        print(f"interrupted ({e}): every mutated file was restored", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(out, indent=2))
    return 0 if ok else 1


# ---------------------------------------------------------------- self-test --

_PROG = "def add(a, b):\n    return a + b\n\n\ndef twice(a):\n    return a * 2\n"
_UNIT = ("import sys, prog\n"
         "sys.exit(0 if prog.add(2, 3) == 5 and prog.twice(4) == 8 else 1)\n")
# Exit 2 ("could not judge") when add(1, 1) is 0, as a harness exits on its
# own error; exit 1 when add(7, 1) is wrong.
_JUDGE = ("import sys, prog\n"
          "sys.exit(2 if prog.add(1, 1) == 0 else 1 if prog.add(7, 1) != 8 else 0)\n")
_STAMP = ("import hashlib\n"
          "open('built.stamp', 'w').write(hashlib.sha256(open('prog.py', 'rb').read()).hexdigest())\n")
_SLOW = ("import os, sys, time\n"
         "open('slow.started', 'w').close()\n"
         "time.sleep(30)\n")


def _fixture(root, gates, mutants):
    os.makedirs(os.path.join(root, "proj"), exist_ok=True)
    for name, text in (("prog.py", _PROG), ("unit.py", _UNIT), ("judge.py", _JUDGE),
                       ("stamp.py", _STAMP), ("slow.py", _SLOW), ("other.py", "x = 1\n")):
        _write(os.path.join(root, "proj", name), text.encode())
    py = json.dumps(sys.executable)
    lines = ['[run]', 'dir = "proj"',
             f'build = [[{py}, "-m", "py_compile", "prog.py"], [{py}, "stamp.py"]]']
    for g in gates:
        lines += ["[[run.gate]]", f'name = "{g[0]}"', f'cmd = [{py}, "{g[1]}"]']
        if len(g) > 2:
            lines.append(f"infra = {g[2]}")
    for name, edits in mutants:
        lines += ["[[mutant]]", f'name = "{name}"']
        for f, old, new in edits:
            lines += ["[[mutant.edit]]", f'file = "{f}"', f"old = {json.dumps(old)}",
                      f"new = {json.dumps(new)}"]
    path = os.path.join(root, "mutants.toml")
    _write(path, "\n".join(lines).encode() + b"\n")
    return path


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS  " if cond else "FAIL  ") + name)
        ok = ok and bool(cond)

    gates = [("unit", "unit.py"), ("judge", "judge.py", "[2]")]
    mutants = [
        ("subtracts", [("prog.py", "return a + b", "return a - b")]),
        ("commutes", [("prog.py", "return a + b", "return b + a")]),
        ("missing", [("prog.py", "return a * b", "return a")]),
        ("ambiguous", [("prog.py", "return a", "return 0")]),
        ("nobuild", [("prog.py", "return a + b", "return a +")]),
        ("unjudged", [("prog.py", "return a + b", "return 0 if (a, b) == (1, 1) else a + b")]),
        ("judged", [("prog.py", "return a + b", "return 9 if (a, b) == (7, 1) else a + b")]),
        ("two-files", [("other.py", "x = 1", "x = 2"), ("prog.py", "return a * 2", "return a + a + 1")]),
        ("half-applies", [("other.py", "x = 1", "x = 3"), ("prog.py", "no such text", "y")]),
    ]
    with tempfile.TemporaryDirectory() as td:
        spec = load(_fixture(td, gates, mutants))
        before = {p: _read(p) for p in Tree(spec).snap}
        recs = {r["name"]: r for r in run(spec)}
        want = {"subtracts": "KILLED", "commutes": "SURVIVED", "missing": "DOES-NOT-APPLY",
                "ambiguous": "DOES-NOT-APPLY", "nobuild": "NOBUILD", "unjudged": "INFRA",
                "judged": "KILLED", "two-files": "KILLED", "half-applies": "DOES-NOT-APPLY"}
        for name, v in want.items():
            check(f"{name} is {v}", recs[name]["verdict"] == v)
        check("a kill names its gate: subtracts by unit, judged by judge",
              recs["subtracts"]["killed_by"] == ["unit"] and recs["judged"]["killed_by"] == ["judge"])
        check("an `infra` exit is never a kill", recs["unjudged"]["killed_by"] == [])
        check("every touched file is restored byte for byte",
              all(_read(p) == b for p, b in before.items()))
        stamp = _read(os.path.join(td, "proj", "built.stamp")).decode()
        check("the build ran again at the end: its output matches the source, not the last mutant",
              stamp == _sha(_PROG.encode()))
        check("a mutant that applies only in part writes nothing",
              _read(os.path.join(td, "proj", "other.py")) == b"x = 1\n")
        checked = {r["name"]: r["verdict"] for r in run(spec, apply_only=True)}
        check("--apply-only applies and reverts, without building",
              checked["subtracts"] == "APPLIES" and checked["missing"] == "DOES-NOT-APPLY")
        only = run(spec, only={"subtracts"}, first_kill=True)
        check("--only runs the named mutant alone", [r["name"] for r in only] == ["subtracts"])
        rc = main([spec["path"], "--only", "subtracts,judged"])
        check("exit 0 when every mutant run is killed", rc == 0)
        rc = main([spec["path"], "--only", "subtracts,commutes"])
        check("exit 1 when one survives", rc == 1)
        rc = main([spec["path"], "--apply-only", "--only", "subtracts,missing"])
        check("--apply-only exits 1 when a mutant no longer applies", rc == 1)

    with tempfile.TemporaryDirectory() as td:
        path = _fixture(td, [("unit", "unit.py")], [("subtracts", [("prog.py", "return a + b", "return a - b")])])
        _write(os.path.join(td, "proj", "unit.py"), b"import sys\nsys.exit(1)\n")
        check("a red baseline is exit 2, before any mutant runs", main([path]) == 2)

    for bad, why in ((['[run]', 'dir = "proj"', '[[run.gate]]', 'name = "u"', 'cmd = ["x"]',
                       'infras = [2]'], "a misspelt key"),
                     (['[run]', 'dir = "proj"'], "no gate"),
                     (['[run]', 'dir = "proj"', '[[run.gate]]', 'name = "u"', 'cmd = ["x"]',
                       '[[mutant]]', 'name = "m"', '[[mutant.edit]]', 'file = "../../etc/passwd"',
                       'old = "a"', 'new = "b"'], "an edit outside run.dir")):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "proj"))
            p = os.path.join(td, "m.toml")
            _write(p, "\n".join(bad).encode())
            try:
                load(p)
                check(f"{why} is refused", False)
            except Usage:
                check(f"{why} is refused", True)

    # Interrupted mid-gate: the tree is put back all the same.
    with tempfile.TemporaryDirectory() as td:
        path = _fixture(td, [("slow", "slow.py")], [("subtracts", [("prog.py", "return a + b", "return a - b")])])
        _write(os.path.join(td, "proj", "slow.py"),
               b"import os, sys, prog, time\n"
               b"if prog.add(2, 3) != 5:\n"
               b"    open('slow.started', 'w').close()\n"
               b"    time.sleep(30)\n")
        p = subprocess.Popen([sys.executable, os.path.abspath(__file__), path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        marker = os.path.join(td, "proj", "slow.started")
        for _ in range(200):
            if os.path.exists(marker):
                break
            time.sleep(0.05)
        p.send_signal(signal.SIGTERM)
        try:
            _, err = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            _, err = p.communicate()
        check("SIGTERM in the middle of a gate restores the tree, and exits 2",
              os.path.exists(marker) and p.returncode == 2
              and _read(os.path.join(td, "proj", "prog.py")) == _PROG.encode())

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
