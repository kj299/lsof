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
  LIVE            (--apply-only, --check-clean) the tree reads as this mutant
                  applied, and its `new` keeps its `old`, so the count cannot
                  see it (THE CLEAN-TREE PROOF below); a full run refuses
  AMBIGUOUS       (--apply-only, --check-clean) applied, it leaves its `old`
                  occurring once again, so no check of the tree can tell one
                  that holds it from a clean one: widen its `old`. A full run
                  runs it, and warns
The BASELINE, unmutated, must build and pass every gate first, or no kill can
be attributed (exit 2). Every file a mutant touches is restored from a snapshot
after it and its bytes checked against the snapshot (#066), on SIGINT and
SIGTERM as well; and the build runs once more at the end, so the last mutant's
binary is not left behind for the next command to test.

THE JOURNAL (LESSONS #086). A run killed outright restores nothing: SIGKILL,
the OOM killer, a container restart. So before its first write of a mutant a
run (full or --apply-only) writes `<run.dir>/.mutate_port.journal/`:
`manifest.json` (format, the writer's pid and start time, the mutants file,
and for every file a selected mutant touches its path, the SHA-256 of its
original bytes and every mutant's edits to it) and `orig-N`, a copy of each
original. It is built under another name, each piece written to a temp name,
fsynced and renamed, then renamed into place whole and the directory fsynced,
so a kill leaves no journal or a complete one (a dead run's half-built one,
under the other name, is deleted by the next invocation: that run had written
no mutant); a journal without its `complete` mark, with a copy that does not
match its SHA-256, or naming a file outside run.dir, is reported and never
used to restore. Only after the final restore has been checked byte for byte,
and each restored file fsynced (on SIGINT/SIGTERM/SIGHUP as well), is it
removed, out of sight by one rename and then deleted, so a run that ends
leaves none. A journal that cannot be removed (run.dir not writable), or that
something else removed first, is exit 2, saying so: the tree was put back and
checked before. While it exists it is the lock: a second run over the same
run.dir refuses. No ignore rule names it, and none may: a leftover journal
must show in `git status` as an untracked directory.

Every invocation over a run.dir looks for a journal before anything else reads
or writes the tree: a full run, --apply-only, --check-clean. If its writer may
still be alive, it refuses: exit 2. The writer is the process with the
journal's pid, never this one, that started when the journal records: by its
start in clock ticks and the boot id where /proc says, whatever its name, or
else by the start time `ps` gives; a journal written in another pid namespace
is looked for by its start among every process. Only where no start was
recorded is the name asked: a python running mutate_port.py. If the writer
is dead, it says of each journaled file whether it is (a) back to its original
bytes, (b) EXACTLY one journaled mutant applied to the original (named), or
(c) neither, changed some other way since; and exits 2. Then:

  mutate_port.py --restore MUTANTS.toml

puts back every (b) file from the journal and checks it by SHA-256; leaves a
(c) file untouched, names it and keeps the journal (exit 2; a (c) file that is
the start of what was being written, a write a kill cut short, gets the `cp`
that puts back its original); and removes the journal once no file is in (b)
or (c) (exit 0). It builds nothing and runs no gate: rebuild before you test.
Mutants and restores are written in place, which keeps a file's owner, mode,
inode and links; so a kill inside a write leaves a (c) file, never a guess.

THE CLEAN-TREE PROOF is one command, and it writes nothing to the tree (it
may delete a dead run's leftover staging directory, above):

  mutate_port.py --check-clean MUTANTS.toml

Exit 0 says: no journal under run.dir, and for every mutant, its edits apply
(each `old` occurs exactly once) and the tree is not that mutant applied to a
tree on which it reads CLEAN. It prints how many mutants and files it checked.
It never counts a mutant's `new`, which may occur anywhere for reasons of its
own. Most mutants erase their `old`, so one left in place fails the count
(DOES-NOT-APPLY, with a hint where the tree reads as it applied). Where its
`new` keeps its `old` (an inserted line) the count passes, so the check
reverts `new` at each place it occurs and asks whether that gives a tree the
mutant applies to and turns back into this one (LIVE); a `new` that merely
occurs elsewhere reverts into a second `old`, which the mutant does not apply
to. A clean tree that already has an inserted line's `new` at its anchor
reads LIVE too: the bytes are the same, so re-anchor it. Where a mutant's edit
re-forms its own `old` (`0x1000` -> `0x100` over `0x10000`), a tree that holds
it passes the count just as a clean one does, and nothing in the tree can
tell them apart: it is AMBIGUOUS (exit 1) on the clean tree, and once applied
it may read CLEAN. So the proof covers every mutant that read CLEAN on the
tree it was run against, which --apply-only in CI enforces for every mutant
committed; what a run killed outright left is the journal's to say, not the
tree's. --apply-only makes the same checks before it applies anything, so
CI's run of it fails on a committed mutant; it is not the proof only because
it writes each mutant into the tree. A hand-written check is not the proof
either: one read the wrong key, checked nothing, and reported nothing
(LESSONS #086).

Usage:
  mutate_port.py MUTANTS.toml [MUTANTS.toml ...] [--only NAME[,NAME..]]
                 [--apply-only] [--first-kill] [--json]
  mutate_port.py --check-clean MUTANTS.toml [MUTANTS.toml ...]
                 [--only NAME[,NAME..]] [--json]
  mutate_port.py --restore MUTANTS.toml [MUTANTS.toml ...]
  mutate_port.py --self-test
  --apply-only  only apply and revert each mutant: does every one still apply
                to the tree? No build, no gate; seconds, so it suits every PR.
                It says the evidence still fits the code, not that it still
                holds: only a full run says that.
  --check-clean prove no mutant is left in the tree (above); writes nothing
                to the tree
  --restore     undo a killed run from its journal (above)
  --first-kill  stop a mutant's gates at the first that kills it (faster; the
                table then names one killer, not all of them)
Exit: 0 every mutant killed (--apply-only: every mutant applies; --check-clean:
the tree is clean; --restore: the tree is back and the journal gone); 1 any
other verdict; 2 usage, an unreadable file, a red baseline, a journal (another
run's, or a killed run's), a journal that cannot be written or removed, a
file that cannot be written or restored, or a full run over a tree that holds
a LIVE mutant.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shlex
import shutil
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
JOURNAL = ".mutate_port.journal"
_FORMAT = 1
_STARTED = time.time()
_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
_HELD = set()  # journals this process wrote and has not removed
# Where /proc is. The self-test points it at nothing, in this process and in
# the runs it starts, to take the path a host without /proc takes (macOS: ps).
_PROC = os.environ.get("MUTATE_PORT_PROC", "/proc")


class Usage(Exception):
    """A mutants file this runner cannot trust: exit 2, never a verdict."""


class Interrupted(Exception):
    pass


class Unrestored(Exception):
    """A file the final restore could not put back: its journal is kept."""


class Broken(Exception):
    """A journal that is not whole: never used to restore."""


class JournalLeft(Exception):
    """The tree was put back and checked, but its journal could not be
    removed, or was gone before it was: exit 2, saying which."""


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


def _run_dir(path):
    """run.dir of a mutants file, read as little as --restore needs: a file
    edited into something `load` refuses still names the tree to put back."""
    try:
        with open(path, "rb") as fh:
            run = tomllib.load(fh).get("run")
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Usage(f"{path}: {e}")
    d = run.get("dir", ".") if isinstance(run, dict) else "."
    base = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(path)), str(d)))
    if not os.path.isdir(base):
        raise Usage(f"{path}: run.dir {d!r} is not a directory")
    return base


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


def _fsync_file(p):
    """Best effort, as _fsync_dir: a restored file's bytes on disk before the
    journal's removal is, so a host crash cannot keep the one and lose the
    other (a mutant with no record: LESSONS #086)."""
    try:
        fd = os.open(p, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _edits(m):
    """[(old, new)] of a journaled mutant's edits to one file, as bytes."""
    return [(e["old"].encode(), e["new"].encode()) for e in m["edits"]]


def _by_file(mutant):
    """{path: ([(old, new), ...], [edit number, ...])}: a loaded mutant's
    edits, file by file, in order, each with its number in the mutant."""
    out = {}
    for i, e in enumerate(mutant["edit"], 1):
        edits, nums = out.setdefault(e["path"], ([], []))
        edits.append((e["old"].encode(), e["new"].encode()))
        nums.append(i)
    return out


def _forward(text, edits):
    """(text with `edits` applied in order, None, None), or (None, i, n) when
    edit i's `old` occurs n times, not once, at its turn."""
    for i, (old, new) in enumerate(edits, 1):
        n = 0 if text is None else text.count(old)
        if n != 1:
            return None, i, n
        text = text.replace(old, new, 1)
    return text, None, None


def _preimages(text, edits, cap=64, tries=4096):
    """[(tree, at)]: every text `edits` apply to and turn into `text`, found by
    reverting the last edit's `new` wherever it occurs (`at`, its offset in
    `text`), then, depth first, the others', and applying them all again.
    Where `old` occurs already, only a `new` whose reverting breaks every
    occurrence of it can give a tree in which `old` occurs once, so only
    those are tried. None when there are more than `cap` such trees, or
    `tries` places to revert (an empty `new` occurs everywhere): then nothing
    can be said."""
    found, left = [], [tries]

    def back(t, k, at):
        """False when the budget ran out."""
        if k == 0:
            if _forward(t, edits)[0] == text:
                found.append((t, at))
            return len(found) <= cap
        old, new = edits[k - 1]
        lo, hi = 0, len(t)
        if old in t:  # [i, i + len(new)) must meet [j, j + len(old)) for each j
            lo = t.rfind(old) - max(len(new), 1) + 1
            hi = t.find(old) + len(old) - 1
        i = t.find(new, max(lo, 0))
        while i != -1 and i <= hi:
            left[0] -= 1
            if left[0] < 0 or not back(t[:i] + old + t[i + len(new):], k - 1,
                                       i if at is None else at):
                return False
            i = t.find(new, i + 1)
        return True

    return found if back(text, len(edits), None) else None


def _where(rel, text, pre):
    """`rel line N, M`: where in `text` the reverted `new`s of `pre` sit."""
    if pre is None:
        return f"{rel}, where its `new` occurs in too many places to revert, so it cannot be ruled out"
    lines = sorted({text[:at].count(b"\n") + 1 for _, at in pre})
    return f"{rel} line {', '.join(map(str, lines))}"


def _state(texts, mutant, base):
    """(CLEAN | LIVE | AMBIGUOUS | DOES-NOT-APPLY, why): is `mutant` in the
    tree, judged from the tree alone (THE CLEAN-TREE PROOF, LESSONS #086). Its
    `new` text is never counted: it may occur anywhere for reasons of its own.

    CLEAN, for a mutant whose `new` keeps no `old`: every edit's `old` occurs
    once, and the mutant applied leaves one that does not, so a tree holding
    it would fail that count. AMBIGUOUS: applied, it leaves every `old` once
    again (`0x1000` -> `0x100` over `0x10000`), so a tree that holds it passes
    the count as this one does, and no check of the tree can tell the two.
    Where a `new` keeps its `old` (an inserted line) no count can see it: the
    tree is LIVE if it is that mutant applied to a tree it applies to, found
    by reverting `new`, or if there are too many places to revert to rule
    that out; CLEAN if it is not. So a tree on which a mutant reads CLEAN is
    never read CLEAN once that mutant is applied to it. A mutant that does not apply is
    DOES-NOT-APPLY, never LIVE: a stale one whose `new` is a prefix of some
    line reverts into a tree it applies to just as one left in place does, so
    that is a hint, not a verdict."""
    live, unsure, fails = [], [], []
    for p, (edits, nums) in _by_file(mutant).items():
        rel = os.path.relpath(p, base)
        text = texts.get(p)
        if text is None:
            fails.append(f"edit {nums[0]}: {rel} cannot be read")
            continue
        once, i, n = _forward(text, edits)
        keeps = any(old in new for old, new in edits)
        if once is not None and not keeps:
            if _forward(once, edits)[0] is not None:
                unsure.append(f"{rel}: applied, it leaves its `old` occurring once again")
            continue
        pre = _preimages(text, edits)
        if once is None:
            fails.append(f"edit {nums[i - 1]}: `old` occurs {n} times in {rel}"
                         + (f"; the tree may hold it: reverting its `new` at "
                            f"{_where(rel, text, pre)} gives a tree it applies to"
                            if pre else ""))
        elif pre != []:
            live.append(_where(rel, text, pre))
    if live:
        return "LIVE", ("the tree reads as this mutant applied to a tree it applies "
                        "to (" + "; ".join(live) + "), and its `new` keeps its `old`, "
                        "so no count of `old` can tell. A run left it in place, or the "
                        "code already has its `new` at its anchor: the bytes are the "
                        "same, so if this is the code as it should be, re-anchor the "
                        "mutant so its `new` does not occur in the clean tree")
    if fails:
        return "DOES-NOT-APPLY", "; ".join(fails + unsure)
    if unsure:
        return "AMBIGUOUS", ("; ".join(unsure) + ", so a tree that holds it passes the "
                             "count as this one does, and --check-clean cannot tell "
                             "them apart: widen its `old` until applying it erases it")
    return "CLEAN", ""


class Tree:
    """The files the selected mutants touch, snapshotted before the first one
    runs and put back, byte for byte and checked, after each one and on exit."""

    def __init__(self, mutants):
        self.snap = {}
        for m in mutants:
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
        try:
            for p, data in cur.items():
                _write(p, data)
        except OSError as e:  # the run's restore puts back what was written
            raise Usage(f"cannot write mutant {mutant['name']!r} into the tree: {e}")
        return True, ""

    def restore(self, sync=False):
        """Put back every file and check it byte for byte; with `sync`, fsync
        each, as the journal's removal follows. Unrestored names every file
        that is not back, after trying them all."""
        bad = []
        for p, data in self.snap.items():
            if data is None:
                continue
            try:
                if _read(p) != data:
                    _write(p, data)
                if sync:
                    _fsync_file(p)
            except OSError as e:
                bad.append(f"{p} ({e})")
                continue
            if _sha(_read(p) or b"") != _sha(data):
                bad.append(p)
        if bad:
            raise Unrestored(f"could not restore {', '.join(bad)}: the tree is left mutated")


# ------------------------------------------------------------------ journal --

@contextlib.contextmanager
def _held():
    """Hold SIGINT/SIGTERM/SIGHUP while the journal is written or the tree put
    back and the journal removed: one that arrives meanwhile is delivered after,
    so it cannot cut either in half."""
    mask = getattr(signal, "pthread_sigmask", None)
    old = mask(signal.SIG_BLOCK, _SIGNALS) if mask else None
    try:
        yield
    finally:
        if mask:
            mask(signal.SIG_SETMASK, old)


def _fsync_dir(d):
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass  # some filesystems refuse a directory fsync; the rename still holds
    finally:
        os.close(fd)


def _put(d, name, data):
    """Write `d/name` whole: a temp name, fsync, rename."""
    tmp = os.path.join(d, name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.rename(tmp, os.path.join(d, name))


def _procfs():
    return os.path.isdir(os.path.join(_PROC, "self"))


def _proc_start(pid):
    """A process's start, in clock ticks since boot (/proc/PID/stat field 22);
    None when there is no such process, or no /proc."""
    raw = _read(f"{_PROC}/{pid}/stat")
    if raw is None:
        return None
    try:
        return int(raw[raw.rindex(b")") + 2:].split()[19])
    except (ValueError, IndexError):
        return None


def _boot_id():
    raw = _read(f"{_PROC}/sys/kernel/random/boot_id")
    return raw.decode(errors="replace").strip() if raw else None


def _pid_ns():
    try:
        return os.readlink(f"{_PROC}/self/ns/pid")
    except OSError:
        return None


def _pids():
    try:
        return [int(n) for n in os.listdir(_PROC) if n.isdigit()]
    except OSError:
        return []


def _ps(pid, field):
    """`ps -o FIELD= -p PID`, as text; None when ps cannot say. Where there is
    no /proc (macOS) a process's start is `lstart`, to the second."""
    try:
        r = subprocess.run(["ps", "-o", f"{field}=", "-p", str(pid)], capture_output=True,
                           timeout=10, env=dict(os.environ, LC_ALL="C", TZ="UTC"))
    except (OSError, subprocess.SubprocessError):
        return None
    out = r.stdout.decode(errors="replace").strip()
    return out if r.returncode == 0 and out else None


def _exists(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True  # EPERM: it exists, as another user's; else it may
    return True


def _identity():
    """What names this process in its journal: its pid and its start, by
    /proc (clock ticks since boot, the boot id, the pid namespace) or else by
    ps."""
    procfs = _procfs()
    start = _proc_start("self") if procfs else None
    return {"pid": os.getpid(), "proc_start": start,
            "boot_id": _boot_id() if procfs else None,
            "pid_ns": _pid_ns() if procfs else None,
            "ps_start": None if start is not None else _ps(os.getpid(), "lstart")}


def _iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _is_harness(args):
    """Is this argv a python running mutate_port.py?"""
    args = [os.path.basename(a).lower() for a in args if a]
    return bool(args) and b"python" in args[0] and any(
        a.startswith(b"mutate_port") and a.endswith(b".py") for a in args[1:])


def _writer_alive(man):
    """May the process that wrote this journal still be running? It is the
    process with the journal's pid that started when the journal says: by its
    start in clock ticks and the boot id, where /proc says, whatever its name
    (a run started through a link is a run all the same); or else by the
    start `ps` gives. A journal from another pid namespace names a pid that
    means another process here, so its start is looked for among them all.
    Only where no start was recorded is the name asked: a python running
    mutate_port.py. Our own pid is never it: this process has written
    nothing yet, and pids repeat after a container restart. When nothing can
    say, it may be: refuse rather than guess."""
    pid = man.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    start = man.get("proc_start")
    if start is not None and _procfs():
        boot, ns = _boot_id(), _pid_ns()
        if man.get("boot_id") and boot and man["boot_id"] != boot:
            return False  # booted since: nothing that ran then runs now
        if man.get("pid_ns") and ns and man["pid_ns"] != ns:
            return any(_proc_start(q) == start for q in _pids())
        if pid == os.getpid():
            return False
        now = _proc_start(pid)
        # No /proc entry: gone, or hidden from us (hidepid); kill(2) says which.
        return now == start if now is not None else _exists(pid)
    if pid == os.getpid() or not _exists(pid):
        return False
    if man.get("ps_start") is not None:
        now = _ps(pid, "lstart")
        return now is None or now == man["ps_start"]
    cmd = _read(f"{_PROC}/{pid}/cmdline") if _procfs() else None
    if cmd is not None:
        return _is_harness(cmd.split(b"\0"))
    cmd = _ps(pid, "command")
    return cmd is None or _is_harness(cmd.encode().split())


class Journal:
    """`<run.dir>/.mutate_port.journal/`: what a killed run needs undone."""

    def __init__(self, path):
        self.path = path

    @classmethod
    def create(cls, spec, tree, chosen):
        """Write the journal whole before the first mutant is written, or raise
        Usage when another run's is in place: its existence is the lock."""
        base = spec["dir"]
        final = os.path.join(base, JOURNAL)
        files = []
        for p, data in tree.snap.items():
            files.append({
                "path": os.path.relpath(p, base),
                "sha256": None if data is None else _sha(data),
                "mutants": [{"name": m["name"],
                             "edits": [{"old": e["old"], "new": e["new"]}
                                       for e in m["edit"] if e["path"] == p]}
                            for m in chosen if any(e["path"] == p for e in m["edit"])]})
        man = dict({"format": _FORMAT, "writer": "mutate_port.py"}, **_identity(),
                   started=_iso(_STARTED), mutants_file=os.path.abspath(spec["path"]),
                   mutants=[m["name"] for m in chosen], files=files, complete=True)
        stage = f"{final}.tmp-{os.getpid()}"
        shutil.rmtree(stage, ignore_errors=True)  # a dead run's, with our pid
        try:
            os.mkdir(stage)
            for i, data in enumerate(tree.snap.values()):
                if data is not None:
                    _put(stage, f"orig-{i}", data)
            _put(stage, "manifest.json", json.dumps(man, indent=1).encode())
            _fsync_dir(stage)
            os.rename(stage, final)  # fails onto a journal that is there
        except OSError as e:
            shutil.rmtree(stage, ignore_errors=True)
            if os.path.lexists(final):
                raise Usage(f"{final} is in place: another run holds this run.dir; "
                            f"run again to see whose")
            raise Usage(f"cannot write the journal {final} ({e}): a run that cannot "
                        f"journal writes no mutant")
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        _HELD.add(final)
        _fsync_dir(base)
        journal = cls(final)
        moved = [os.path.relpath(p, base) for p, data in tree.snap.items()
                 if _read(p) != data]
        if moved:
            journal.remove()
            raise Usage(f"{', '.join(moved)} changed while the journal was written "
                        f"(another run, or an editor): nothing was mutated")
        return journal

    def remove(self, by="this run"):
        """Out of sight first, by one rename, then deleted: a kill meanwhile
        leaves a `.done-` directory, which is no journal. Called only once the
        tree is put back and checked; JournalLeft when the journal cannot be
        removed, or is gone already."""
        done = f"{self.path}.done-{os.getpid()}"
        shutil.rmtree(done, ignore_errors=True)
        try:
            os.rename(self.path, done)
        except OSError as e:
            _HELD.discard(self.path)
            if os.path.lexists(self.path):
                raise JournalLeft(f"the tree was put back and checked, but its journal "
                                  f"{self.path} cannot be removed ({e}): remove it by "
                                  f"hand, then run --check-clean")
            raise JournalLeft(f"the tree was put back and checked, but its journal "
                              f"{self.path} was gone before {by} removed it: something "
                              f"else removed it meanwhile (another --restore, or a "
                              f"hand), so the tree was not kept from another run while "
                              f"it was mutated. Run --check-clean")
        _fsync_dir(os.path.dirname(self.path))
        _HELD.discard(self.path)
        shutil.rmtree(done, ignore_errors=True)


def _load_journal(jdir):
    """(manifest, originals) of a complete journal, or Broken: a journal is
    used to restore only whole, with every copy matching its SHA-256."""
    raw = _read(os.path.join(jdir, "manifest.json"))
    if raw is None:
        raise Broken("it has no manifest.json")
    try:
        man = json.loads(raw)
    except ValueError:
        raise Broken("its manifest.json is not JSON (cut short?)")
    if not isinstance(man, dict) or man.get("complete") is not True:
        raise Broken("its manifest.json has no `complete` mark: it was never finished")
    if man.get("format") != _FORMAT:
        raise Broken(f"it is format {man.get('format')!r}; this harness reads {_FORMAT}")
    files = man.get("files")
    try:
        assert isinstance(man["pid"], int) and man["pid"] > 0 and isinstance(files, list)
        for f in files:
            assert isinstance(f["path"], str) and isinstance(f["sha256"], (str, type(None)))
            for m in f["mutants"]:
                assert isinstance(m["name"], str)
                _edits(m)
    except (AssertionError, KeyError, TypeError, AttributeError):
        raise Broken("its manifest.json is malformed")
    base = os.path.realpath(os.path.dirname(jdir))
    originals = []
    for i, f in enumerate(files):
        f["full"] = os.path.realpath(os.path.join(base, f["path"]))
        if os.path.commonpath([f["full"], base]) != base:
            raise Broken(f"it names {f['path']!r}, outside run.dir")
        if f["sha256"] is None:
            originals.append(None)
            continue
        data = _read(os.path.join(jdir, f"orig-{i}"))
        if data is None:
            raise Broken(f"the copy of {f['path']} (orig-{i}) is missing")
        if _sha(data) != f["sha256"]:
            raise Broken(f"the copy of {f['path']} (orig-{i}) does not match its "
                         f"SHA-256: cut short, or changed")
        originals.append(data)
    return man, originals


def _case(orig, cur, mutants):
    """(case, names) for one journaled file: "a" its original bytes; "b"
    exactly one journaled mutant applied to the original (every mutant that
    gives these bytes is named); "c" anything else, which nothing may touch."""
    if cur == orig:
        return "a", []
    names = [m["name"] for m in mutants if _forward(orig, _edits(m))[0] == cur]
    return ("b", names) if names else ("c", [])


def _cut(orig, cur, mutants):
    """What a (c) file's bytes are a strict start of, the original's or a
    journaled mutant's: a write a kill cut short (empty: cut at once)."""
    texts = [("its original", orig)] + [
        (f"mutant {m['name']!r}", _forward(orig, _edits(m))[0]) for m in mutants]
    return [n for n, t in texts if t is not None and cur is not None
            and len(cur) < len(t) and t.startswith(cur)]


def _sweep(base):
    """Delete what a dead run left beside its journal: one it was still
    building (it had written no mutant: a journal is in place before the first)
    or one it was removing (its tree was restored and checked first)."""
    for name in sorted(os.listdir(base)):
        for tag in (".tmp-", ".done-"):
            pid = name[len(JOURNAL + tag):]
            full = os.path.join(base, name)
            if name.startswith(JOURNAL + tag) and pid.isdigit() \
                    and not _writer_alive({"pid": int(pid)}):
                shutil.rmtree(full, ignore_errors=True)
                if not os.path.lexists(full):
                    print(f"note: removed {full}, which a dead run left; it is no "
                          f"journal", file=sys.stderr)


def _journal(base, restore=False):
    """Look for a journal under run.dir `base` before anything else reads or
    writes the tree. None when there is none; otherwise say what it holds and
    return the exit status. With `restore`, put back every (b) file."""
    _sweep(base)
    jdir = os.path.join(base, JOURNAL)
    say = lambda s: print(s, file=sys.stderr)  # noqa: E731
    if not os.path.lexists(jdir):
        if restore:
            say(f"{base}: no journal, nothing to restore")
            return 0
        return None
    try:
        man, originals = _load_journal(jdir)
    except Broken as e:
        say(f"error: {jdir} is not a complete journal: {e}. It is never used to "
            f"restore. A run builds its journal under another name and renames it "
            f"into place whole, so it was damaged or made by hand: check by hand "
            f"(git diff) every file the mutants touch, then remove it and run "
            f"--check-clean.")
        return 2
    who = (f"pid {man['pid']}, started {man.get('started', '?')}, mutants file "
           f"{man.get('mutants_file', '?')}")
    if _writer_alive(man):
        say(f"error: {jdir}: the run that wrote it is still running ({who}): another "
            f"run is in progress over {base}. Wait for it, or stop it with SIGTERM: "
            f"it restores the tree and removes its journal. If pid {man['pid']} is "
            f"not that run (a stale journal, its pid reused), stop that process or "
            f"let it exit, then run --restore.")
        return 2
    say(f"{'' if restore else 'error: '}{jdir}: a run was killed before it put the "
        f"tree back ({who}; that process is gone). Its files:")
    left, kept = [], False
    for i, f in enumerate(man["files"]):
        orig, cur = originals[i], _read(f["full"])
        case, names = _case(orig, cur, f["mutants"])
        if case == "a":
            say(f"  (a) {f['path']}: its original bytes")
        elif case == "b":
            also = f" (identical here to {', '.join(names[1:])})" if names[1:] else ""
            if not restore:
                say(f"  (b) {f['path']}: holds mutant {names[0]!r}{also}")
                left.append(f["path"])
                continue
            try:
                with _held():
                    _write(f["full"], orig)
                _fsync_file(f["full"])  # on disk before the journal's removal is
                err = "its SHA-256 does not match"
            except OSError as e:
                err = str(e)
            if _sha(_read(f["full"]) or b"") != f["sha256"]:
                say(f"  (b) {f['path']}: holds mutant {names[0]!r}, and could not be "
                    f"restored: {err}")
                kept = True
                continue
            say(f"  (b) {f['path']}: held mutant {names[0]!r}{also}; restored, SHA-256 checked")
        else:
            copy = os.path.join(jdir, f"orig-{i}")
            say(f"  (c) {f['path']}: changed since, and not by one journaled mutant; "
                f"never touched here. Its original bytes are {copy}"
                + ("" if orig is not None else " (none: it did not exist)"))
            cut = _cut(orig, cur, f["mutants"])
            if cut:
                say(f"      It is the start of {' and of '.join(cut)}: a write a kill cut "
                    f"short? If so, put back its original, then run --restore again: "
                    f"cp {shlex.quote(copy)} {shlex.quote(f['full'])}")
            kept = True
    if not restore:
        say(f"Run `mutate_port.py --restore {man.get('mutants_file', 'MUTANTS.toml')}` "
            f"to put back the (b) files and remove the journal"
            + (f" ({len(left)} file(s) hold a mutant)" if left else "") + ".")
        return 2
    if kept:
        say(f"The journal is kept: put each (c) file back by hand (or, if its change "
            f"is yours to keep, remove {jdir} by hand), then run --restore again.")
        return 2
    with _held():
        Journal(jdir).remove(by="this --restore")
    say(f"The tree is back, and the journal removed. --restore builds nothing: "
        f"rebuild before you test.")
    return 0


# ------------------------------------------------------------------ the run --

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


def run(spec, only=None, apply_only=False, first_kill=False, check_clean=False):
    """Every selected mutant's record. Raises Usage for a red baseline, for a
    full run over a tree that reads LIVE, and when another run's journal is in
    place. Writes the journal before its first write of a mutant, and before
    the baseline, so a second run is refused from the start; --check-clean
    writes nothing to the tree."""
    chosen = [m for m in spec["mutants"] if not only or m["name"] in only]
    if only and len(chosen) != len(only):
        raise Usage(f"--only names no mutant: {sorted(set(only) - {m['name'] for m in chosen})}")
    tree = Tree(chosen)
    state = {m["name"]: _state(tree.snap, m, spec["dir"]) for m in chosen}

    def record(m, v, why="", codes=None, killers=(), t0=None):
        return {"name": m["name"], "rule": m.get("rule", ""), "verdict": v,
                "killed_by": list(killers), "codes": codes or {}, "why": why,
                "seconds": round(time.time() - t0, 1) if t0 else 0.0}
    if check_clean:
        return [dict(record(m, *state[m["name"]]),
                     files=sorted({os.path.relpath(e["path"], spec["dir"]) for e in m["edit"]}))
                for m in chosen]
    live = [f"{n!r}: {why}" for n, (v, why) in state.items() if v == "LIVE"]
    if live and not apply_only:
        raise Usage("the tree reads as holding a mutant, so a baseline might test it: "
                    + "; ".join(live) + ". If a run was killed with it in place (see "
                    "--restore) or it was committed, put the code back (git diff), "
                    "then run --check-clean.")
    unsure = [n for n, (v, _) in state.items() if v == "AMBIGUOUS"]
    if unsure and not apply_only:
        print(f"warning: AMBIGUOUS: {', '.join(unsure)}: applied, each leaves its `old` "
              f"once again, so --check-clean cannot tell a tree that holds it from a "
              f"clean one (it and --apply-only exit 1 on it): widen its `old`. This run "
              f"tests it all the same.", file=sys.stderr)
    records, journal, based = [], None, False
    try:
        with _held():
            journal = Journal.create(spec, tree, chosen)
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
            based = True
        for m in chosen:
            t0 = time.time()
            if apply_only and state[m["name"]][0] in ("LIVE", "AMBIGUOUS"):
                records.append(record(m, *state[m["name"]], t0=t0))  # the tree's verdict
                continue
            applied, why = tree.apply(m)
            if not applied:  # every edit that fails, and whether the tree may hold it
                why = state[m["name"]][1] or why
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
            records.append(record(m, v, why or ("" if v in ("KILLED", "APPLIES") else
                                                "\n".join(said.values())[-600:]),
                                  codes, killers, t0))
    finally:
        if journal is not None:
            with _held():
                tree.restore(sync=True)  # checked and on disk; only then the journal goes
                journal.remove()
            if based:
                ok, why = _build(spec)
                if not ok:
                    print(f"warning: the rebuild after restoring failed; the build "
                          f"artifacts may not match the source: {why}", file=sys.stderr)
    return records


_GOOD = ("KILLED", "APPLIES", "CLEAN")


def _report(spec, records, mode):
    print(f"## {spec['path']}\n")
    print("| mutant | verdict | killed by | rule |\n|---|---|---|---|")
    for r in records:
        print(f"| {r['name']} | {r['verdict']} | {', '.join(r['killed_by']) or '—'} | {r['rule']} |")
    bad = [r for r in records if r["verdict"] not in _GOOD]
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
    if by and mode == "run":
        print("killed by: " + ", ".join(f"{g} {n} ({alone.get(g, 0)} alone)" for g, n in sorted(by.items())))
    if mode == "check-clean":
        files = {f for r in records for f in r["files"]}
        # A check that can find nothing must show it looked (LESSONS #086).
        print(f"{'clean' if not bad else 'NOT CLEAN'}: no journal under {spec['dir']}; "
              f"{len(records)} mutant(s) checked against {len(files)} file(s), "
              f"{len(records) - len(bad)} of them applying and not in the tree")
    return not bad


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("files", nargs="*")
    ap.add_argument("--only", help="comma-separated mutant names")
    ap.add_argument("--apply-only", action="store_true")
    ap.add_argument("--check-clean", action="store_true",
                    help="prove no mutant is left in the tree; writes nothing")
    ap.add_argument("--restore", action="store_true",
                    help="put back what a killed run's journal says it left")
    ap.add_argument("--first-kill", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.files:
        ap.error("name a mutants file")
    if a.restore and (a.only or a.apply_only or a.check_clean or a.first_kill or a.json):
        ap.error("--restore takes mutants files and nothing else")
    if a.check_clean and (a.apply_only or a.first_kill):
        ap.error("--check-clean applies nothing: not with --apply-only or --first-kill")

    def interrupted(signum, frame):
        raise Interrupted(f"signal {signum}")
    for s in _SIGNALS:
        signal.signal(s, interrupted)
    only = set(a.only.split(",")) if a.only else None
    mode = "check-clean" if a.check_clean else "apply-only" if a.apply_only else "run"
    ok, out = True, []
    try:
        if a.restore:
            dirs = dict.fromkeys(_run_dir(f) for f in a.files)
            return max([_journal(d, restore=True) for d in dirs])
        specs = [load(f) for f in a.files]
        # Before anything reads or writes the tree, for every file named.
        if [d for d in dict.fromkeys(s["dir"] for s in specs) if _journal(d) is not None]:
            return 2
        for spec in specs:
            records = run(spec, only, a.apply_only, a.first_kill, a.check_clean)
            out.append({"file": spec["path"], "mutants": records})
            if not a.json:
                ok = _report(spec, records, mode) and ok
            else:
                ok = ok and all(r["verdict"] in _GOOD for r in records)
    except Usage as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Unrestored as e:
        print(f"error: {e}; its journal is kept: run --restore", file=sys.stderr)
        return 2
    except JournalLeft as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except Interrupted as e:
        if a.restore:
            print(f"interrupted ({e}): run --restore again to see what is left",
                  file=sys.stderr)
        elif _HELD:
            print(f"interrupted ({e}) before the tree was put back: the journal "
                  f"{', '.join(sorted(_HELD))} is kept: run --restore", file=sys.stderr)
        else:
            print(f"interrupted ({e}): every mutated file was restored, and the "
                  f"journal removed", file=sys.stderr)
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
# A gate that kills a mutant of add() at once, or holds: while `slow.hold`
# exists, a mutant's run of it, and while `slow.base` exists, the baseline's.
# Held, it first names its own pid in `slow.started`, then sleeps: a run held
# mid-gate, for a test to signal or kill.
_HOLD = (b"import os, sys, time, prog\n"
         b"bad = prog.add(2, 3) != 5\n"
         b"if os.path.exists('slow.hold' if bad else 'slow.base'):\n"
         b"    open('slow.started.tmp', 'w').write(str(os.getpid()))\n"
         b"    os.rename('slow.started.tmp', 'slow.started')\n"
         b"    time.sleep(30)\n"
         b"sys.exit(1 if bad else 0)\n")


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


def _main(*argv):
    """main(argv) in this process: (exit status, all it printed). A crash is
    (None, what it raised): a failure the test reports, not one it dies of."""
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = main(list(argv))
    except Exception as e:  # noqa: BLE001 - reported as a FAIL by the caller
        return None, f"{buf.getvalue()}\ncrashed: {type(e).__name__}: {e}"
    return rc, buf.getvalue()


@contextlib.contextmanager
def _held_run(td, mutants, hold="slow.hold", via=None, env=None):
    """A run of `mutants` in its own process group, held in its slow gate: the
    first mutant's, with that mutant in the tree (`slow.hold`), or the
    baseline's (`slow.base`). `via` names a link to this harness to start it
    through, `env` its environment. Yields (mutants file, process, its gate's
    marker), and kills whatever is left of either on the way out."""
    path = _fixture(td, [("slow", "slow.py")], mutants)
    _write(os.path.join(td, "proj", "slow.py"), _HOLD)
    _write(os.path.join(td, "proj", hold), b"")
    script = os.path.abspath(__file__)
    if via:
        os.symlink(script, os.path.join(td, via))
        script = os.path.join(td, via)
    p = subprocess.Popen([sys.executable, script, path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE, start_new_session=True, env=env)
    marker = os.path.join(td, "proj", "slow.started")
    try:
        for _ in range(400):
            if os.path.exists(marker) or p.poll() is not None:
                break
            time.sleep(0.05)
        yield path, p, marker
    finally:
        if p.returncode is None:
            _kill_hard(p, marker)


def _kill_hard(p, marker):
    """SIGKILL the run's process group and its gate's, as a container restart
    does, and reap them: nothing outlives the test."""
    gate = int(_read(marker) or b"0")
    for group in (p.pid, gate):
        try:
            if group > 0:
                os.killpg(group, signal.SIGKILL)
        except OSError:
            pass
    p.communicate(timeout=30)


def _leftovers(proj):
    return sorted(n for n in os.listdir(proj) if n.startswith(JOURNAL))


def _refuse(p, data):
    raise PermissionError(13, "Permission denied", p)


class _Killed(BaseException):
    """A kill, simulated in this process: nothing catches it but the test."""


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
        ("absent", [("nosuch.py", "x", "y")]),
    ]
    write, real_rename, real_rmtree = _write, os.rename, shutil.rmtree
    with tempfile.TemporaryDirectory() as td:
        spec = load(_fixture(td, gates, mutants))
        proj = os.path.join(td, "proj")
        before = {p: _read(p) for p in Tree(spec["mutants"]).snap}
        recs = {r["name"]: r for r in run(spec)}
        want = {"subtracts": "KILLED", "commutes": "SURVIVED", "missing": "DOES-NOT-APPLY",
                "ambiguous": "DOES-NOT-APPLY", "nobuild": "NOBUILD", "unjudged": "INFRA",
                "judged": "KILLED", "two-files": "KILLED", "half-applies": "DOES-NOT-APPLY",
                "absent": "DOES-NOT-APPLY"}
        for name, v in want.items():
            check(f"{name} is {v}", recs[name]["verdict"] == v)
        check("a kill names its gate: subtracts by unit, judged by judge",
              recs["subtracts"]["killed_by"] == ["unit"] and recs["judged"]["killed_by"] == ["judge"])
        check("an `infra` exit is never a kill", recs["unjudged"]["killed_by"] == [])
        check("every touched file is restored byte for byte",
              all(_read(p) == b for p, b in before.items()))
        check("a run that ends leaves no journal (LESSONS #086)", _leftovers(proj) == [])
        stamp = _read(os.path.join(td, "proj", "built.stamp")).decode()
        check("the build ran again at the end: its output matches the source, not the last mutant",
              stamp == _sha(_PROG.encode()))
        check("a mutant that applies only in part writes nothing",
              _read(os.path.join(td, "proj", "other.py")) == b"x = 1\n")
        checked = {r["name"]: r["verdict"] for r in run(spec, apply_only=True)}
        check("--apply-only applies and reverts, without building",
              checked["subtracts"] == "APPLIES" and checked["missing"] == "DOES-NOT-APPLY")
        check("an --apply-only run leaves no journal either", _leftovers(proj) == [])
        # A stale mutant whose `new` is a prefix of a line ("return a" here)
        # reads, reverted, as one left in place: a hint, never a LIVE verdict
        # that would stop a full run over a tree that holds nothing.
        cc = {r["name"]: (r["verdict"], r["why"]) for r in run(spec, check_clean=True)}
        check("--check-clean: a stale mutant is DOES-NOT-APPLY, hinted only where `new` "
              "reverts into a tree it applies to",
              cc["subtracts"] == ("CLEAN", "") and cc["missing"][0] == "DOES-NOT-APPLY"
              and "may hold it: reverting its `new` at prog.py line 2, 6" in cc["missing"][1]
              and cc["ambiguous"][0] == "DOES-NOT-APPLY" and "may hold" not in cc["ambiguous"][1]
              and cc["absent"] == ("DOES-NOT-APPLY", "edit 1: nosuch.py cannot be read"))
        check("... and a full run says the same of it",
              "may hold it: reverting its `new` at prog.py line 2, 6" in recs["missing"]["why"])
        only = run(spec, only={"subtracts"}, first_kill=True)
        check("--only runs the named mutant alone", [r["name"] for r in only] == ["subtracts"])
        rc = main([spec["path"], "--only", "subtracts,judged"])
        check("exit 0 when every mutant run is killed", rc == 0)
        rc = main([spec["path"], "--only", "subtracts,commutes"])
        check("exit 1 when one survives", rc == 1)
        rc = main([spec["path"], "--apply-only", "--only", "subtracts,missing"])
        check("--apply-only exits 1 when a mutant no longer applies", rc == 1)
        # The journal is the lock: one in place stops a run before it writes,
        # however it got past the look main() takes first.
        os.mkdir(os.path.join(proj, JOURNAL))
        _write(os.path.join(proj, JOURNAL, "manifest.json"), b"{}")
        try:
            run(spec, only={"subtracts"}, apply_only=True)
            took = True
        except Usage:
            took = False
        check("a run refuses, writing nothing, while another's journal is in place",
              not took and all(_read(p) == b for p, b in before.items())
              and _read(os.path.join(proj, JOURNAL, "manifest.json")) == b"{}")
        shutil.rmtree(os.path.join(proj, JOURNAL))
        # The tree moving between the snapshot and the journal is a run that
        # cannot know its originals: it stops, and leaves no journal.
        tree = Tree(spec["mutants"])
        _write(os.path.join(proj, "other.py"), b"x = 1  # edited meanwhile\n")
        try:
            Journal.create(spec, tree, spec["mutants"])
            stopped = False
        except Usage:
            stopped = True
        check("a file that changes while the journal is written stops the run, with no journal",
              stopped and _leftovers(proj) == []
              and _read(os.path.join(proj, "other.py")) == b"x = 1  # edited meanwhile\n")
        _write(os.path.join(proj, "other.py"), b"x = 1\n")

        # How the journal is written and removed, each failure on its own
        # (LESSONS #086). `one` is an --apply-only run of one mutant.
        jdir = os.path.join(spec["dir"], JOURNAL)
        progp = os.path.join(spec["dir"], "prog.py")
        orig = _PROG.encode()
        intact = lambda: all(_read(p) == b for p, b in before.items())  # noqa: E731
        one = lambda: _main(spec["path"], "--apply-only", "--only", "subtracts")  # noqa: E731
        # Signals wait while the journal is written, or the tree is put back
        # and the journal removed: one sent inside arrives after.
        got = []
        prev = signal.signal(signal.SIGHUP, lambda s, f: got.append(s))
        try:
            with _held():
                os.kill(os.getpid(), signal.SIGHUP)
                time.sleep(0.05)
                inside = list(got)
            for _ in range(100):
                if got:
                    break
                time.sleep(0.01)
        finally:
            signal.signal(signal.SIGHUP, prev)
        check("a signal sent while the journal is written or removed waits until that is done",
              inside == [] and got == [signal.SIGHUP])
        # SIGTERM the moment the journal is in place: held, it arrives once the
        # run has it, which puts the tree back and removes it. Unheld, it cuts
        # Journal.create between the rename and the record of it, and leaves a
        # journal that nothing removes.

        def rename(src, dst, *a, **k):
            real_rename(src, dst, *a, **k)
            if dst == jdir:
                os.kill(os.getpid(), signal.SIGTERM)
        os.rename = rename
        try:
            rc, said = one()
        finally:
            os.rename = real_rename
        check("SIGTERM as the journal goes into place: the tree put back, the journal removed, exit 2",
              rc == 2 and "journal removed" in said and _leftovers(proj) == [] and intact())
        shutil.rmtree(jdir, ignore_errors=True)
        # The final restore fails, cut short or refused: the journal stays.
        for what, bad in (("cut short", lambda p, d: write(p, d[:-1])), ("refused", _refuse)):
            globals()["_write"] = lambda p, d, bad=bad: bad(p, d) if d == orig else write(p, d)
            try:
                rc, said = one()
            finally:
                globals()["_write"] = write
            check(f"a final restore {what}: exit 2, said, and the journal kept for --restore",
                  rc == 2 and "journal is kept: run --restore" in said and os.path.isdir(jdir))
            write(progp, orig)
            shutil.rmtree(jdir, ignore_errors=True)
            _HELD.discard(jdir)
        # A mutant that cannot be written: exit 2, said, nothing left behind.
        globals()["_write"] = lambda p, d: _refuse(p, d) if d != orig else write(p, d)
        try:
            rc, said = one()
        finally:
            globals()["_write"] = write
        check("a mutant that cannot be written: exit 2, said, the tree as it was, no journal",
              rc == 2 and "cannot write mutant 'subtracts'" in said and intact()
              and _leftovers(proj) == [])
        # A journal that cannot be removed, or is gone first: exit 2, said.

        def deny(src, dst, *a, **k):
            if src == jdir and ".done-" in dst:
                raise PermissionError(1, "Operation not permitted", src)
            return real_rename(src, dst, *a, **k)

        def lose(src, dst, *a, **k):
            if src == jdir and ".done-" in dst:
                real_rmtree(src)
            return real_rename(src, dst, *a, **k)
        for what, patch, says, left in (
                ("cannot be removed", deny, "remove it by hand", [JOURNAL]),
                ("is gone first", lose, "was gone before this run removed it", [])):
            os.rename = patch
            try:
                rc, said = one()
            finally:
                os.rename = real_rename
            check(f"a journal that {what}: exit 2, said, the tree put back and checked",
                  rc == 2 and says in said and intact() and _leftovers(proj) == left)
            shutil.rmtree(jdir, ignore_errors=True)
        # Killed while its journal is deleted: renamed aside first, it leaves
        # a `.done-` directory, which is no journal, and the next run sweeps.

        def dying(path, *a, **k):
            name = os.path.basename(path)
            if name.startswith(JOURNAL) and ".tmp-" not in name and os.path.isdir(path):
                os.remove(os.path.join(path, "manifest.json"))
                raise _Killed()
            return real_rmtree(path, *a, **k)
        shutil.rmtree = dying
        try:
            one()
            died = False
        except _Killed:
            died = True
        finally:
            shutil.rmtree = real_rmtree
        rc, said = _main(spec["path"], "--check-clean", "--only", "subtracts")
        check("killed while its journal is deleted, a run leaves none: the next sweeps the rest",
              died and rc == 0 and _leftovers(proj) == [] and intact())
        # Each restored file reaches the disk before the journal's removal.
        events = []
        real_sync, real_remove = _fsync_file, Journal.remove
        globals()["_fsync_file"] = lambda p: (events.append(("sync", p)), real_sync(p))
        Journal.remove = lambda self, **k: (events.append(("remove",)), real_remove(self, **k))
        try:
            rc, said = one()
        finally:
            globals()["_fsync_file"], Journal.remove = real_sync, real_remove
        check("a run fsyncs each restored file before it removes its journal",
              rc == 0 and ("sync", progp) in events and ("remove",) in events
              and events.index(("sync", progp)) < events.index(("remove",)))
        # No /proc (macOS): the run is named by the start ps gives.
        proc = _PROC
        globals()["_PROC"] = os.path.join(td, "no-proc")
        try:
            ident = _identity()
            rc, said = one()
        finally:
            globals()["_PROC"] = proc
        check("with no /proc a run journals its start by ps, and runs as ever",
              ident["proc_start"] is None and (ident["ps_start"] or not shutil.which("ps"))
              and rc == 0 and _leftovers(proj) == [] and intact())

    with tempfile.TemporaryDirectory() as td:
        path = _fixture(td, [("unit", "unit.py")], [("subtracts", [("prog.py", "return a + b", "return a - b")])])
        _write(os.path.join(td, "proj", "unit.py"), b"import sys\nsys.exit(1)\n")
        check("a red baseline is exit 2, before any mutant runs", main([path]) == 2)
        check("... and leaves no journal", _leftovers(os.path.join(td, "proj")) == [])

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

    # THE CLEAN-TREE PROOF (LESSONS #086), on a tree no journal describes: a
    # mutant left by a hand script, by a harness older than the journal, or in
    # a commit. `new` texts are never counted: this tree carries one in a
    # comment, so a count would see a mutant where there is none, and miss
    # the one that is there.
    prog = _PROG + "\n# `return a - b` would be wrong\n"
    guard = "    if a < 0:\n        return 0\n    return a * 2\n"
    with tempfile.TemporaryDirectory() as td:
        path = _fixture(td, [("unit", "unit.py")], [
            ("subtracts", [("prog.py", "return a + b", "return a - b")]),
            ("guards", [("prog.py", "    return a * 2\n", guard)]),
            ("drops-twice", [("prog.py", "def twice(a):\n    return a * 2\n", "")])])
        progp = os.path.join(td, "proj", "prog.py")
        _write(progp, prog.encode())
        rc, said = _main(path, "--check-clean")
        check("--check-clean passes a clean tree, though a mutant's `new` occurs in it, "
              "and says what it checked",
              rc == 0 and "3 mutant(s) checked against 1 file(s)" in said)
        check("... and writes nothing", _read(progp) == prog.encode()
              and _leftovers(os.path.join(td, "proj")) == [])
        _write(progp, prog.replace("return a + b", "return a - b", 1).encode())
        v = {r["name"]: r["verdict"] for r in run(load(path), check_clean=True)}
        rc, said = _main(path, "--check-clean")
        check("a mutant left in place, its `new` occurring elsewhere too, fails it: exit 1, "
              "and the tree is said to hold it",
              v == {"subtracts": "DOES-NOT-APPLY", "guards": "CLEAN", "drops-twice": "CLEAN"}
              and rc == 1
              and "the tree may hold it: reverting its `new` at prog.py line 2, 8" in said)
        # An inserted line keeps its anchor: the `old` count cannot see it,
        # and the unit gate cannot either, so a baseline over it is green.
        held = prog.replace("    return a * 2\n", guard).encode()
        _write(progp, held)
        v = {r["name"]: (r["verdict"], r["why"]) for r in run(load(path), check_clean=True)}
        rc, said = _main(path, "--apply-only")
        check("a mutant whose `new` keeps its `old` is LIVE to --check-clean and --apply-only",
              v["subtracts"][0] == "CLEAN" and v["guards"][0] == "LIVE" and rc == 1
              and "LIVE: guards" in said and _read(progp) == held)
        # Those bytes are also a clean tree that has the guard already: LIVE
        # says so, and how to re-anchor; never that the mutant is stale.
        check("... and LIVE says the code may have its `new` at its anchor already: re-anchor",
              "so its `new` does not occur in the clean tree" in v["guards"][1]
              and "stale" not in v["guards"][1])
        # An empty `new` occurs everywhere: too many places to revert, no hint.
        check("a mutant with an empty `new` that does not apply is DOES-NOT-APPLY, unhinted",
              v["drops-twice"][0] == "DOES-NOT-APPLY" and "may hold" not in v["drops-twice"][1])
        rc, said = _main(path)
        check("a full run over it refuses, exit 2, before it builds or writes",
              rc == 2 and "reads as holding a mutant" in said and "stale" not in said
              and _read(progp) == held
              and not os.path.exists(os.path.join(td, "proj", "built.stamp"))
              and _leftovers(os.path.join(td, "proj")) == [])

    # A mutant whose own edit re-forms its `old` (LESSONS #086): 0x1000 ->
    # 0x100 over 0x10000 leaves 0x1000 again, so a tree holding it passes the
    # count as a clean one does. On the clean tree it is AMBIGUOUS, exit 1,
    # never CLEAN or LIVE; a full run runs it, and warns.
    with tempfile.TemporaryDirectory() as td:
        path = _fixture(td, [("limit", "limit.py")], [
            ("smaller", [("lib.py", "0x1000", "0x100")]),
            ("subtracts", [("prog.py", "return a + b", "return a - b")])])
        libp = os.path.join(td, "proj", "lib.py")
        _write(libp, b"LIMIT = 0x10000\n")
        _write(os.path.join(td, "proj", "limit.py"),
               b"import sys, lib\nsys.exit(0 if lib.LIMIT == 0x10000 else 1)\n")
        v = {r["name"]: (r["verdict"], r["why"]) for r in run(load(path), check_clean=True)}
        rc, said = _main(path, "--check-clean")
        check("a mutant that re-forms its own `old` is AMBIGUOUS on the clean tree: "
              "--check-clean exits 1, and says to widen its `old`",
              v["smaller"][0] == "AMBIGUOUS" and "widen its `old`" in v["smaller"][1]
              and v["subtracts"] == ("CLEAN", "") and rc == 1 and "NOT CLEAN" in said)
        rc, said = _main(path, "--apply-only")
        check("... --apply-only exits 1 on it as well, and writes nothing",
              rc == 1 and "| smaller | AMBIGUOUS |" in said and _read(libp) == b"LIMIT = 0x10000\n")
        rc, said = _main(path, "--only", "smaller")
        check("... a full run is not refused: it runs it (killed here) and warns",
              rc == 0 and "warning: AMBIGUOUS: smaller" in said and "1 KILLED" in said
              and _read(libp) == b"LIMIT = 0x10000\n")
        # Held, it reads CLEAN: nothing in the tree can say otherwise. That
        # is the limit the docstring states, and why it is refused above,
        # before it can be committed.
        _write(libp, b"LIMIT = 0x1000\n")
        v = {r["name"]: r["verdict"] for r in run(load(path), check_clean=True)}
        check("... held, it reads CLEAN, as the docstring says: the tree cannot tell",
              v["smaller"] == "CLEAN")
    # An inserted line beside a long deletion, in a file longer than the
    # places a revert may try: only reverts that break the `old` already
    # there are tried, depth first, so the clean tree is cleared, not LIVE.
    big = "".join(f"v{i} = {i}\n" for i in range(1000))
    cut = "".join(f"v{i} = {i}\n" for i in range(500, 600))
    f = os.path.join(os.getcwd(), "f.py")
    m = {"name": "m", "edit": [{"path": f, "old": "v5 = 5\n", "new": "v5 = 5\nassert v5\n"},
                               {"path": f, "old": cut, "new": ""}]}
    held = big.replace("v5 = 5\n", "v5 = 5\nassert v5\n").replace(cut, "")
    check("an inserted line beside a long deletion: CLEAN on a long clean file, not CLEAN held",
          _state({f: big.encode()}, m, os.getcwd())[0] == "CLEAN"
          and _state({f: held.encode()}, m, os.getcwd())[0] != "CLEAN")

    # A run killed outright (LESSONS #086): SIGKILL to its process group and
    # its gate's, mid-gate, as a container restart does. The tree holds the
    # mutant; the journal must say so, and --restore must undo it.
    two = [("subtracts", [("prog.py", "return a + b", "return a - b"), ("other.py", "x = 1", "x = 2")])]
    mutated = _PROG.replace("return a + b", "return a - b").encode()
    with tempfile.TemporaryDirectory() as td, _held_run(td, two) as (path, p, marker):
        proj = os.path.join(td, "proj")
        progp, otherp = os.path.join(proj, "prog.py"), os.path.join(proj, "other.py")
        jdir = os.path.join(proj, JOURNAL)
        outside = os.path.join(td, "outside")
        held = os.path.exists(marker)
        _kill_hard(p, marker)
        check("SIGKILL mid-gate leaves the mutant in the tree",
              held and _read(progp) == mutated and _read(otherp) == b"x = 2\n")
        try:
            man, originals = _load_journal(jdir)
            whole = (man["pid"] == p.pid and originals == [_PROG.encode(), b"x = 1\n"]
                     and [f["path"] for f in man["files"]] == ["prog.py", "other.py"])
        except Broken:
            man, whole = None, False
        check("... and a complete journal: the writer, each file's original bytes", whole)
        stamp = _read(os.path.join(proj, "built.stamp"))
        for args, what in (((), "a new run"), (("--apply-only",), "--apply-only"),
                           (("--check-clean",), "--check-clean")):
            rc, said = _main(path, *args)
            check(f"{what} exits 2, naming the file and the mutant, and touches nothing",
                  rc == 2 and "(b) prog.py: holds mutant 'subtracts'" in said
                  and "--restore" in said and _read(progp) == mutated
                  and _read(os.path.join(proj, "built.stamp")) == stamp)
        # Whose journal it is: our own pid (pids repeat after a container
        # restart), or a live process that is not this harness, is a dead run.
        good = _read(os.path.join(jdir, "manifest.json"))
        sleeper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            for pid, what in ((os.getpid(), "this process's own pid"),
                              (sleeper.pid, "a live process that is not this harness")):
                _write(os.path.join(jdir, "manifest.json"),
                       json.dumps(dict(json.loads(good), pid=pid, proc_start=None,
                                       ps_start=None)).encode())
                rc, said = _main(path)
                check(f"a journal naming {what} is a killed run's, not a live one",
                      rc == 2 and "holds mutant 'subtracts'" in said and "still running" not in said)
        finally:
            sleeper.kill()
            sleeper.wait()
            _write(os.path.join(jdir, "manifest.json"), good)
        # A journal that is not whole is never used to restore.
        saved = os.path.join(td, "saved")
        shutil.copytree(jdir, saved)

        def elsewhere():
            m = json.loads(good)
            m["files"][0]["path"] = "../outside"
            _write(outside, mutated)
            _write(os.path.join(jdir, "manifest.json"), json.dumps(m).encode())
        for what, spoil in (
                ("a manifest without its `complete` mark",
                 lambda: _write(os.path.join(jdir, "manifest.json"),
                                json.dumps(dict(json.loads(good), complete=None)).encode())),
                ("a manifest never renamed into place",
                 lambda: os.rename(os.path.join(jdir, "manifest.json"),
                                   os.path.join(jdir, "manifest.json.tmp"))),
                ("an original copy cut short",
                 lambda: _write(os.path.join(jdir, "orig-0"), _PROG.encode()[:20])),
                ("an original copy missing", lambda: os.remove(os.path.join(jdir, "orig-1"))),
                ("a manifest naming a file outside run.dir", elsewhere)):
            spoil()
            rc, said = _main(path, "--restore")
            check(f"{what}: --restore refuses, exit 2, and touches nothing",
                  rc == 2 and "not a complete journal" in said and _read(progp) == mutated
                  and _read(otherp) == b"x = 2\n" and os.path.isdir(jdir)
                  and _read(outside) in (None, mutated))
            shutil.rmtree(jdir)
            shutil.copytree(saved, jdir)
        # A journal still being built when its run was killed is no journal:
        # that run had written no mutant. It is swept, never used.
        os.rename(jdir, f"{jdir}.tmp-{p.pid}")
        rc, said = _main(path, "--restore")
        check("a journal killed before its rename into place is swept, never used",
              rc == 0 and "nothing to restore" in said and _read(progp) == mutated
              and _leftovers(proj) == [])
        rc, said = _main(path, "--check-clean")
        check("with the journal lost, --check-clean still fails on the mutant, in both files",
              rc == 1 and "DOES-NOT-APPLY: subtracts" in said
              and "may hold it: reverting its `new` at prog.py line 2" in said
              and "may hold it: reverting its `new` at other.py line 1" in said)
        shutil.copytree(saved, jdir)
        # A write that does not come back as the original, or is refused, is
        # caught: reported, the journal kept.
        for what, bad in (("does not come back as the original", lambda p, d: write(p, d[:-1])),
                          ("cannot be written", _refuse)):
            globals()["_write"] = bad
            try:
                rc, said = _main(path, "--restore")
            finally:
                globals()["_write"] = write
            check(f"a restore that {what} is reported, the journal kept: exit 2",
                  rc == 2 and "could not be restored" in said and os.path.isdir(jdir))
            _write(progp, mutated)
            _write(otherp, b"x = 2\n")
        # A file that is the start of what was being written, a write a kill
        # cut short: (c), never touched, with the `cp` that puts it back.
        for what, cur in (("the start of it", _PROG.encode()[:20]), ("empty", b"")):
            _write(progp, cur)
            rc, said = _main(path, "--restore")
            check(f"a file cut short ({what}) is left alone, with the cp that puts back its original",
                  rc == 2 and _read(progp) == cur and "(c) prog.py" in said
                  and "It is the start of its original and of mutant 'subtracts'" in said
                  and "cp " in said and "orig-0 " in said)
        _write(progp, mutated)
        _write(otherp, b"x = 2\n")
        # --restore, too, fsyncs each file it puts back before it removes the
        # journal; a journal it cannot remove is exit 2, said.
        events = []
        real_sync, real_remove = _fsync_file, Journal.remove
        globals()["_fsync_file"] = lambda p: (events.append(("sync", os.path.basename(p))), real_sync(p))
        Journal.remove = lambda self, **k: (events.append(("remove",)), real_remove(self, **k))
        os.rename = lambda src, dst, *a, **k: (
            _refuse(src, b"") if ".done-" in dst else real_rename(src, dst, *a, **k))
        try:
            rc, said = _main(path, "--restore")
        finally:
            globals()["_fsync_file"], Journal.remove, os.rename = real_sync, real_remove, real_rename
        check("--restore fsyncs each file it puts back before it removes the journal",
              ("sync", "prog.py") in events and ("remove",) in events
              and events.index(("sync", "prog.py")) < events.index(("remove",)))
        check("... and a journal it cannot remove is exit 2, said; the tree is back",
              rc == 2 and "remove it by hand" in said and _read(progp) == _PROG.encode()
              and os.path.isdir(jdir))
        _write(progp, mutated)
        _write(otherp, b"x = 2\n")
        rc, said = _main(path, "--restore")
        check("--restore exits 0: the tree byte-identical to the original, the journal gone",
              rc == 0 and _read(progp) == _PROG.encode() and _read(otherp) == b"x = 1\n"
              and _leftovers(proj) == [] and "restored, SHA-256 checked" in said)
        os.remove(os.path.join(proj, "slow.hold"))
        rc, said = _main(path)
        check("a full run then passes", rc == 0 and "1 KILLED" in said)
        check("... and --check-clean proves the tree clean", _main(path, "--check-clean")[0] == 0)

    # Changed by hand after the kill: never touched, the journal kept.
    with tempfile.TemporaryDirectory() as td, _held_run(td, two) as (path, p, marker):
        proj = os.path.join(td, "proj")
        progp, otherp = os.path.join(proj, "prog.py"), os.path.join(proj, "other.py")
        _kill_hard(p, marker)
        mine = mutated + b"# mine\n"
        _write(progp, mine)
        rc, said = _main(path, "--restore")
        check("--restore leaves a file changed since by hand untouched, keeps the journal: exit 2",
              rc == 2 and _read(progp) == mine and os.path.isdir(os.path.join(proj, JOURNAL))
              and "(c) prog.py" in said and "It is the start" not in said)
        check("... and puts back the file that holds exactly the mutant",
              _read(otherp) == b"x = 1\n")
        _write(progp, _PROG.encode())
        rc, said = _main(path, "--restore")
        check("once the file is back by hand, --restore removes the journal: exit 0",
              rc == 0 and _leftovers(proj) == [])

    # Interrupted mid-gate: the tree is put back all the same, and the journal
    # goes; while the run lives, its journal is refused, not restored. Whose
    # journal it is goes by the start it records, never by the pid alone.
    with tempfile.TemporaryDirectory() as td:
        proj = os.path.join(td, "proj")
        progp = os.path.join(proj, "prog.py")
        jdir = os.path.join(proj, JOURNAL)
        with _held_run(td, [("subtracts", [("prog.py", "return a + b", "return a - b")])]) \
                as (path, p, marker):
            held = os.path.exists(marker)
            rc, said = _main(path)
            check("a second run while the first is in its gate refuses: exit 2",
                  held and rc == 2 and "still running" in said and f"pid {p.pid}" in said)
            rc, said = _main(path, "--restore")
            check("--restore refuses a journal whose writer is alive, and touches nothing",
                  rc == 2 and "still running" in said and _read(progp) == mutated)
            good = json.loads(_read(os.path.join(jdir, "manifest.json")) or b"{}")
            dead = subprocess.Popen([sys.executable, "-c", ""])
            dead.wait()
            if good.get("proc_start") is not None:
                later = good["proc_start"] + 10 ** 9  # no process here started then
                variants = (
                    ("the run's pid, started another time", dict(proc_start=later), False),
                    ("the run's pid and start, on another boot", dict(boot_id="another"), False),
                    ("another pid namespace and the run's start", dict(pid=dead.pid, pid_ns="pid:[1]"), True),
                    ("another pid namespace and another start",
                     dict(pid=dead.pid, pid_ns="pid:[1]", proc_start=later), False),
                    ("the run's pid and no start (a python running mutate_port.py)",
                     dict(proc_start=None), True))
            else:  # no /proc here: the start ps gives
                variants = (
                    ("the run's pid, started another time", dict(ps_start="Thu Jan  1 00:00:00 1970"), False),
                    ("the run's pid and no start (a python running mutate_port.py)",
                     dict(ps_start=None), True))
            for what, change, alive in variants:
                _write(os.path.join(jdir, "manifest.json"), json.dumps(dict(good, **change)).encode())
                rc, said = _main(path, "--check-clean")
                check(f"a journal naming {what} is {'a live run' if alive else 'a killed run'}'s",
                      rc == 2 and ("still running" in said) == alive and ("was killed" in said) != alive)
            _write(os.path.join(jdir, "manifest.json"), json.dumps(good).encode())
            # What a run leaves beside its journal is swept only once it is dead.
            gone = os.path.join(proj, f"{JOURNAL}.done-{dead.pid}")
            live = os.path.join(proj, f"{JOURNAL}.done-{p.pid}")
            os.mkdir(gone)
            os.mkdir(live)
            rc, said = _main(path, "--check-clean")
            check("a dead run's half-removed journal is swept; a live run's is not",
                  rc == 2 and not os.path.lexists(gone) and os.path.isdir(live))
            os.rmdir(live)
            p.send_signal(signal.SIGTERM)
            try:
                _, err = p.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                err = b""
        check("SIGTERM in the middle of a gate restores the tree, and exits 2",
              held and p.returncode == 2 and _read(progp) == _PROG.encode())
        check("... and removes the journal", _leftovers(proj) == [] and b"journal removed" in err)

    # A run started under another name, held in its BASELINE gate: its journal
    # is in place before the baseline, and it is known by its start, so a
    # second invocation is refused as a live run's, not taken for a dead one.
    with tempfile.TemporaryDirectory() as td:
        proj = os.path.join(td, "proj")
        with _held_run(td, [("subtracts", [("prog.py", "return a + b", "return a - b")])],
                       hold="slow.base", via="mp") as (path, p, marker):
            held = os.path.exists(marker)
            rc, said = _main(path, "--check-clean")
            check("a run started through a link, in its baseline, is refused as still running",
                  held and rc == 2 and "still running" in said
                  and _read(os.path.join(proj, "prog.py")) == _PROG.encode())
            p.send_signal(signal.SIGTERM)
            try:
                p.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                pass
        check("... and SIGTERM there leaves the tree as it was and no journal",
              p.returncode == 2 and _leftovers(proj) == []
              and _read(os.path.join(proj, "prog.py")) == _PROG.encode())

    # Where there is no /proc (macOS), the same, by the start ps gives: here
    # the run and this test are pointed at a /proc that is not there.
    if shutil.which("ps") is None:
        print("SKIP  no ps here: the path a host without /proc takes is not run")
    else:
        _no_proc(check)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def _no_proc(check):
    """The journal's liveness where there is no /proc (macOS), run here by
    pointing the run, and this process, at a /proc that is not there."""
    with tempfile.TemporaryDirectory() as td:
        noproc = os.path.join(td, "no-proc")
        proj = os.path.join(td, "proj")
        progp = os.path.join(proj, "prog.py")
        jm = os.path.join(proj, JOURNAL, "manifest.json")
        with _held_run(td, [("subtracts", [("prog.py", "return a + b", "return a - b")])],
                       env=dict(os.environ, MUTATE_PORT_PROC=noproc)) as (path, p, marker):
            held = os.path.exists(marker)
            good = json.loads(_read(jm) or b"{}")
            proc = _PROC
            globals()["_PROC"] = noproc
            try:
                alive = _main(path, "--check-clean")
                _write(jm, json.dumps(dict(good, ps_start="Thu Jan  1 00:00:00 1970")).encode())
                other = _main(path, "--check-clean")
                _write(jm, json.dumps(good).encode())
                _kill_hard(p, marker)
                rc, said = _main(path, "--restore")
            finally:
                globals()["_PROC"] = proc
        check("with no /proc the journal records the run's start as ps gives it",
              held and good.get("proc_start") is None and bool(good.get("ps_start")))
        check("... a live run is refused by it", alive[0] == 2 and "still running" in alive[1])
        check("... the same pid started at another time is a killed run",
              other[0] == 2 and "was killed" in other[1])
        check("... and once it is killed, --restore puts the tree back",
              rc == 0 and _read(progp) == _PROG.encode() and _leftovers(proj) == [])


if __name__ == "__main__":
    sys.exit(main())
