#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #4->#004, #6->#036, #8->#043, #14->#037, #16->#050;
#          #36 by title (no entry in this log).
# Local: #080, #084.
"""Differential fuzzing — feed the SAME generated input to the C oracle and the
Rust rewrite and compare, over thousands of mutated inputs. The fixed matrix
(diff_run.py) checks the cases you thought of; this finds the semantic
divergences you didn't (OPERATING-GUIDE §3/§5 P1: "the highest-value single
addition for a security-critical port").

It is a black-box fuzzer over TWO binaries — it does not need cargo-fuzz (that is
the in-process, Rust-only, panic-finding gate 3). Here the signal is not "Rust
panics" but "Rust and C disagree": a divergence on some input the matrix never
had. Each finding is minimized to its smallest triggering input and saved as a
committable reproducer.

Fidelity and triage are NOT reimplemented here: every generated input is judged
by `diff_run.compare_one`, so the stdout+exit-code verdict (LESSONS #004), the
fail-closed timeout handling (a rust-side hang on some input is a finding, not a
pass — LESSONS #036), and the ledger fingerprint (LESSONS #043) are exactly the same
as the matrix differential. A divergence whose fingerprint is pinned in
DIVERGENCES.md (``- [x] `fuzz:<desc>` [sha256:<hex>]: <why>``) is a known-intentional
divergence and is suppressed — triage a fuzz finding the same way you triage a
matrix one.

Determinism: everything random is driven by `--seed` (default 0), so a run is
100% reproducible and a reported finding always reproduces. The input is fuzzed
on STDIN by default (the parse/decode surface the port must harden); fixed argv
comes from `--args`.

ARGV MODE (`--argv-inventory FILE`). A tool whose input is its command line has
its parser on argv, and stdin never reaches it. In this mode the fuzzed input is
the words after `--args`: options drawn from a coverage-gate feature inventory
(its `options` letters, and which of them `takes_value`), spelt every way getopt
offers them (`-x`, `+x`, a cluster, a value attached or in the next word, a
value from a list of awkward ones plus `--argv-value`), options first and at
most one operand last. Minimizing drops whole words. lsof-rs found its
option-parsing divergences by hand over a week; this mode, run for a minute
against the binary from before that week, finds 34 of them (LESSONS #084).
Run it from an empty directory: a value of `.` names the directory it runs in,
and a tool that walks a tree walks that one. `--argv-exclude` drops letters
that cannot be compared (one that repeats for ever, one that prints a build
stamp, one that writes a cache file).

Usage:
  diff_fuzz.py --oracle PATH --rust PATH [--seed N] [--iterations N | --max-time S]
               [--args A ...] [--seed-file F ...] [--matrix M]
               [--argv-inventory TOML [--argv-exclude LETTERS]
                [--argv-value V ...] [--argv-words N]]
               [--ledger DIVERGENCES.md] [--findings-dir DIR]
               [--timeout S] [--max-findings N] [--sort] [--mask-numbers]
               [--ignore-exit] [--with-stderr] [--json]
  diff_fuzz.py --self-test

Exit: 0 = no new (unledgered) divergence; 1 = at least one finding; 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "differential"))
import diff_run as D          # noqa: E402  (run_one/compare_one/load_ledger/load_matrix)

# Bytes/tokens chosen to provoke the C-vuln classes a port must fix better than
# the original: format specifiers (CWE-134), NUL/high bytes (truncation, sign),
# path traversal (CWE-22), quoting/escaping, and separators the parser branches
# on. Tie the fuzzer to the threat model, don't flail randomly.
INTERESTING_BYTES = bytes([0x00, 0x01, 0x07, 0x09, 0x0a, 0x0d, 0x1b, 0x20,
                           0x25, 0x22, 0x27, 0x5c, 0x2f, 0x3d, 0x2d, 0x2e,
                           0x30, 0x39, 0x41, 0x7f, 0x80, 0xfe, 0xff])
INTERESTING_TOKENS = [b"%s", b"%n", b"%d", b"%x", b"../", b"..\\", b"\x00",
                      b"=", b"\n", b"\r\n", b"AAAAAAAA", b"-1", b"2147483648",
                      b"4294967296", b"\x1b[31m", b"# ", b'""']


def _mutate(data: bytes, rng: random.Random) -> bytes:
    """Apply one random mutation. Bounded output growth keeps runs fast."""
    b = bytearray(data)
    op = rng.randrange(8)
    if op == 0 and b:                       # flip one bit
        i = rng.randrange(len(b)); b[i] ^= 1 << rng.randrange(8)
    elif op == 1 and b:                     # set an interesting byte
        b[rng.randrange(len(b))] = rng.choice(INTERESTING_BYTES)
    elif op == 2:                           # insert an interesting byte
        b.insert(rng.randrange(len(b) + 1), rng.choice(INTERESTING_BYTES))
    elif op == 3:                           # insert an interesting token
        tok = rng.choice(INTERESTING_TOKENS)
        pos = rng.randrange(len(b) + 1); b[pos:pos] = tok
    elif op == 4 and len(b) > 1:            # delete a chunk
        i = rng.randrange(len(b)); n = rng.randrange(1, min(8, len(b) - i) + 1)
        del b[i:i + n]
    elif op == 5 and b:                     # duplicate a chunk
        i = rng.randrange(len(b)); n = rng.randrange(1, min(8, len(b) - i) + 1)
        b[i:i] = bytes(b[i:i + n])
    elif op == 6:                           # append repeated byte (length stress)
        b += bytes([rng.choice(INTERESTING_BYTES)]) * rng.choice([4, 16, 64])
    else:                                   # overwrite a token in place
        if b:
            tok = rng.choice(INTERESTING_TOKENS); i = rng.randrange(len(b))
            b[i:i + len(tok)] = tok
    return bytes(b)


def _splice(a: bytes, c: bytes, rng: random.Random) -> bytes:
    if not a or not c:
        return a or c
    return a[: rng.randrange(len(a) + 1)] + c[rng.randrange(len(c) + 1):]


# Values an option is given in argv mode: empty and lone separators, list
# shapes with an empty item, a lone negation prefix, numbers at the edges of
# 32 and 64 bits, a format specifier, an escape sequence. `/` and `..` are
# left out on purpose: a tree-walking option given either walks a whole disk.
INTERESTING_VALUES = ["", ",", "^", "-", "--", "0", "1", "-1", "2147483648",
                      "4294967296", "x", "a,b", ",x", "x,", "x,,y", " ", ".",
                      "/nonexistent", "%s", "\x1b[31m"]


def load_argv_alphabet(path, exclude="", values=()):
    """The option alphabet for argv mode, from a coverage-gate feature
    inventory: its single-letter `options`, less `exclude`, and which of them
    `takes_value`. One with no letter left is an error, not an empty alphabet:
    a fuzzer over nothing reports nothing, and that reads as a pass."""
    import tomllib
    with open(path, "rb") as fh:
        feats = tomllib.load(fh).get("features", {})
    letters = [o for o in feats.get("options", [])
               if isinstance(o, str) and len(o) == 1 and o not in exclude]
    if not letters:
        raise ValueError(f"{path}: no option letters to fuzz")
    takes = {o for o in feats.get("takes_value", []) if o in letters}
    return {"letters": letters, "takes_value": takes,
            "values": INTERESTING_VALUES + list(values)}


def _option_words(alpha, rng):
    """One option, as getopt offers it: `-x` or `+x`, a cluster, and a value
    attached (`-pVAL`) or in the next word (`-p VAL`)."""
    pre = rng.choice("-+")
    k = rng.choice(alpha["letters"])
    if k not in alpha["takes_value"] and rng.random() < 0.3:
        k += rng.choice(alpha["letters"])
    if k[-1] in alpha["takes_value"] or rng.random() < 0.1:
        v = rng.choice(alpha["values"])
        return [pre + k + v] if rng.random() < 0.5 else [pre + k, v]
    return [pre + k]


def _gen_argv(alpha, rng, max_words=4):
    """Options first, then at most one operand: the order getopt reads, so a
    finding is about what an option means, not about where a parser stops."""
    words = []
    for _ in range(rng.randint(1, max_words)):
        words += _option_words(alpha, rng)
    if rng.random() < 0.2:
        words.append(rng.choice(alpha["values"]))
    return tuple(words)


def _mutate_argv(argv, alpha, rng, max_words=4):
    w = list(argv)
    op = rng.randrange(6)
    if op == 0 or not w:                    # insert an option
        i = rng.randrange(len(w) + 1)
        w[i:i] = _option_words(alpha, rng)
    elif op == 1 and len(w) > 1:            # drop a word
        del w[rng.randrange(len(w))]
    elif op == 2:                           # give a word another value
        i = rng.randrange(len(w))
        w[i] = (w[i][:2] if w[i][:1] in ("-", "+") else "") + rng.choice(alpha["values"])
    elif op == 3:                           # flip a word's prefix
        i = rng.randrange(len(w))
        if w[i][:1] in ("-", "+"):
            w[i] = ("+" if w[i][0] == "-" else "-") + w[i][1:]
    elif op == 4:                           # say a word twice
        i = rng.randrange(len(w))
        w.insert(i, w[i])
    else:                                   # start again
        w = list(_gen_argv(alpha, rng, max_words))
    return tuple(w)


def _seeds(seed_files, matrix_path):
    """Assemble the seed corpus: explicit files, plus every `stdin` in a matrix,
    plus built-in defaults so an empty corpus still fuzzes something."""
    seeds = []
    for f in seed_files or []:
        with open(f, "rb") as fh:
            seeds.append(fh.read())
    if matrix_path:
        # allow_empty: a matrix with no cases is a legitimate (empty) seed set for
        # the fuzzer, unlike a differential where 0 cases is a misconfiguration.
        for case in D.load_matrix(matrix_path, allow_empty=True):
            # `stdin_bytes` first: load_matrix resolves a case's `stdin_b64` into
            # it, and those are exactly the seeds a UTF-8 string cannot spell.
            # Dropping them would silently narrow the corpus for the modes that
            # most need raw bytes.
            b = case.get("stdin_bytes")
            if isinstance(b, (bytes, bytearray)) and b:
                seeds.append(bytes(b))
                continue
            s = case.get("stdin")
            if isinstance(s, str) and s:
                seeds.append(s.encode())
    seeds.extend([b"", b"key = value\n", b"# comment\n"])
    # de-dup, keep order
    seen, out = set(), []
    for s in seeds:
        if s not in seen:
            seen.add(s); out.append(s)
    return out


def _case_for(data, args, timeout):
    if isinstance(data, tuple):
        # argv mode: the fuzzed words follow the fixed ones; stdin is empty.
        return {"name": "fuzz", "args": list(args) + list(data),
                "stdin_bytes": b"", "timeout": timeout}
    # Feed the EXACT fuzz bytes via stdin_bytes — run_one writes them verbatim.
    # (The old latin-1-decode-then-run_one-utf-8-encode round-trip silently
    # mangled every 0x80-0xFF byte, so the fuzzer never actually exercised the
    # high/invalid-byte inputs its threat model targets. LESSONS #036, #037.)
    return {"name": "fuzz", "args": list(args),
            "stdin_bytes": data, "timeout": timeout}


def _is_finding(verdict):
    return verdict in ("DIVERGE", "TIMEOUT")


def _judge(data, oracle, rust, args, opts):
    # Pass known={} so compare_one returns a CLEAN verdict/fingerprint: all fuzz
    # inputs share the case name "fuzz", so compare_one's per-name ledger logic
    # doesn't apply here. Fuzz suppression is by fingerprint (below), the only
    # stable key an arbitrary generated input has.
    case = _case_for(data, args, opts["timeout"])
    return D.compare_one("fuzz", oracle, rust, case, {},
                         opts["sort"], opts["mask_numbers"],
                         opts["ignore_exit"], opts["with_stderr"])


def _suppressed(fp_full, known_fps):
    """A fuzz divergence is suppressed iff its fingerprint is pinned in the
    ledger (``- [x] `fuzz:<desc>` [sha256:<hex>]: <why>``). Prefix match so a short
    pin locks a full fingerprint — same rule diff_run uses (LESSONS #043)."""
    return any(fp_full.startswith(p) for p in known_fps)


def _minimize(data, oracle, rust, args, opts, budget):
    """Shrink `data` while it keeps DIVERGING (a finding), via delta-debugging
    with shrinking chunk sizes. The reported fingerprint is recomputed from the
    minimized input, so the smallest reproducer IS the bucket key: many inputs
    that trigger the same divergence collapse onto one minimal form, which is
    what dedup and the ledger pin then match on."""
    best = data
    steps = 0
    chunk = max(1, len(best) // 2)
    while chunk >= 1 and steps < budget:
        i = 0
        shrunk = False
        while i < len(best) and steps < budget:
            cand = best[:i] + best[i + chunk:]
            steps += 1
            if cand != best and _is_finding(
                    _judge(cand, oracle, rust, args, opts)["verdict"]):
                best = cand; shrunk = True
                continue  # same i; best is shorter now
            i += chunk
        if not shrunk:
            chunk //= 2
    return best, steps


def fuzz(oracle, rust, opts):
    rng = random.Random(opts["seed"])
    known_fps = {fp for fp in D.load_ledger(opts["ledger"]).values() if fp}
    alpha = opts.get("argv")
    words = opts.get("argv_words", 4)
    corpus = ([_gen_argv(alpha, rng, words) for _ in range(8)] if alpha
              else _seeds(opts["seed_files"], opts["matrix"]))
    findings = []        # unique by minimized-input fingerprint
    seen_fp = set()
    suppressed = 0
    iters = 0
    start = time.time()

    def budget_left():
        if opts["max_time"] is not None and (time.time() - start) >= opts["max_time"]:
            return False
        if opts["iterations"] is not None and iters >= opts["iterations"]:
            return False
        return True

    while budget_left() and len(findings) < opts["max_findings"]:
        iters += 1
        data = rng.choice(corpus)
        for _ in range(rng.randint(1, 4)):
            data = _mutate_argv(data, alpha, rng, words) if alpha else _mutate(data, rng)
        if rng.random() < 0.15:
            data = _splice(data, rng.choice(corpus), rng)

        if not _is_finding(_judge(data, oracle, rust, opts["args"], opts)["verdict"]):
            continue
        # Found a raw divergence — minimize, then bucket/suppress on the
        # minimized form's fingerprint (its smallest reproducer).
        mini, msteps = _minimize(data, oracle, rust, opts["args"], opts,
                                 opts["minimize_budget"])
        res = _judge(mini, oracle, rust, opts["args"], opts)
        fp = res["fingerprint_full"]
        if _suppressed(fp, known_fps):
            suppressed += 1
            continue
        if fp in seen_fp:
            corpus.append(mini)  # keep exploring near an interesting input
            continue
        seen_fp.add(fp)
        rec = {"fingerprint": fp[:12], "verdict": res["verdict"],
               "iteration": iters, "input_len": len(mini),
               "input_repr": repr(mini), "minimize_steps": msteps,
               "diff": res["diff"]}
        if opts["findings_dir"]:
            os.makedirs(opts["findings_dir"], exist_ok=True)
            # Filename is the hex fingerprint — no attacker-controlled bytes in
            # the path (the harness assumes a hostile host).
            stem = os.path.join(opts["findings_dir"], fp[:12])
            if alpha:
                with open(stem + ".argv", "w", encoding="utf-8") as fh:
                    json.dump(list(mini), fh)
                rec["saved"] = stem + ".argv"
            else:
                with open(stem + ".input", "wb") as fh:
                    fh.write(mini)
                rec["saved"] = stem + ".input"
            with open(stem + ".diff", "w", encoding="utf-8") as fh:
                fh.write(res["diff"] or "")
        findings.append(rec)

    return {"iterations": iters, "elapsed_s": round(time.time() - start, 3),
            "findings": findings, "suppressed_ledgered": suppressed,
            "seeds": len(corpus)}


def _report(summary, as_json):
    if as_json:
        print(json.dumps(dict(summary, provenance=D.provenance_stamp("diff_fuzz")),
                         indent=2))
        return
    for f in summary["findings"]:
        print(f"[{f['verdict']:8}] fp={f['fingerprint']}  "
              f"found@iter {f['iteration']}  min_len={f['input_len']}  "
              f"input={f['input_repr']}")
        if f.get("saved"):
            print(f"           saved: {f['saved']}")
        if f["diff"]:
            for line in f["diff"].splitlines()[:12]:
                print("           " + line)
    n = len(summary["findings"])
    print(f"\n{summary['iterations']} iterations, {summary['seeds']} seeds, "
          f"{n} distinct finding(s), {summary['suppressed_ledgered']} ledgered-suppressed "
          f"({summary['elapsed_s']}s)")
    if n:
        print("Triage each: fix the Rust, OR — if the C is the buggy one — pin the "
              "intentional divergence in the ledger as\n"
              "  - [x] `fuzz:<desc>` [sha256:<fingerprint>]: <why + CWE>\n"
              "(quote the name: unquoted, every fuzz entry is named `fuzz`, and "
              "the second one stops the run)")


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        # Oracle echoes stdin bytes verbatim. "Rust" echoes them too, EXCEPT it
        # diverges whenever the input contains a '%' — a stand-in for a
        # format-string divergence and the ONLY divergence between them (Python,
        # not shell: `$(cat)` would strip NULs/newlines and manufacture extra
        # divergence classes). A correct differential fuzzer must (a) find it,
        # (b) minimize it to the single triggering byte, (c) return exit 1, and
        # (d) go silent once the divergence is ledger-pinned.
        oracle = os.path.join(d, "oracle.py")
        open(oracle, "w").write(
            "#!/usr/bin/env python3\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n")
        os.chmod(oracle, 0o755)
        rust = os.path.join(d, "rust.py")
        open(rust, "w").write(
            "#!/usr/bin/env python3\nimport sys\n"
            "d = sys.stdin.buffer.read()\n"
            "sys.stdout.buffer.write(b'DIVERGED\\n' if b'%' in d else d)\n")
        os.chmod(rust, 0o755)

        # Budgets kept small: check-kit must stay fast. Fixed seed → the
        # outcomes below are deterministic, not "usually".
        base_opts = dict(seed=0, iterations=80, max_time=None, args=[],
                         seed_files=None, matrix=None, ledger=None,
                         findings_dir=None, timeout=5, max_findings=1,
                         sort=False, mask_numbers=False, ignore_exit=False,
                         with_stderr=False, minimize_budget=60)

        clean = dict(base_opts); clean["max_findings"] = 5
        summary = fuzz(oracle, oracle, clean)
        check("oracle vs itself → zero findings (no false positives)",
              len(summary["findings"]) == 0)

        summary = fuzz(oracle, rust, dict(base_opts))
        check("finds the format-string divergence", len(summary["findings"]) >= 1)
        # Guard the [0] access so a zero-findings run FAILS these checks instead of
        # crashing the self-test: red must come from a FAILED CHECK, not from a
        # Traceback — crash-red is indistinguishable from harness-broken-red, so
        # a mutation sweep cannot tell a killed mutant from a broken harness.
        # (The gate-mutation sweep depends on exactly that: this guard is what
        # makes this file legible to it.)
        first = summary["findings"][0] if summary["findings"] else {}
        check("minimizes to the single triggering byte '%'",
              first.get("input_repr") == repr(b"%"))
        fp = first.get("fingerprint")

        # deterministic: same seed → identical finding
        s2 = fuzz(oracle, rust, dict(base_opts))
        check("same seed reproduces the same finding",
              [f["fingerprint"] for f in s2["findings"]] ==
              [f["fingerprint"] for f in summary["findings"]])

        # ledger pin suppresses the whole class (reuses LESSONS #043 fingerprints):
        # every '%' input minimizes to "%", so one pin covers them all.
        led = os.path.join(d, "DIVERGENCES.md")
        # Two entries, in the quoted form the triage text prints: unquoted, both
        # would be named `fuzz` and the second would stop load_ledger (LESSONS #080).
        open(led, "w").write(f"- [x] `fuzz:pct` [sha256:{fp}]: intentional; C format bug\n"
                             "- [x] `fuzz:other` [sha256:0123456789ab]: another finding\n")
        opts_l = dict(base_opts); opts_l["ledger"] = led; opts_l["max_findings"] = 5
        summary = fuzz(oracle, rust, opts_l)
        check("ledger-pinned divergence is suppressed",
              len(summary["findings"]) == 0 and summary["suppressed_ledgered"] >= 1)

        # findings are written as committable reproducers
        fdir = os.path.join(d, "findings")
        opts_f = dict(base_opts); opts_f["findings_dir"] = fdir
        summary = fuzz(oracle, rust, opts_f)
        # guarded like `first` above: zero findings must FAIL, not crash
        saved = (summary["findings"][0].get("saved", "")
                 if summary["findings"] else "")
        check("saves a reproducer input file", bool(saved) and os.path.exists(saved))
        check("saved reproducer actually re-triggers the divergence",
              bool(saved) and _is_finding(
                  _judge(open(saved, "rb").read(), oracle, rust, [],
                         opts_f)["verdict"]))

        # a rust-side HANG on some input is a finding, not a pass (LESSONS #036).
        # Tight timeout + small minimize budget keep this cheap.
        hang = os.path.join(d, "hang.py")
        open(hang, "w").write(
            "#!/usr/bin/env python3\nimport sys, time\n"
            "d = sys.stdin.buffer.read()\n"
            "time.sleep(5) if b'%' in d else sys.stdout.buffer.write(d)\n")
        os.chmod(hang, 0o755)
        opts_h = dict(base_opts); opts_h["timeout"] = 0.3; opts_h["minimize_budget"] = 12
        summary = fuzz(oracle, hang, opts_h)
        check("a rust-side hang is caught as a TIMEOUT finding",
              any(f["verdict"] == "TIMEOUT" for f in summary["findings"]))

        # Seeding from a matrix must pick up `stdin_b64` cases.
        # These are exactly the seeds a UTF-8 `stdin` string cannot spell, so
        # silently dropping them would narrow the corpus for the modes that most
        # need raw bytes — and nothing else in this file would notice.
        import base64 as _b64
        mpath = os.path.join(d, "seedmatrix.json")
        raw = b"\x80\x00\xfe"
        with open(mpath, "w") as fh:
            json.dump([{"name": "txt", "args": [], "stdin": "plain"},
                       {"name": "bin", "args": [],
                        "stdin_b64": _b64.b64encode(raw).decode()}], fh)
        got = _seeds(None, mpath)
        check("matrix seeding picks up a `stdin_b64` case's raw bytes",
              raw in got and b"plain" in got)

        # ARGV MODE. The oracle prints its arguments; "Rust" prints them too,
        # except that it refuses any `+` word holding the letter q, as a port
        # refuses a spelling getopt accepts. The fuzzer must find that from
        # the inventory alone and shrink it to that one word.
        inv = os.path.join(d, "inventory.toml")
        open(inv, "w").write('[features]\noptions = ["a", "b", "q"]\n'
                             'takes_value = ["b"]\n')
        aoracle = os.path.join(d, "aoracle.py")
        open(aoracle, "w").write(
            "#!/usr/bin/env python3\nimport sys\nprint(' '.join(sys.argv[1:]))\n")
        os.chmod(aoracle, 0o755)
        arust = os.path.join(d, "arust.py")
        open(arust, "w").write(
            "#!/usr/bin/env python3\nimport sys\n"
            "bad = [w for w in sys.argv[1:] if w.startswith('+') and 'q' in w]\n"
            "sys.exit('unsupported: ' + bad[0]) if bad else print(' '.join(sys.argv[1:]))\n")
        os.chmod(arust, 0o755)
        alpha = load_argv_alphabet(inv)
        check("argv alphabet: the inventory's letters, and which take a value",
              alpha["letters"] == ["a", "b", "q"] and alpha["takes_value"] == {"b"})
        argv_opts = dict(base_opts, argv=alpha, max_findings=5)
        summary = fuzz(aoracle, aoracle, argv_opts)
        check("argv mode: oracle vs itself → zero findings", len(summary["findings"]) == 0)
        afdir = os.path.join(d, "afindings")
        summary = fuzz(aoracle, arust, dict(argv_opts, max_findings=1, findings_dir=afdir))
        first = summary["findings"][0] if summary["findings"] else {}
        word = first.get("input_repr", "")
        check("argv mode finds the refused spelling, shrunk to the one word",
              word.startswith("('+") and "q" in word and word.endswith("',)"))
        saved = first.get("saved", "")
        check("argv mode saves the words as a reproducer that re-triggers",
              saved.endswith(".argv") and _is_finding(_judge(
                  tuple(json.load(open(saved))), aoracle, arust, [], argv_opts)["verdict"]))
        empty = os.path.join(d, "empty.toml")
        open(empty, "w").write('[features]\noptions = ["q"]\n')
        check("an alphabet with every letter excluded is an error, not a clean run",
              main(["--oracle", aoracle, "--rust", arust, "--argv-inventory", empty,
                    "--argv-exclude", "q"]) == 2)
        check("argv mode refuses stdin seeds rather than ignoring them",
              main(["--oracle", aoracle, "--rust", arust, "--argv-inventory", inv,
                    "--seed-file", inv]) == 2)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="C reference binary (a live one: a golden replay cannot answer a generated input)")
    ap.add_argument("--rust", help="Rust binary under test")
    ap.add_argument("--seed", type=int, default=0, help="PRNG seed (reproducible runs)")
    ap.add_argument("--iterations", type=int, default=None, help="max inputs to try (1000 when no --max-time is given)")
    ap.add_argument("--max-time", type=float, default=None, help="wall-clock budget (s); stops with --iterations, whichever first")
    ap.add_argument("--args", nargs="*", default=[], help="fixed argv passed to both binaries")
    ap.add_argument("--seed-file", nargs="*", dest="seed_files", default=[], help="seed corpus files")
    ap.add_argument("--matrix", help="also seed the corpus from a matrix's stdin fields")
    ap.add_argument("--ledger", default="DIVERGENCES.md", help="known-intentional-divergence ledger")
    ap.add_argument("--findings-dir", help="write <fp>.input / <fp>.diff reproducers here")
    ap.add_argument("--timeout", type=float, default=10, help="per-run timeout (s); a rust hang is a finding")
    ap.add_argument("--max-findings", type=int, default=25, help="stop after this many distinct findings")
    ap.add_argument("--minimize-budget", type=int, default=200, help="max shrink steps per finding")
    ap.add_argument("--sort", action="store_true")
    ap.add_argument("--mask-numbers", action="store_true")
    ap.add_argument("--ignore-exit", action="store_true")
    ap.add_argument("--with-stderr", action="store_true")
    ap.add_argument("--argv-inventory", help="fuzz argv, not stdin: options from this coverage-gate inventory")
    ap.add_argument("--argv-exclude", default="", help="option letters argv mode never uses")
    ap.add_argument("--argv-value", action="append", default=[], help="a value argv mode may give an option (repeatable)")
    ap.add_argument("--argv-words", type=int, default=4, help="most options in one generated vector")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust):
        ap.print_usage(sys.stderr)
        print("error: --oracle and --rust are required (or --self-test)", file=sys.stderr)
        return 2
    # --max-time alone runs until the time is up: a default iteration count
    # used to stop every timed run at 1000 inputs, whatever time it was given.
    if args.max_time is None and args.iterations is None:
        args.iterations = 1000
    if (args.iterations is not None and args.iterations <= 0) or \
            (args.max_time is not None and args.max_time <= 0):
        print("error: a zero budget fuzzes nothing, and would report clean", file=sys.stderr)
        return 2

    alpha = None
    if args.argv_inventory:
        # Seeds are stdin bytes; argv mode makes its own vectors. Taking both
        # would silently ignore one of them.
        if args.seed_files or args.matrix:
            print("error: --argv-inventory fuzzes argv; --seed-file and --matrix "
                  "seed stdin and cannot be combined with it", file=sys.stderr)
            return 2
        try:
            alpha = load_argv_alphabet(args.argv_inventory, args.argv_exclude, args.argv_value)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    opts = dict(seed=args.seed, iterations=args.iterations, max_time=args.max_time,
                args=args.args, seed_files=args.seed_files, matrix=args.matrix,
                ledger=args.ledger, findings_dir=args.findings_dir, timeout=args.timeout,
                max_findings=args.max_findings, minimize_budget=args.minimize_budget,
                sort=args.sort, mask_numbers=args.mask_numbers,
                ignore_exit=args.ignore_exit, with_stderr=args.with_stderr,
                argv=alpha, argv_words=args.argv_words)
    summary = fuzz(args.oracle, args.rust, opts)
    _report(summary, args.json)
    return 1 if summary["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
