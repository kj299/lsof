#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Local: #070.
# Re-cited: #1->#001, #4->#004, #6->#036, #8->#043, #9->#044, #11->#045,
#          #14->#037, #16->#050, #48->#069, #50->#071; #36 by title (no
#          entry in this log).
"""Differential harness — run the C oracle and the Rust rewrite over the same
input matrix, normalize both, and diff. Divergences are *triaged*, not blindly
failed: the C may itself be buggy (the prime directive), so a difference is a
question — "Rust bug, or intentional fix of a C defect?" — and the intentional
ones live in a ledger (DIVERGENCES.md) that suppresses them on future runs.

Two comparison modes:
  * same-binary-both-platforms: --oracle and --rust are real binaries.
  * oracle-substitution: when the reference can't run here, point --oracle at a
    wrapper that emits the captured golden output (see harnesses/golden) — and
    exits with the captured `<case>.rc` code, so exit-code fidelity survives
    the substitution.

Timeouts are failures, not behavior (the liveness backstop, LESSONS #001): a case
where the RUST side exceeds its timeout gets the verdict TIMEOUT — never MATCH,
and the ledger cannot excuse it (two hangs matching each other is not fidelity).
An oracle-only timeout is an ordinary DIVERGE to triage: "C hangs on this input,
Rust errors cleanly" is a legitimate ledgered fix-of-C-defect.

Matrix (TOML or JSON): a list of cases, each with a name and argv, e.g.

  [[case]]
  name = "listen-sockets"
  args = ["-nP", "-iTCP"]
  # optional: stdin = "...", env = {FOO="bar"}, timeout = 10,
  #           keep_whitespace = true

Output is normalized before it is compared: masking rules, and runs of blanks
collapsed with trailing ones stripped. That collapse is what lets content be
compared at all across two formatters, and it makes LAYOUT invisible — a column
right-aligned in one program and left-aligned in the other normalizes to the
same line. `keep_whitespace = true` compares that case's output with its
spacing intact, for a case whose point is alignment (LESSONS #070).

Give stdin as `stdin` (UTF-8 text) or `stdin_b64` (raw bytes), never both. Use
`stdin_b64` for any input a JSON/TOML string cannot spell — a lone 0x80-0xFF
byte, an embedded NUL — so a fuzz finding on such an input can be PINNED as a
matrix case. (That gap — a fixed matrix that cannot spell what the fuzzer
generates — is the source lineage's lesson "The differential can only compare
where the C has an answer"; it has no entry in this log, so it is named, not
numbered.)

Ledger entries come in two strengths. `- [x] <case>: <why>` suppresses by case
name alone (legacy). `- [x] <case> [sha256:<12-hex>]: <why>` pins the entry to
ONE accepted divergence — the tool prints the fingerprint to pin, and if the
case's divergence ever changes shape (a NEW regression arriving in a ledgered
case), the pin no longer matches and the case fails again. Pin your entries.

The verdict covers stdout AND exit code by default; stderr is compared too when
--with-stderr is given (error text is behavior for a CLI, but many tools put
nondeterministic noise there — opt in per port).

Usage:
  diff_run.py --oracle PATH --rust PATH --matrix FILE [--ledger DIVERGENCES.md]
              [--sort] [--mask-numbers] [--ignore-exit] [--with-stderr]
              [--rules FILE] [--json]
  diff_run.py --self-test

Exit: 0 = all match or all divergences are ledgered; 1 = unexplained divergence,
any TIMEOUT, or a LEDGER-STALE case (a ledgered divergence that stopped occurring
— a ledger ASSERTS a divergence, it does not license a silent MATCH).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import difflib
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import normalize as N  # noqa: E402


def _validate_matrix(cases):
    """Case names become file names (golden corpus: <name>.golden) and report
    labels; a separator or '..' would escape the corpus directory. The test
    harness is software with a hostile host — reject, don't sanitize.

    Also resolves `stdin_b64` into `stdin_bytes` so every consumer of a matrix
    (this tool's runner AND diff_fuzz's seed corpus) gets raw bytes for free.

    Why: a matrix case could only spell its stdin as a JSON/TOML string,
    which the runner UTF-8 encodes — so the fixed matrix could not express an
    input the FUZZER generates constantly (any byte 0x80-0xFF outside a valid
    UTF-8 sequence). That is a hole in "fix-forward, then immediately pin the
    regression test": a fuzz finding on such an input had nowhere to be pinned.
    `stdin_b64` is the same escape hatch probe.py already had."""
    for case in cases:
        name = case.get("name")
        if not name or not isinstance(name, str):
            sys.exit("error: every matrix case needs a non-empty string `name`")
        if re.search(r"[/\\]", name) or name in (".", ".."):
            sys.exit(f"error: case name {name!r} contains a path separator / traversal "
                     "(names become corpus file names)")
        # A misspelt value must not quietly mean "collapse": `"yes"` and `1`
        # are refused, so a layout case cannot pass on a typo.
        if "keep_whitespace" in case and not isinstance(case["keep_whitespace"], bool):
            sys.exit(f"error: case {name!r} has a non-boolean `keep_whitespace`")
        if "stdin_b64" in case:
            if case.get("stdin"):
                sys.exit(f"error: case {name!r} sets both `stdin` and `stdin_b64` — "
                         "give exactly one (they would silently disagree)")
            try:
                case["stdin_bytes"] = base64.b64decode(case["stdin_b64"], validate=True)
            except (ValueError, binascii.Error) as exc:
                sys.exit(f"error: case {name!r} has an undecodable `stdin_b64`: {exc}")
    return cases


def load_matrix(path, allow_empty=False):
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        cases = data["case"] if isinstance(data, dict) and "case" in data else data
    else:
        try:
            import tomllib
        except ModuleNotFoundError:
            sys.exit("error: TOML matrix needs Python 3.11+ (tomllib); use a .json matrix instead")
        with open(path, "rb") as f:
            data = tomllib.load(f)
        cases = data.get("case", data if isinstance(data, list) else [])
    # A differential over ZERO cases is a misconfiguration (a mis-keyed matrix —
    # `[[cases]]` for `[[case]]` — an empty file, or a glob that matched nothing),
    # not a pass: it would report "0 cases, 0 divergences" and exit 0 over a
    # totally wrong binary. Refuse it (LESSONS #036, gates fail closed). The fuzzer
    # legitimately seeds from an empty matrix, so it opts in with allow_empty.
    if not cases and not allow_empty:
        sys.exit(f"error: matrix {path!r} loaded 0 cases — empty, mis-keyed "
                 "(expected `[[case]]` / a top-level list or {\"case\": [...]}), or a "
                 "glob that matched nothing. A differential over 0 cases cannot pass.")
    return _validate_matrix(cases)


_FP_RE = re.compile(r"\[sha256:([0-9a-fA-F]{6,64})\]")
# A backtick-quoted ledger case name, so a name containing ':' survives parsing.
_QUOTED_NAME_RE = re.compile(r"^`([^`]+)`")


def provenance_stamp(harness):
    """Run-provenance stamp for --json reports: which harness, when, and at what
    git commit. It exists so a STALE report (generated before the code changed)
    or a hand-authored shape-valid one cannot advance a gate silently — in the
    source lineage `progress.py ingest` verifies the stamp against the tree it
    runs in (that lineage's kit audit, §6 item 8).

    NOT A CONTROL HERE YET: this kit's `progress.py ingest` reads only
    `audit_unsafe.py` reports and checks no provenance, so the stamp is a record,
    not a gate. Wiring it is a later stage of the kit refresh; until then do not
    cite it as one. `git_sha` is None outside a git checkout."""
    import datetime
    import subprocess
    try:
        p = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
                           text=True, timeout=10)
        sha = p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else None
    except (OSError, subprocess.SubprocessError):
        sha = None
    return {"harness": harness,
            "generated_at": datetime.datetime.now(datetime.timezone.utc)
                            .isoformat(timespec="seconds"),
            "git_sha": sha}


def load_ledger(path):
    """Known-intentional divergences as {case-name: fingerprint-or-None}. The
    ledger is human-readable Markdown; we harvest `- [x] case-name: reason`
    lines and, when present, a pinned fingerprint of the accepted diff:
    `- [x] case-name [sha256:abcdef123456]: reason`. A pinned entry suppresses
    only that exact divergence; an unpinned one suppresses by name alone
    (legacy) — pin them, or a new regression can hide behind an old acceptance.

    The name ends at the first `:`, so a case whose OWN name contains a colon
    (`parse:header`) would truncate to `parse` — quietly suppressing a divergence
    in the wrong case. Two guards (the source lineage's kit audit, §6 item 4):
      * backtick-quote the name to include colons verbatim —
        ``- [x] `parse:header` [sha256:..]: why``;
      * a name harvested twice is a hard error, never a silent overwrite. That is
        both the genuine-duplicate case (one entry would be dead, and the later
        pin would silently win over the earlier) and the collision that
        truncation causes (`parse:header` + `parse:footer` → both `parse`)."""
    known = {}
    if path and os.path.exists(path):
        in_fence = False
        for lineno, line in enumerate(open(path, encoding="utf-8"), 1):
            s = line.strip()
            # Lines inside a ``` fence are FORMAT DOCUMENTATION, not entries. The
            # shipped skeleton/DIVERGENCES.md shows the format in a fenced block
            # using `- [x]` — harvested literally, that gave a port three bogus
            # by-name suppressions (`fuzz` among them) the moment it copied the
            # template: a template failing the gate it ships (LESSONS #044).
            if s.startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            if s.startswith(("- [x]", "* [x]")):
                body = s[5:].strip()
                m = _FP_RE.search(body)
                fp = m.group(1).lower() if m else None
                if m:  # remove the pin before splitting on ':' (the pin has one)
                    body = (body[: m.start()] + body[m.end():]).strip()
                q = _QUOTED_NAME_RE.match(body)
                name = q.group(1).strip() if q else body.split(":", 1)[0].strip().strip("`")
                if not name:
                    continue
                if name in known:
                    sys.exit(
                        f"error: ledger {path!r}:{lineno}: case {name!r} is already "
                        f"ledgered — a duplicate entry means one of them is dead, and "
                        f"the later pin would silently override the earlier. If two "
                        f"cases only differ after a ':' they collapse to the same name "
                        f"here; backtick-quote the full name to keep it "
                        f"(`- [x] `case:with:colons`: why`). Remove or rename one.")
                known[name] = fp
    return known


def run_one(binary, case, default_timeout=15):
    """Run one case; returns (stdout, returncode, timed_out, stderr). On
    timeout the output is the <<TIMEOUT>> sentinel and rc 124 — callers must
    treat timed_out=True as a failed run, never as comparable behavior: two
    sides that both hang produce identical sentinels, and comparing those as if
    they were output would pass the exact hang class this harness exists to
    catch."""
    argv = [binary] + [str(a) for a in case.get("args", [])]
    env = dict(os.environ)
    env.update({k: str(v) for k, v in case.get("env", {}).items()})
    # `stdin_bytes` (raw bytes) feeds the child EXACTLY those bytes — the fuzzer
    # uses it so 0x80-0xFF reach the program verbatim; a plain `stdin` str is
    # utf-8 encoded. (Before this, the fuzzer latin-1-decoded its bytes and
    # run_one re-encoded utf-8, silently mangling every high byte — LESSONS #036:
    # a fuzzer that can't feed the bytes it claims is a coverage hole.)
    sb = case.get("stdin_bytes")
    has_stdin = sb is not None or bool(case.get("stdin"))
    inp = sb if sb is not None else (case["stdin"].encode("utf-8") if case.get("stdin") else None)
    # When a case gives no stdin, feed the child DEVNULL — NOT the parent's
    # inherited stdin. A binary that reads stdin (the skeleton `port` does)
    # would otherwise block forever on an interactive/tty parent, turning a
    # differential/perf run into a hang that depends on who launched it. A test
    # harness must be hermetic (the hostile-host rule, LESSONS #045); EOF is
    # deterministic.
    try:
        p = subprocess.run(
            argv,
            input=inp,
            stdin=None if has_stdin else subprocess.DEVNULL,
            capture_output=True,
            timeout=case.get("timeout", default_timeout),
            env=env,
        )
        # `backslashreplace`, NOT `replace`: `replace` maps EVERY invalid byte to
        # the same U+FFFD, so a C tool emitting 0xFF and a Rust tool emitting 0xFE
        # decode identically and compare as MATCH — a binary-output divergence
        # invisible to the whole differential (LESSONS #036). backslashreplace keeps
        # distinct bytes distinct (\xff vs \xfe) and stays printable/hashable/JSON-safe.
        return (p.stdout.decode("utf-8", "backslashreplace"), p.returncode, False,
                p.stderr.decode("utf-8", "backslashreplace"))
    except subprocess.TimeoutExpired:
        return "<<TIMEOUT>>\n", 124, True, ""
    except FileNotFoundError:
        sys.exit(f"error: binary not found: {binary}")


def compare_one(name, oracle_bin, rust_bin, case, known, sort, mask_numbers,
                ignore_exit=False, with_stderr=False, rules=None):
    """Run one case on both binaries and return its verdict dict. This is the
    single source of differential fidelity — the matrix runner (`compare`) and
    the differential FUZZER (`diff-fuzz/diff_fuzz.py`) both call it, so the
    stdout+exit-code rule (LESSONS #004), the fail-closed timeout handling
    (LESSONS #036) and the ledger fingerprint (LESSONS #043) live in exactly one
    place. `known` is a {name: pin} map from `load_ledger`."""
    o_out, o_rc, o_to, o_err = run_one(oracle_bin, case)
    r_out, r_rc, r_to, r_err = run_one(rust_bin, case)
    # `keep_whitespace`: compare this case's spacing too (see the module doc).
    trim = not case.get("keep_whitespace", False)
    norm = lambda t: N.normalize_text(t, rules=rules if rules is not None else N.DEFAULT_RULES,
                                      sort=sort, strip_blank=True, trim=trim,
                                      mask_numbers=mask_numbers)
    o_n, r_n = norm(o_out), norm(r_out)
    # Fidelity is stdout AND exit code: a rewrite that prints the right thing
    # but returns the wrong status (lsof exits 1 on no-match; scripts branch
    # on it) is NOT a match. Exit-code drift was a real lsof-rs bug.
    # (LESSONS #004). `--ignore-exit` opts out for tools without stable codes.
    # `--with-stderr` opts stderr in (error text is behavior too).
    stdout_match = o_n == r_n
    exit_match = ignore_exit or (o_rc == r_rc)
    o_e, r_e = (norm(o_err), norm(r_err)) if with_stderr else ("", "")
    stderr_match = (not with_stderr) or o_e == r_e
    note = ""
    if o_to or r_to:
        which = "both" if (o_to and r_to) else ("rust" if r_to else "oracle")
        note += f"timed out: {which} (case timeout {case.get('timeout', 15)}s)\n"
    if not exit_match:
        note += f"exit code differs: oracle={o_rc} rust={r_rc}\n"
    body = "" if stdout_match else "".join(difflib.unified_diff(
        o_n.splitlines(keepends=True), r_n.splitlines(keepends=True),
        fromfile=f"oracle:{name}", tofile=f"rust:{name}"))
    if not stderr_match:
        body += "".join(difflib.unified_diff(
            o_e.splitlines(keepends=True), r_e.splitlines(keepends=True),
            fromfile=f"oracle-stderr:{name}", tofile=f"rust-stderr:{name}"))
    # Fingerprint of the observed divergence (over the stable diff text,
    # before any mismatch message is appended) — what a ledger pin locks.
    fp = hashlib.sha256((note + body).encode("utf-8")).hexdigest()
    # A rust-side timeout is TIMEOUT outright: never MATCH (both sides
    # hanging yields identical <<TIMEOUT>> sentinels, which is two hangs,
    # not fidelity) and never ledgered (nothing ran; there is no behavior
    # to accept). Oracle-only timeouts fall through to the normal DIVERGE
    # triage — fixing a C hang is a legitimate ledgered divergence.
    pin = known.get(name) if name in known else None
    is_match = stdout_match and exit_match and stderr_match
    if r_to:
        verdict = "TIMEOUT"
    elif name in known and is_match:
        # A ledger entry ASSERTS a case diverges (an intentional fix-of-C-defect).
        # If a ledgered case now MATCHes the oracle, that assertion is FALSE: the
        # intentional divergence is gone — the fix was likely reverted (the whole
        # point of the port stopped happening) or the C changed too. Silently
        # passing it as MATCH is the exact hole that let the adler32 exit test go
        # green after the overflow fix was reverted. An allow-list must ASSERT the
        # accepted state, not merely SUPPRESS (LESSONS #037). Fails, never passes.
        verdict = "LEDGER-STALE"
        note += (f"ledgered case {name!r} no longer diverges from the oracle — the "
                 f"intentional divergence is GONE (fix reverted, or the C changed "
                 f"too). Re-triage: restore the fix, or remove the ledger entry if "
                 f"the match is now correct. A ledger asserts a divergence; it does "
                 f"not license a silent MATCH.\n")
    elif is_match:
        verdict = "MATCH"
    elif name in known:
        if pin is not None and not fp.startswith(pin):
            verdict = "DIVERGE"
            note += (f"ledgered fingerprint mismatch: accepted [sha256:{pin}], "
                     f"observed [sha256:{fp[:12]}] — the divergence changed; re-triage\n")
        else:
            verdict = "DIVERGE(ledgered)"
    else:
        verdict = "DIVERGE"
    clean = verdict in ("MATCH", "LEDGER-STALE")  # no observed-divergence fingerprint
    return {
        "name": name, "verdict": verdict,
        "oracle_rc": o_rc, "rust_rc": r_rc, "exit_match": exit_match,
        "timed_out": {"oracle": o_to, "rust": r_to},
        "fingerprint": None if clean else fp[:12],
        "fingerprint_full": None if clean else fp,
        "pinned": pin is not None,
        "diff": None if verdict == "MATCH" else (note + body),
    }


def compare(oracle_bin, rust_bin, matrix, ledger, sort, mask_numbers, ignore_exit=False,
            with_stderr=False, rules=None):
    known = load_ledger(ledger)
    return [compare_one(case["name"], oracle_bin, rust_bin, case, known,
                        sort, mask_numbers, ignore_exit, with_stderr, rules)
            for case in matrix]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--oracle", help="path to the C reference binary (or golden-replay wrapper)")
    ap.add_argument("--rust", help="path to the Rust binary under test")
    ap.add_argument("--matrix", help="input matrix (.toml or .json)")
    ap.add_argument("--ledger", default="DIVERGENCES.md", help="known-intentional-divergence ledger")
    ap.add_argument("--sort", action="store_true", help="order-independent compare")
    ap.add_argument("--mask-numbers", action="store_true", help="mask bare numbers (PIDs) too")
    ap.add_argument("--ignore-exit", action="store_true", help="don't treat an exit-code difference as a divergence")
    ap.add_argument("--with-stderr", action="store_true", help="also compare (normalized) stderr")
    ap.add_argument("--rules", help="per-project normalization rules file (.json/.toml); replaces the defaults")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not (args.oracle and args.rust and args.matrix):
        ap.print_usage(sys.stderr)
        print("error: --oracle, --rust and --matrix are required", file=sys.stderr)
        return 2

    rules = N.load_rules(args.rules) if args.rules else None
    results = compare(args.oracle, args.rust, load_matrix(args.matrix),
                      args.ledger, args.sort, args.mask_numbers, args.ignore_exit,
                      args.with_stderr, rules)
    unexplained = [r for r in results if r["verdict"] == "DIVERGE"]
    timeouts = [r for r in results if r["verdict"] == "TIMEOUT"]
    stale = [r for r in results if r["verdict"] == "LEDGER-STALE"]
    if args.json:
        # Wrapped shape {provenance, results} so `progress.py ingest` can verify
        # the report is from THIS tree, not a stale or hand-authored one.
        print(json.dumps({"provenance": provenance_stamp("diff_run"),
                          "results": results}, indent=2))
    else:
        for r in results:
            print(f"[{r['verdict']:18}] {r['name']}")
            if r["verdict"] == "DIVERGE(ledgered)" and not r["pinned"]:
                print(f"    (unpinned ledger entry — pin it as `- [x] {r['name']} "
                      f"[sha256:{r['fingerprint']}]: <why>` so a changed divergence fails again)")
            if r["verdict"] in ("DIVERGE", "TIMEOUT", "LEDGER-STALE") and r["diff"]:
                sys.stdout.write(r["diff"])
        print(f"\n{len(results)} cases, {len(unexplained)} unexplained divergence(s), "
              f"{len(timeouts)} timeout(s), {len(stale)} stale ledger entrie(s)")
        if unexplained:
            print("Triage each: fix the Rust, OR record an intentional fix-of-C-defect in",
                  args.ledger, "as `- [x] <case>: <why>`.")
        if timeouts:
            print("A TIMEOUT is a hard failure (a hang is a design smell — design the "
                  "blocking call out); it cannot be ledgered.")
        if stale:
            print("A LEDGER-STALE case no longer diverges — the fix may be reverted. A "
                  "ledger asserts a divergence; restore the fix or remove the entry.")
    return 1 if (unexplained or timeouts or stale) else 0


def _exits(fn):
    """True if fn() refuses via sys.exit — the fail-closed fixtures' assertion."""
    try:
        fn()
        return False
    except SystemExit:
        return True


def _self_test():
    """Prove the harness detects both a match and an unexplained divergence,
    and that the ledger suppresses a known one — using /bin/echo as both sides."""
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    echo = "/bin/echo" if os.path.exists("/bin/echo") else "echo"
    same = [{"name": "identical", "args": ["hello"]}]
    res = compare(echo, echo, same, ledger=None, sort=False, mask_numbers=False)
    check("identical output → MATCH", res[0]["verdict"] == "MATCH")

    # A case with no stdin must not inherit (and block on) the parent's stdin:
    # a stdin-reading binary gets DEVNULL → EOF → returns, it does not hang.
    cat = "/bin/cat" if os.path.exists("/bin/cat") else "cat"
    res = run_one(cat, {"name": "no-stdin", "args": [], "timeout": 5})
    check("no-stdin case feeds DEVNULL, doesn't hang on inherited stdin",
          res[2] is False and res[0] == "")

    # echo vs printf genuinely diverge on a format-string arg:
    # echo "%s" "hi" → "%s hi"   ;   printf "%s" "hi" → "hi"
    printf = "/usr/bin/printf" if os.path.exists("/usr/bin/printf") else "printf"
    diff_case = [{"name": "diverging", "args": ["%s", "hi"]}]
    res = compare(echo, printf, diff_case, ledger=None, sort=False, mask_numbers=False)
    check("different output → DIVERGE", res[0]["verdict"] == "DIVERGE")
    # The report's shape is read by other tools: diff_fuzz buckets findings by
    # `fingerprint_full`, and the fingerprint hashes note + body, so what goes
    # INTO it decides what a ledger pin accepts. LESSONS #069/#071's decision sweep
    # found each of these unpinned — stdout could drop out of the fingerprint.
    div = res[0]
    ddiff = div["diff"] or ""
    check("a DIVERGE carries its fingerprint, short and full",
          bool(div["fingerprint"] and div["fingerprint_full"]
               and div["fingerprint_full"].startswith(div["fingerprint"])))
    check("a DIVERGE's diff (and so its fingerprint) includes the stdout diff",
          "--- oracle:diverging" in ddiff)
    check("...and no note for a timeout or an exit code that did not happen",
          bool(ddiff) and "timed out" not in ddiff and "exit code differs" not in ddiff)
    ok_res = compare(echo, echo, same, ledger=None, sort=False, mask_numbers=False)[0]
    check("a MATCH carries no fingerprint and no diff",
          ok_res["fingerprint"] is None and ok_res["fingerprint_full"] is None
          and ok_res["diff"] is None)

    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as f:
        f.write("- [x] diverging: printf drops the trailing newline; intentional\n")
        ledger_path = f.name
    res = compare(echo, printf, diff_case, ledger=ledger_path, sort=False, mask_numbers=False)
    check("ledgered divergence → suppressed", res[0]["verdict"] == "DIVERGE(ledgered)")
    check("unpinned ledger entry is reported as such (so it gets pinned)",
          res[0]["pinned"] is False and res[0]["fingerprint"])
    # a PINNED entry accepts exactly the accepted divergence...
    fp = compare(echo, printf, diff_case, ledger=None, sort=False, mask_numbers=False)[0]["fingerprint"]
    open(ledger_path, "w").write(f"- [x] diverging [sha256:{fp}]: printf drops the newline\n")
    res = compare(echo, printf, diff_case, ledger=ledger_path, sort=False, mask_numbers=False)
    check("pinned fingerprint matches → suppressed", res[0]["verdict"] == "DIVERGE(ledgered)")
    check("...and the report says it is pinned", res[0]["pinned"] is True)
    # ...and re-fails when the divergence changes shape (stale pin ≠ observed)
    open(ledger_path, "w").write("- [x] diverging [sha256:000000000000]: stale acceptance\n")
    res = compare(echo, printf, diff_case, ledger=ledger_path, sort=False, mask_numbers=False)
    check("changed divergence breaks the pin → DIVERGE again",
          res[0]["verdict"] == "DIVERGE" and "fingerprint mismatch" in res[0]["diff"])

    # Ledger NAME parsing (the source lineage's kit audit, §6 item 4). The name ends at
    # the first ':', so a colon-bearing case name must be backtick-quotable, and a
    # name harvested twice must be a hard error — never a silent overwrite, which is
    # how a truncation collision would mis-suppress the wrong case.
    open(ledger_path, "w").write("- [x] `parse:header` [sha256:abc123]: colon in the name\n")
    check("a backtick-quoted case name keeps its colons",
          load_ledger(ledger_path) == {"parse:header": "abc123"})
    open(ledger_path, "w").write("- [x] plain: unquoted still splits at the first colon\n")
    check("an unquoted name still parses (back-compat)",
          load_ledger(ledger_path) == {"plain": None})
    open(ledger_path, "w").write("- [x] dup: first\n- [x] dup [sha256:abc123]: second\n")
    check("a duplicate ledger name is a hard error, not a silent overwrite",
          _exits(lambda: load_ledger(ledger_path)))
    # the truncation collision itself: two distinct cases → same harvested name
    open(ledger_path, "w").write("- [x] parse:header: one\n- [x] parse:footer: two\n")
    check("two names colliding via ':' truncation is refused",
          _exits(lambda: load_ledger(ledger_path)))
    # A ``` fenced block documents the FORMAT — its `- [x]` lines are not entries.
    # (The shipped skeleton ledger does exactly this; harvesting them handed every
    # port that copied it three bogus by-name suppressions.)
    open(ledger_path, "w").write(
        "text\n```\n- [x] <case-name> [sha256:<hex>]: format example\n- [x] fuzz:<desc>: example\n```\n"
        "- [x] real: an actual entry outside the fence\n")
    check("`- [x]` lines inside a ``` fence are documentation, not entries",
          load_ledger(ledger_path) == {"real": None})
    os.unlink(ledger_path)

    # `stdin_b64` — raw bytes a JSON/TOML string cannot spell.
    # 0x80 alone is not valid UTF-8, so this seed is unreachable via `stdin`.
    raw = b"\x80\x00\xff"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump([{"name": "b64", "args": [],
                    "stdin_b64": base64.b64encode(raw).decode()}], f)
        mpath = f.name
    loaded = load_matrix(mpath)
    check("`stdin_b64` resolves to the exact raw bytes",
          loaded[0].get("stdin_bytes") == raw)
    # ...and the LOADED case must feed them verbatim, end to end. Run the case
    # object load_matrix produced, not a hand-built one: that is the path a real
    # matrix takes, and it is what would silently drop the bytes.
    catout, _rc, _to, _e = run_one(cat, dict(loaded[0], timeout=5))
    check("a `stdin_b64` case reaches the child verbatim, end to end",
          "\\x80" in catout and "\\xff" in catout)
    with open(mpath, "w") as f:
        json.dump([{"name": "both", "args": [], "stdin": "x", "stdin_b64": "eA=="}], f)
    check("a case with BOTH `stdin` and `stdin_b64` is refused",
          _exits(lambda: load_matrix(mpath)))
    with open(mpath, "w") as f:
        json.dump([{"name": "bad", "args": [], "stdin_b64": "not!base64"}], f)
    check("an undecodable `stdin_b64` is refused, not silently empty",
          _exits(lambda: load_matrix(mpath)))
    os.unlink(mpath)

    # exit-code fidelity: same stdout, different exit status must DIVERGE.
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh"); open(o, "w").write("#!/bin/sh\necho hi\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh"); open(r, "w").write("#!/bin/sh\necho hi\nexit 3\n"); os.chmod(r, 0o755)
        ec = [{"name": "exitcode", "args": []}]
        res = compare(o, r, ec, ledger=None, sort=False, mask_numbers=False)
        check("same stdout + different exit code → DIVERGE", res[0]["verdict"] == "DIVERGE")
        check("divergence note names the exit codes", "exit code differs" in (res[0]["diff"] or ""))
        res = compare(o, r, ec, ledger=None, sort=False, mask_numbers=False, ignore_exit=True)
        check("--ignore-exit suppresses an exit-only divergence → MATCH", res[0]["verdict"] == "MATCH")

    # Timeouts are failures, not fidelity: two hangs produce identical
    # <<TIMEOUT>> sentinels, which must never compare as MATCH, and the ledger
    # must not be able to excuse a hung rewrite.
    with tempfile.TemporaryDirectory() as d:
        slow = os.path.join(d, "slow.sh")
        open(slow, "w").write("#!/bin/sh\nsleep 2\n"); os.chmod(slow, 0o755)
        fast = os.path.join(d, "fast.sh")
        open(fast, "w").write("#!/bin/sh\necho hi\n"); os.chmod(fast, 0o755)
        tc = [{"name": "hang", "args": [], "timeout": 0.4}]
        res = compare(slow, slow, tc, ledger=None, sort=False, mask_numbers=False)
        check("both sides hanging → TIMEOUT, not MATCH", res[0]["verdict"] == "TIMEOUT")
        res = compare(fast, slow, tc, ledger=None, sort=False, mask_numbers=False)
        check("rust-side hang → TIMEOUT", res[0]["verdict"] == "TIMEOUT")
        ledger = os.path.join(d, "ledger.md")
        open(ledger, "w").write("- [x] hang: pretend this is fine\n")
        res = compare(fast, slow, tc, ledger=ledger, sort=False, mask_numbers=False)
        check("ledger cannot excuse a rust-side hang", res[0]["verdict"] == "TIMEOUT")
        res = compare(slow, fast, tc, ledger=None, sort=False, mask_numbers=False)
        check("oracle-only hang → DIVERGE (triaged, ledgerable)", res[0]["verdict"] == "DIVERGE")
        # The note names the side that hung; it is part of the fingerprint an
        # oracle-only hang is ledgered under (unpinned until LESSONS #069/#071's
        # sweep).
        says = lambda o, r: compare(o, r, tc, ledger=None, sort=False,
                                    mask_numbers=False)[0]["diff"] or ""
        check("the timeout note names the side that hung: both",
              "timed out: both" in says(slow, slow))
        check("...rust", "timed out: rust" in says(fast, slow))
        check("...oracle", "timed out: oracle" in says(slow, fast))

    # Whitespace: collapsed by default, which is what makes a layout difference
    # invisible; compared as it stands for a case that sets `keep_whitespace`.
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh")
        open(o, "w").write("#!/bin/sh\nprintf 'a    b\\n'\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh")
        open(r, "w").write("#!/bin/sh\nprintf 'a b \\n'\n"); os.chmod(r, 0o755)
        wc = [{"name": "spacing", "args": []}]
        res = compare(o, r, wc, ledger=None, sort=False, mask_numbers=False)
        check("a spacing-only difference MATCHes by default", res[0]["verdict"] == "MATCH")
        wc = [{"name": "spacing", "args": [], "keep_whitespace": True}]
        res = compare(o, r, wc, ledger=None, sort=False, mask_numbers=False)
        check("`keep_whitespace` makes a spacing-only difference DIVERGE",
              res[0]["verdict"] == "DIVERGE")
        res = compare(o, o, wc, ledger=None, sort=False, mask_numbers=False)
        check("`keep_whitespace` still MATCHes identical output", res[0]["verdict"] == "MATCH")
        check("a non-boolean `keep_whitespace` is refused",
              _exits(lambda: _validate_matrix([{"name": "x", "keep_whitespace": "yes"}])))
        check("a boolean `keep_whitespace` is accepted",
              not _exits(lambda: _validate_matrix([{"name": "x", "keep_whitespace": False}])))

    # stderr: ignored by default (documented), compared with --with-stderr
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh")
        open(o, "w").write("#!/bin/sh\necho hi\necho err-one >&2\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh")
        open(r, "w").write("#!/bin/sh\necho hi\necho err-two >&2\n"); os.chmod(r, 0o755)
        sc = [{"name": "stderr-drift", "args": []}]
        res = compare(o, r, sc, ledger=None, sort=False, mask_numbers=False)
        check("stderr drift ignored by default → MATCH", res[0]["verdict"] == "MATCH")
        res = compare(o, r, sc, ledger=None, sort=False, mask_numbers=False, with_stderr=True)
        check("--with-stderr catches stderr drift → DIVERGE",
              res[0]["verdict"] == "DIVERGE" and "stderr" in (res[0]["diff"] or ""))
        res = compare(o, o, sc, ledger=None, sort=False, mask_numbers=False, with_stderr=True)
        check("--with-stderr on identical stderr → MATCH", res[0]["verdict"] == "MATCH")

    # Case names become corpus file names. Each rejection alone (LESSONS #050):
    # none but the separator was reached until LESSONS #069/#071's decision sweep.
    with tempfile.TemporaryDirectory() as d:
        for label, name in [("an empty name", ""), ("a non-string name", 7),
                            ("`..` as a name", ".."), ("`.` as a name", ".")]:
            bad = os.path.join(d, "n.json")
            open(bad, "w").write(json.dumps([{"name": name, "args": []}]))
            check(f"{label} is refused", _exits(lambda: load_matrix(bad)))
        good = os.path.join(d, "g.json")
        open(good, "w").write('[{"name": "plain", "args": [], "stdin": "x"}]')
        check("a plain case with `stdin` (and no `stdin_b64`) loads",
              [c["name"] for c in load_matrix(good)] == ["plain"])

    # hostile case names must be rejected, not become corpus file paths
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.join(d, "bad.json")
        open(bad, "w").write('[{"name": "../evil", "args": []}]')
        try:
            load_matrix(bad)
            check("path-traversal case name rejected", False)
        except SystemExit:
            check("path-traversal case name rejected", True)
        # An empty / mis-keyed matrix must be REFUSED, not pass over 0 cases
        # (a `[[cases]]`-for-`[[case]]` typo used to exit 0 over a wrong binary).
        empty = os.path.join(d, "empty.json"); open(empty, "w").write("[]")
        try:
            load_matrix(empty)
            check("empty matrix refused (fail closed)", False)
        except SystemExit:
            check("empty matrix refused (fail closed)", True)
        check("empty matrix allowed only when the caller opts in (fuzzer seeds)",
              load_matrix(empty, allow_empty=True) == [])

    # LEDGER-STALE (LESSONS #037): a ledgered case that STOPS diverging must FAIL,
    # not silently MATCH — else a reverted fix hides. echo-vs-echo matches; a
    # ledger entry for it asserts a divergence that isn't there.
    with tempfile.TemporaryDirectory() as d:
        led = os.path.join(d, "led.md")
        open(led, "w").write("- [x] identical: pretend this diverges intentionally\n")
        res = compare(echo, echo, [{"name": "identical", "args": ["hi"]}],
                      ledger=led, sort=False, mask_numbers=False)
        check("a ledgered case that now MATCHes → LEDGER-STALE, not MATCH",
              res[0]["verdict"] == "LEDGER-STALE")
        check("LEDGER-STALE explains the vanished divergence",
              "no longer diverges" in (res[0]["diff"] or ""))

    # binary-stdout fidelity: distinct invalid bytes must NOT collapse to MATCH.
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh"); open(o, "w").write("#!/bin/sh\nprintf '\\377'\n"); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh"); open(r, "w").write("#!/bin/sh\nprintf '\\376'\n"); os.chmod(r, 0o755)
        bc = [{"name": "binbyte", "args": []}]
        res = compare(o, r, bc, ledger=None, sort=False, mask_numbers=False)
        check("0xFF vs 0xFE binary stdout → DIVERGE (not collapsed to U+FFFD MATCH)",
              res[0]["verdict"] == "DIVERGE")

    # stdin_bytes feeds EXACT bytes (the fuzzer's high-byte path, LESSONS #036):
    # a program that echoes stdin gets 0xFE back verbatim, not utf-8-mangled.
    catout, _rc, _to, _e = run_one(cat, {"name": "raw", "args": [], "stdin_bytes": b"\xfe\x00A"})
    check("stdin_bytes reaches the child verbatim (0xFE preserved)", "\\xfe" in catout)

    # per-project rules (--rules): a custom rule masks a project token so an
    # otherwise-diverging pair matches — proving rules thread through compare.
    with tempfile.TemporaryDirectory() as d:
        o = os.path.join(d, "o.sh"); open(o, "w").write('#!/bin/sh\necho "req abc123"\n'); os.chmod(o, 0o755)
        r = os.path.join(d, "r.sh"); open(r, "w").write('#!/bin/sh\necho "req def456"\n'); os.chmod(r, 0o755)
        rc = [{"name": "reqid", "args": []}]
        res = compare(o, r, rc, ledger=None, sort=False, mask_numbers=False)
        check("differing request ids → DIVERGE under default rules", res[0]["verdict"] == "DIVERGE")
        custom = [("reqid", re.compile(r"req [a-z0-9]+"), "req <ID>")]
        res = compare(o, r, rc, ledger=None, sort=False, mask_numbers=False, rules=custom)
        check("a custom --rules entry masks the id → MATCH", res[0]["verdict"] == "MATCH")

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
