#!/usr/bin/env python3
# KIT-IMPORT: from the c2rust-port lineage of this kit.
# Re-cited: #6->#036, #13->#033, #14->#037, #17->#038, #18->#039, #19->#040,
#          #21->#041, #23->#042, #48->#069, #50->#071; #15 by title (no entry
#          in this log).
# Local: #047 (this import's own carried-over members).
"""Probe-then-port harness — the C is a spec only the oracle can read, so the
module's test expectations are GENERATED from an oracle transcript, never
hand-written (LESSONS #038, mechanized; LESSONS #041).

Why: on the cJSON port every substantive first-try mistake came from *reasoning*
about the C instead of running it — a lossy `%1.15g` the C accepts, `Compare`
rejecting a value's own duplicate, minify ignoring escape parity. The gates
caught the wrong code, but only AFTER wrong unit tests had been written to agree
with it. LESSONS #038 made probe-first a convention; conventions decay without a
control (LESSONS #033). This harness is the control:

  probes.json --run--> transcript.json --gen--> probes_gen.rs
   (inputs)            (C's observed            (#[test] fns asserting the
    you write)          bytes, fingerprinted)    OBSERVED bytes, DO-NOT-EDIT)

  * `run`    executes every probe against the C oracle and pins the observed
    (rc, stdout) — byte-faithfully (LESSONS #037) — under a fingerprint.
  * `gen`    turns the transcript into a Rust test file: one `#[test]` per
    probe, expectations taken verbatim from the C's bytes. A hand-written
    expectation that contradicts the C cannot exist in this file, because no
    hand writes it. The port supplies one glue fn (`tests/<glue>/mod.rs`):
        pub fn run_probe(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>)
    mirroring the differential driver's contract (stdout + exit).
  * `verify` fails closed on every way the pin can rot: a tampered transcript
    (fingerprint), probes edited without a re-run (correspondence), the ORACLE
    drifting (every probe is re-run and re-compared), and a hand-edited or
    stale generated file (byte-compare against a fresh regeneration).

Fail-closed (LESSONS #036): zero probes is an error, not a pass (a transcript
that pinned nothing is the 0-of-0 audit again — LESSONS #039); a probe that
hangs the oracle is an error (a hang cannot be pinned); a missing oracle,
transcript, or generated file is an error.

Probes file (JSON):
  {"module": "num-print",
   "probes": [{"id": "dbl-max", "args": ["print-unformatted"],
               "stdin": "1e308", "note": "why this case"},
              {"id": "raw", "args": ["minify"], "stdin_b64": "Ig=="}]}
  `stdin` (UTF-8 text) or `stdin_b64` (raw bytes), exactly one per probe.

Usage:
  probe.py run    --probes P.json --oracle BIN --transcript T.json [--timeout S]
  probe.py gen    --transcript T.json --out GEN.rs [--glue MOD]
  probe.py verify --probes P.json --oracle BIN --transcript T.json \
                  --out GEN.rs [--glue MOD] [--timeout S]
  probe.py --self-test
Exit: 0 = pinned/verified; 1 = drift, tamper, or nothing pinned; 2 = usage.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys

TRANSCRIPT_VERSION = 1
# fields of a transcript entry that carry meaning; previews are cosmetic and
# regenerated, so they stay outside the fingerprint on purpose
SEMANTIC_FIELDS = ("id", "args", "stdin_b64", "note", "rc", "stdout_b64")


def _die(msg):
    print(f"error: {msg}", file=sys.stderr)
    return 1


def _preview(data: bytes, limit=80) -> str:
    """Human-readable, lossy preview (the b64 field is the truth)."""
    s = data.decode("utf-8", errors="backslashreplace")
    return s if len(s) <= limit else s[:limit] + "…"


def _fingerprint(entries) -> str:
    """sha256 over the canonical JSON of every entry's semantic fields.
    This is what makes the transcript a PIN: verify recomputes it, so a
    hand-edited expectation in the transcript fails instead of silently
    redefining the spec."""
    canon = [{k: e[k] for k in SEMANTIC_FIELDS} for e in entries]
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_probes(path):
    """Load + validate the probes file. Returns (module, probes) with each
    probe normalized to {id, args, stdin(bytes), note}. Raises ValueError."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    module = doc.get("module")
    if not isinstance(module, str) or not module:
        raise ValueError("probes file needs a non-empty string `module`")
    raw = doc.get("probes")
    if not isinstance(raw, list) or not raw:
        # a probe run over nothing pins nothing — the 0-of-0 audit again
        # (LESSONS #039): NOTHING-TO-PROBE is a failure, never a pass
        raise ValueError("NOTHING-TO-PROBE: `probes` must be a non-empty list")
    probes, seen = [], set()
    for i, p in enumerate(raw):
        pid = p.get("id")
        if not isinstance(pid, str) or not pid:
            raise ValueError(f"probe [{i}] has no `id`")
        if pid in seen:
            raise ValueError(f"duplicate probe id `{pid}`")
        seen.add(pid)
        args = p.get("args")
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            raise ValueError(f"probe `{pid}`: `args` must be a list of strings")
        has_txt, has_b64 = "stdin" in p, "stdin_b64" in p
        if has_txt == has_b64:
            raise ValueError(
                f"probe `{pid}`: exactly one of `stdin` / `stdin_b64` required")
        stdin = (p["stdin"].encode("utf-8") if has_txt
                 else base64.b64decode(p["stdin_b64"], validate=True))
        note = p.get("note", "")
        if not isinstance(note, str):
            raise ValueError(f"probe `{pid}`: `note` must be a string")
        probes.append({"id": pid, "args": args, "stdin": stdin, "note": note})
    return module, probes


def probes_modules(path):
    """The port modules this probes file claims to cover.

    `modules: [...]` (defaulting to `[module]`) mirrors the corpus module-tagging
    of LESSONS #040: one probes file may decide several modules, and `coverage`
    uses these tags to answer "does every ported module have probes at all?"
    Coverage metadata, not pinned behavior — deliberately outside the transcript
    fingerprint, which covers only the C's observed bytes."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    module = doc.get("module")
    mods = doc.get("modules", [module] if module else [])
    if (not isinstance(mods, list) or not mods
            or not all(isinstance(m, str) and m for m in mods)):
        raise ValueError(f"{path}: `modules` must be a non-empty list of strings")
    return mods


def cmd_coverage(a):
    """Fail unless EVERY named module is covered by some probes file.

    The gate above the gate (LESSONS #042). `run`/`gen`/`verify` fail closed on a
    probes file that pins nothing — but WHICH probes files exist was, until this
    subcommand, a hand-edited line in the port's check script. A module could land
    with no probes at all and no gate would notice: the kit's characteristic
    0-of-0 (LESSONS #036/#037/#039, and the source lineage's "a harness meets its
    real bugs only on a real port") displaced one level up, into the wiring.
    Point `--modules` at the port's real module list (or `--progress` at its
    progress.json, so the list cannot drift from the one the gates track)."""
    mods = []
    if a.progress:
        try:
            with open(a.progress, encoding="utf-8") as f:
                mods = list(json.load(f).get("modules", {}))
        except (OSError, json.JSONDecodeError, AttributeError) as e:
            return _die(f"{a.progress}: {e}")
    mods += [m for m in (a.modules or "").split(",") if m]
    mods = list(dict.fromkeys(mods))
    if not mods:
        # a coverage check over zero modules proves nothing and must not pass
        return _die("NOTHING-TO-COVER: no modules named "
                    "(--modules and/or --progress) — a coverage check over an "
                    "empty module list is the 0-of-0 pass this gate exists to "
                    "refuse (LESSONS #039)")
    covered = {}
    for path in a.probes:
        try:
            for m in probes_modules(path):
                covered.setdefault(m, []).append(os.path.basename(path))
        except (ValueError, OSError, json.JSONDecodeError) as e:
            return _die(str(e))
    missing = [m for m in mods if m not in covered]
    for m in mods:
        where = ", ".join(covered.get(m, [])) or "— NO PROBES"
        print(f"  {m:<20} {where}")
    if missing:
        print(f"FAIL: {len(missing)} module(s) with no probes file: "
              + ", ".join(missing))
        print("      write probes for them (probe-then-port is a Phase 4 entry "
              "criterion), or drop them from the module list if they are gone")
        return 1
    stray = [m for m in covered if m not in mods]
    if stray:
        print(f"note: probes tag module(s) not in the list: {', '.join(stray)}")
    print(f"probe coverage: {len(mods)} module(s), every one has probes")
    return 0


def run_oracle(oracle, probe, timeout):
    """One probe against the C. The contract is the kit's shared verdict
    surface — stdout + exit code (stderr is off-contract, as in diff_run)."""
    try:
        r = subprocess.run(
            [os.path.abspath(oracle)] + probe["args"], input=probe["stdin"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout)
    except subprocess.TimeoutExpired:
        # fail closed: a hang cannot be pinned as an expectation (LESSONS #036 —
        # the snapshot's both-hang→MATCH is exactly this class)
        raise RuntimeError(
            f"probe `{probe['id']}` TIMED OUT after {timeout}s — a hang is not "
            "a pinnable behavior; fix the probe or the oracle") from None
    return r.returncode, r.stdout


def cmd_run(a):
    try:
        module, probes = load_probes(a.probes)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        return _die(str(e))
    if not os.path.isfile(a.oracle):
        return _die(f"oracle not found: {a.oracle}")
    entries = []
    for p in probes:
        try:
            rc, out = run_oracle(a.oracle, p, a.timeout)
        except RuntimeError as e:
            return _die(str(e))
        entries.append({
            "id": p["id"], "args": p["args"],
            "stdin_b64": base64.b64encode(p["stdin"]).decode("ascii"),
            "note": p["note"], "rc": rc,
            "stdout_b64": base64.b64encode(out).decode("ascii"),
            "stdin_preview": _preview(p["stdin"]),
            "stdout_preview": _preview(out),
        })
        print(f"  {p['id']:<28} rc={rc}  stdout={_preview(out, 48)!r}")
    doc = {
        "probe_transcript": TRANSCRIPT_VERSION,
        "module": module,
        "oracle_sha256": _sha256_file(a.oracle),
        "generated_by": "harnesses/probe/probe.py run",
        "entries": entries,
        "fingerprint": _fingerprint(entries),
    }
    with open(a.transcript, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"TRANSCRIPT PINNED: {len(entries)} probe(s) -> {a.transcript}")
    print("next: probe.py gen --transcript ... --out <crate>/tests/<file>.rs")
    return 0


def load_transcript(path):
    """Load a transcript and enforce its fingerprint. Raises ValueError —
    a transcript whose pin doesn't match its entries has been hand-edited,
    and gen/verify must refuse it rather than propagate it into tests."""
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if doc.get("probe_transcript") != TRANSCRIPT_VERSION:
        raise ValueError(f"{path}: not a v{TRANSCRIPT_VERSION} probe transcript")
    entries = doc.get("entries", [])
    if not entries:
        raise ValueError(f"{path}: transcript pins NOTHING (LESSONS #039)")
    got, want = _fingerprint(entries), doc.get("fingerprint")
    if got != want:
        raise ValueError(
            f"{path}: TAMPERED — fingerprint mismatch (entries hash {got[:12]}…, "
            f"pinned {str(want)[:12]}…). A transcript is regenerated by `run`, "
            "never edited.")
    return doc


def _rust_ident(pid: str) -> str:
    return "probe_" + re.sub(r"[^a-z0-9_]", "_", pid.lower())


def _rust_bytes(data: bytes) -> str:
    """A Rust byte-string literal, byte-faithful (LESSONS #037): printable
    ASCII as-is, everything else \\xNN — no lossy decode step anywhere."""
    out = []
    for b in data:
        if b in (0x22, 0x5C):          # `"` and `\` need escaping
            out.append("\\" + chr(b))
        elif 0x20 <= b <= 0x7E:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return 'b"' + "".join(out) + '"'


def render_rust(doc, glue: str) -> str:
    """The generated test file. Every item carries `#[rustfmt::skip]` (the
    stable outer form — the file-level `#![rustfmt::skip]` is unstable) so
    rustfmt never reflows generated code and verify's byte-compare against a
    regeneration stays authoritative — a hand-edit can't be laundered through
    a formatter."""
    ents = doc["entries"]
    names = {}
    for e in ents:
        name = _rust_ident(e["id"])
        if name in names:
            raise ValueError(
                f"probe ids `{names[name]}` and `{e['id']}` both generate test "
                f"fn `{name}` — rename one")
        names[name] = e["id"]
    # The citation below is EMITTED into the port's generated Rust. Stage 1 of
    # this kit's refresh re-cited its head and left the continuation member at
    # the source lineage's number, so a citation meaning another lesson entirely
    # would have propagated out of the kit into port source, where nothing reads
    # it against this log (LESSONS #047; `check_imports.py` now catches it —
    # including, twice, in the comment you are reading).
    lines = [
        "// @generated by the porting kit's probe harness "
        "(harnesses/probe/probe.py gen).",
        "// DO NOT EDIT. Every expectation below is the C oracle's OBSERVED",
        "// behavior (probe-then-port, LESSONS #038/#041): to change one, change",
        "// the probe and re-run `probe.py run` + `gen`. `probe.py verify`",
        "// byte-compares this file against a fresh regeneration, so a hand",
        "// edit here FAILS the gate instead of silently redefining the spec.",
        f"// module: {doc['module']}",
        f"// transcript fingerprint: sha256:{doc['fingerprint']}",
        "",
        f"mod {glue};",
        "",
        "#[rustfmt::skip]",
        "fn check(id: &str, args: &[&str], stdin: &[u8], want_rc: i32, "
        "want_stdout: &[u8]) {",
        f"    let (rc, stdout) = {glue}::run_probe(args, stdin);",
        "    assert_eq!(",
        "        (rc, stdout.as_slice()),",
        "        (want_rc, want_stdout),",
        '        "probe `{id}` diverges from the pinned C-oracle transcript '
        '(never hand-edit; re-probe)"',
        "    );",
        "}",
    ]
    for e in ents:
        args = ", ".join(f'"{a}"' for a in e["args"])
        stdin = _rust_bytes(base64.b64decode(e["stdin_b64"]))
        stdout = _rust_bytes(base64.b64decode(e["stdout_b64"]))
        lines.append("")
        if e["note"]:
            for nl in e["note"].splitlines():
                lines.append(f"// {nl}")
        lines.append("#[test]")
        lines.append("#[rustfmt::skip]")
        lines.append(f"fn {_rust_ident(e['id'])}() {{")
        lines.append(f'    check("{e["id"]}", &[{args}], {stdin}, '
                     f'{e["rc"]}, {stdout});')
        lines.append("}")
    return "\n".join(lines) + "\n"


def cmd_gen(a):
    try:
        doc = load_transcript(a.transcript)
        rust = render_rust(doc, a.glue)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        return _die(str(e))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(rust)
    print(f"GENERATED: {len(doc['entries'])} #[test] fn(s) -> {a.out}")
    print(f"glue contract: tests/{a.glue}/mod.rs must provide "
          "`pub fn run_probe(args: &[&str], stdin: &[u8]) -> (i32, Vec<u8>)`")
    return 0


def cmd_verify(a):
    problems = []
    try:
        module, probes = load_probes(a.probes)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        return _die(str(e))
    try:
        doc = load_transcript(a.transcript)  # fingerprint enforced here
    except (ValueError, OSError, json.JSONDecodeError) as e:
        return _die(str(e))
    if doc["module"] != module:
        problems.append(f"module mismatch: probes say `{module}`, "
                        f"transcript says `{doc['module']}`")
    # 1. probes <-> transcript correspondence: an edited/added/reordered probe
    #    without a re-run means the transcript no longer describes the probes
    want = [(p["id"], tuple(p["args"]),
             base64.b64encode(p["stdin"]).decode("ascii"), p["note"])
            for p in probes]
    have = [(e["id"], tuple(e["args"]), e["stdin_b64"], e["note"])
            for e in doc["entries"]]
    if want != have:
        problems.append(
            "probes file and transcript disagree (probe added/edited/reordered "
            "without `probe.py run`) — re-probe to re-pin")
    # 2. oracle drift: re-run EVERY probe and re-compare rc + stdout. The
    #    recorded oracle_sha256 is informational only — a rebuilt binary may
    #    hash differently while behaving identically; behavior is the pin.
    if not os.path.isfile(a.oracle):
        return _die(f"oracle not found: {a.oracle}")
    if _sha256_file(a.oracle) != doc.get("oracle_sha256"):
        print("note: oracle binary hash changed since `run` "
              "(rebuild is fine; behavior is re-checked below)")
    by_id = {e["id"]: e for e in doc["entries"]}
    for p in probes:
        e = by_id.get(p["id"])
        if e is None:
            continue  # already reported by the correspondence check
        try:
            rc, out = run_oracle(a.oracle, p, a.timeout)
        except RuntimeError as err:
            problems.append(str(err))
            continue
        out_b64 = base64.b64encode(out).decode("ascii")
        # the crown verdict: the oracle's live behavior must equal the pin
        behavior_matches = rc == e["rc"] and out_b64 == e["stdout_b64"]
        if not behavior_matches:
            problems.append(
                f"ORACLE DRIFT on `{p['id']}`: pinned rc={e['rc']} "
                f"stdout={_preview(base64.b64decode(e['stdout_b64']), 40)!r}, "
                f"live rc={rc} stdout={_preview(out, 40)!r} — the C changed "
                "under the transcript; re-probe and re-triage")
    # 3. generated file: byte-compare against a fresh regeneration — catches
    #    hand-edits AND a stale file after a re-probe
    try:
        expect = render_rust(doc, a.glue)
    except ValueError as e:
        return _die(str(e))
    if not os.path.isfile(a.out):
        problems.append(f"generated test file missing: {a.out} (run `gen`)")
    else:
        actual = open(a.out, encoding="utf-8").read()
        if actual != expect:
            problems.append(
                f"{a.out} does not byte-match a regeneration — hand-edited or "
                "stale; re-run `probe.py gen` (and re-probe if the transcript "
                "changed)")
    for p in problems:
        print("FAIL: " + p)
    n = len(doc["entries"])
    if problems:
        print(f"probe verify: {n} probe(s), {len(problems)} problem(s)")
        return 1
    print(f"probe verify: {n} probe(s) pinned, oracle behavior unchanged, "
          "generated tests byte-match")
    return 0


# --------------------------------------------------------------------------
def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    def ns(**kw):
        return argparse.Namespace(**kw)

    with tempfile.TemporaryDirectory() as d:
        oracle = os.path.join(d, "fake_oracle.py")
        with open(oracle, "w") as f:
            f.write(
                "#!/usr/bin/env python3\n"
                "import sys, time\n"
                "mode = sys.argv[1]\n"
                "data = sys.stdin.buffer.read()\n"
                "if mode == 'upper': sys.stdout.buffer.write(data.upper())\n"
                "elif mode == 'bytes': sys.stdout.buffer.write(b'\\xff\\x00A')\n"
                "elif mode == 'hang': time.sleep(30)\n"
                "elif mode == 'fail': sys.exit(1)\n")
        os.chmod(oracle, 0o755)
        probes = os.path.join(d, "probes.json")
        with open(probes, "w") as f:
            json.dump({"module": "demo", "probes": [
                {"id": "up-1", "args": ["upper"], "stdin": "abc",
                 "note": "case mapping"},
                {"id": "raw-bytes", "args": ["bytes"], "stdin": ""},
                {"id": "rejects", "args": ["fail"], "stdin": "x"},
            ]}, f)
        transcript = os.path.join(d, "t.json")
        gen = os.path.join(d, "probes_gen.rs")
        R = ns(probes=probes, oracle=oracle, transcript=transcript, timeout=10)
        G = ns(transcript=transcript, out=gen, glue="probe_glue")
        V = ns(probes=probes, oracle=oracle, transcript=transcript, out=gen,
               glue="probe_glue", timeout=10)

        # happy path: run pins the observed behavior, byte-faithfully
        check("run pins a transcript", cmd_run(R) == 0)
        doc = json.load(open(transcript))
        e = {x["id"]: x for x in doc["entries"]}
        check("observed rc + stdout recorded",
              e["up-1"]["rc"] == 0
              and base64.b64decode(e["up-1"]["stdout_b64"]) == b"ABC"
              and e["rejects"]["rc"] == 1)
        check("non-UTF-8 stdout stored byte-faithfully (LESSONS #037)",
              base64.b64decode(e["raw-bytes"]["stdout_b64"]) == b"\xff\x00A")

        # gen: expectations come from the transcript, marked DO NOT EDIT
        check("gen writes the Rust tests", cmd_gen(G) == 0)
        rust = open(gen).read()
        check("generated tests carry the observed bytes",
              'check("up-1", &["upper"], b"abc", 0, b"ABC");' in rust
              and "\\xff\\x00A" in rust)
        check("generated file is marked generated + rustfmt-skipped",
              "DO NOT EDIT" in rust and "#[rustfmt::skip]" in rust)
        check("clean verify passes", cmd_verify(V) == 0)

        # zero probes / duplicate ids fail closed (LESSONS #039)
        empt = os.path.join(d, "empty.json")
        json.dump({"module": "demo", "probes": []}, open(empt, "w"))
        check("zero probes is a FAILURE, not a pass (LESSONS #039)",
              cmd_run(ns(probes=empt, oracle=oracle, transcript=transcript,
                         timeout=10)) == 1)
        dup = os.path.join(d, "dup.json")
        json.dump({"module": "demo", "probes": [
            {"id": "a", "args": ["upper"], "stdin": "x"},
            {"id": "a", "args": ["upper"], "stdin": "y"}]}, open(dup, "w"))
        check("duplicate probe ids are refused",
              cmd_run(ns(probes=dup, oracle=oracle, transcript=transcript,
                         timeout=10)) == 1)
        check("run re-pins after the refused runs", cmd_run(R) == 0 and
              cmd_gen(G) == 0 and cmd_verify(V) == 0)

        # ids that collide after Rust-ident sanitization are refused at gen
        col = os.path.join(d, "col.json")
        json.dump({"module": "demo", "probes": [
            {"id": "a-b", "args": ["upper"], "stdin": "x"},
            {"id": "a.b", "args": ["upper"], "stdin": "y"}]}, open(col, "w"))
        tcol = os.path.join(d, "tcol.json")
        cmd_run(ns(probes=col, oracle=oracle, transcript=tcol, timeout=10))
        check("colliding sanitized test names are refused",
              cmd_gen(ns(transcript=tcol, out=os.path.join(d, "c.rs"),
                         glue="probe_glue")) == 1)

        # a hand-edited transcript is TAMPER: gen and verify both refuse
        doc = json.load(open(transcript))
        doc["entries"][0]["rc"] = 7          # rewrite an expectation by hand
        json.dump(doc, open(transcript, "w"))
        check("gen refuses a tampered transcript (fingerprint)",
              cmd_gen(G) == 1)
        check("verify refuses a tampered transcript (fingerprint)",
              cmd_verify(V) == 1)
        cmd_run(R), cmd_gen(G)               # re-pin

        # probes edited without a re-run: correspondence fails
        pd = json.load(open(probes))
        pd["probes"][0]["stdin"] = "abcd"
        json.dump(pd, open(probes, "w"))
        check("probe edited without re-run is caught", cmd_verify(V) == 1)
        cmd_run(R), cmd_gen(G)               # re-pin over the edited probes

        # ORACLE DRIFT: the C changing under the transcript must fail verify
        with open(oracle, "a") as f:
            f.write("sys.stdout.write('!')\n")
        check("oracle drift is caught (behavior re-run, not hash-trusted)",
              cmd_verify(V) == 1)
        cmd_run(R), cmd_gen(G)               # re-pin over the drifted oracle

        # a hand-edited generated file must fail the byte-compare
        with open(gen, "a") as f:
            f.write("// innocuous-looking tweak\n")
        check("hand-edited generated file is caught", cmd_verify(V) == 1)
        check("missing generated file is caught",
              (os.remove(gen) or cmd_verify(V)) == 1)
        cmd_gen(G)
        check("regeneration clears it", cmd_verify(V) == 0)

        # Every check above asks only whether verify exits 1, and one failure
        # anywhere answers yes for all of them. Each verdict below is asked for
        # by its own message (LESSONS #069/#071's decision sweep found four that
        # no fixture reached on its own).
        import contextlib
        import io

        def verify_says(v):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cmd_verify(v)
            return rc, out.getvalue() + err.getvalue()

        src = open(oracle).read()
        open(oracle, "w").write(src.replace("sys.exit(1)", "sys.exit(2)"))
        rc, said = verify_says(V)
        check("an exit-code-only drift is ORACLE DRIFT (stdout alone is not the pin)",
              rc == 1 and "ORACLE DRIFT on `rejects`" in said)
        open(oracle, "w").write(src)

        pd = json.load(open(probes))
        pd["probes"][0]["stdin"] = "abcde"
        json.dump(pd, open(probes, "w"))
        rc, said = verify_says(V)
        check("an edited probe is named as a correspondence failure, not only as drift",
              rc == 1 and "probes file and transcript disagree" in said)
        pd["probes"][0]["stdin"] = "abcd"
        pd["probes"].append({"id": "new-1", "args": ["upper"], "stdin": "z"})
        json.dump(pd, open(probes, "w"))
        rc, said = verify_says(V)
        check("a probe added without a re-run fails the correspondence check",
              rc == 1 and "probes file and transcript disagree" in said)
        pd["probes"].pop()
        pd["module"] = "other"
        json.dump(pd, open(probes, "w"))
        rc, said = verify_says(V)
        check("a transcript pinned for another module is refused",
              rc == 1 and "module mismatch" in said)
        pd["module"] = "demo"
        json.dump(pd, open(probes, "w"))
        rc, said = verify_says(ns(probes=probes, oracle=os.path.join(d, "no-oracle"),
                                  transcript=transcript, out=gen, glue="probe_glue",
                                  timeout=10))
        check("a missing oracle is an error, not a crash",
              rc == 1 and "oracle not found" in said)
        check("...and the fixtures above leave verify clean", cmd_verify(V) == 0)

        # LESSONS #042: coverage — the gate above the gate. A module with NO
        # probes file at all must fail; nothing below this subcommand notices,
        # because `run`/`gen`/`verify` only ever see the files they are handed.
        prog = os.path.join(d, "progress.json")
        json.dump({"modules": {"demo": "ported", "unprobed": "ported"}},
                  open(prog, "w"))
        cov = ns(probes=[probes], modules="", progress=prog)
        check("a module with no probes file is CAUGHT", cmd_coverage(cov) == 1)
        json.dump({"modules": {"demo": "ported"}}, open(prog, "w"))
        check("coverage passes once every module has probes",
              cmd_coverage(ns(probes=[probes], modules="", progress=prog)) == 0)
        # a probes file may cover several modules (LESSONS #040 tagging idiom)
        multi = os.path.join(d, "multi.json")
        pd = json.load(open(probes))
        pd["modules"] = ["demo", "second"]
        json.dump(pd, open(multi, "w"))
        check("one probes file can cover several tagged modules",
              cmd_coverage(ns(probes=[multi], modules="demo,second",
                              progress=None)) == 0)
        # and an EMPTY module list must not pass (0-of-0, one level up)
        check("coverage over zero modules is a FAILURE (LESSONS #039)",
              cmd_coverage(ns(probes=[probes], modules="", progress=None)) == 1)

        # a hanging oracle fails closed — a hang is not a pinnable expectation
        hang = os.path.join(d, "hang.json")
        json.dump({"module": "demo", "probes": [
            {"id": "h", "args": ["hang"], "stdin": ""}]}, open(hang, "w"))
        check("oracle hang fails closed (LESSONS #036)",
              cmd_run(ns(probes=hang, oracle=oracle,
                         transcript=os.path.join(d, "th.json"),
                         timeout=1)) == 1)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p, gen_side, oracle_side):
        p.add_argument("--transcript", required=True)
        if oracle_side:
            p.add_argument("--probes", required=True)
            p.add_argument("--oracle", required=True)
            p.add_argument("--timeout", type=float, default=10)
        if gen_side:
            p.add_argument("--out", required=True)
            p.add_argument("--glue", default="probe_glue")

    common(sub.add_parser("run", help="run probes, pin the transcript"),
           gen_side=False, oracle_side=True)
    common(sub.add_parser("gen", help="generate Rust tests from the transcript"),
           gen_side=True, oracle_side=False)
    common(sub.add_parser("verify", help="fail on drift, tamper, or staleness"),
           gen_side=True, oracle_side=True)
    pc = sub.add_parser("coverage",
                        help="fail unless every module has a probes file")
    pc.add_argument("--probes", nargs="+", required=True)
    pc.add_argument("--modules", default="", help="comma-separated module names")
    pc.add_argument("--progress", help="progress.json to read module names from")
    a = ap.parse_args(argv)
    return {"run": cmd_run, "gen": cmd_gen, "verify": cmd_verify,
            "coverage": cmd_coverage}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
