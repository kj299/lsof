#!/usr/bin/env python3
"""Overflow gate: the release build carries overflow checks, in every crate of
this workspace, and the linked binary shows it.

`[profile.release]` sets `overflow-checks = true` (the maintainer's decision,
2026-10-09). Arithmetic on values from other processes and the kernel is
checked first, so an overflow that audit missed panics instead of wrapping into
a wrong address or count. Losing the flag fails nothing else: on every input
that does not overflow, the binary behaves the same. So this gate asks for it
directly, by two signals, because neither one sees every way to lose it
(measured 2026-10-09 on the Linux build):

1. Cargo's own report of each unit's profile (`--message-format=json`,
   `profile.overflow_checks`), for every workspace crate. It sees a
   `[profile.release.package.<crate>]` override, whether in Cargo.toml, a
   `.cargo/config.toml` or a `CARGO_PROFILE_RELEASE_PACKAGE_*` variable. The
   panic message cannot: with lsof-core and lsof-backend-linux overridden, the
   binary still carried it, from lsof-cli.
2. The panic message `attempt to add with overflow` in the linked binary,
   which only overflow checks put there (`strip` leaves it). It sees
   `-C overflow-checks=off` in RUSTFLAGS or a config `rustflags`, which cargo's
   report cannot: that report shows the profile, not the flags.

Run it from lsof-rs/ after `cargo build --release --bin lsof`. It runs that
build again with `--message-format=json`, which rebuilds nothing, and takes the
binary's path from cargo's report, so the same script checks `lsof` on Linux
and `lsof.exe` on Windows.

Usage:
  overflow_gate.py [-- CARGO_BUILD_ARGS...]
  overflow_gate.py --self-test
Exit: 0 = every workspace crate and the binary carry overflow checks; 1 = one
does not; 2 = usage, or the build failed or reported no crate or no binary.
"""
from __future__ import annotations

import json
import subprocess
import sys

MESSAGE = b"attempt to add with overflow"
BUILD = ["cargo", "build", "--release", "--bin", "lsof", "--message-format=json"]


def verdict(messages, read):
    """(problems, infra, crates) over cargo's JSON messages. `read(path)`
    returns a file's bytes. A problem is a missing check (exit 1); `infra` is
    why nothing could be judged (exit 2), or None."""
    crates, problems, exe = [], [], None
    for m in messages:
        if m.get("reason") != "compiler-artifact":
            continue
        target = m.get("target", {})
        # Workspace crates only (a `path+file` package id): the third-party
        # crates, the windows-sys family on Windows, are not this audit's code,
        # and a build script is not shipped.
        if "path+file://" not in m.get("package_id", ""):
            continue
        if "custom-build" in target.get("kind", []):
            continue
        name = target.get("name", "?")
        crates.append(name)
        if m.get("profile", {}).get("overflow_checks") is not True:
            problems.append(f"{name} was built without overflow checks "
                            "([profile.release], or an override of it for "
                            "this crate)")
        if name == "lsof" and "bin" in target.get("kind", []):
            exe = m.get("executable")
    # 0-of-0 is no pass: a report with nothing in it judged nothing.
    if not crates:
        return problems, "cargo reported no workspace crate", crates
    if not exe:
        return problems, "cargo reported no lsof binary", crates
    try:
        image = read(exe)
    except OSError as e:
        return problems, f"cannot read {exe}: {e}", crates
    if MESSAGE not in image:
        problems.append(f"{exe} lacks {MESSAGE.decode()!r}: built without "
                        "overflow checks (RUSTFLAGS or a config rustflags?)")
    return problems, None, crates


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def run(extra):
    p = subprocess.run(BUILD + extra, stdout=subprocess.PIPE, encoding="utf-8")
    if p.returncode != 0:
        print(f"overflow_gate: ERROR: {' '.join(BUILD + extra)} exited "
              f"{p.returncode}")
        return 2
    messages = [json.loads(line) for line in p.stdout.splitlines()
                if line.startswith("{")]
    problems, infra, crates = verdict(messages, _read)
    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        return 1
    if infra:
        print(f"overflow_gate: ERROR: {infra}")
        return 2
    print(f"overflow_gate: OK: {len(crates)} workspace units built with "
          f"overflow checks ({', '.join(sorted(set(crates)))}), and the binary "
          f"carries {MESSAGE.decode()!r}")
    return 0


def _self_test():
    ok = True

    def check(what, cond):
        nonlocal ok
        ok &= bool(cond)
        print(("  ok    " if cond else "  FAIL  ") + what)

    def art(name, kind, checks, pkg="path+file:///w/crates/c#c@1.0.1", exe=None):
        return {"reason": "compiler-artifact", "package_id": pkg,
                "target": {"name": name, "kind": [kind]},
                "profile": {"overflow_checks": checks}, "executable": exe}

    good = [art("lsof_core", "lib", True), art("lsof_cli", "lib", True),
            art("lsof", "bin", True, exe="/t/lsof"),
            {"reason": "build-finished", "success": True}]
    carries = {"/t/lsof": b"\0..attempt to add with overflow..\0"}
    lacks = {"/t/lsof": b"\0..attempt to subtract with overflow..\0"}

    def judge(messages, files):
        def read(path):
            if path not in files:
                raise OSError("no such file")
            return files[path]
        return verdict(messages, read)

    problems, infra, crates = judge(good, carries)
    check("every crate checked and the message present: a pass",
          not problems and infra is None and len(crates) == 3)
    one_off = [art("lsof_core", "lib", False)] + good[1:]
    problems, infra, _ = judge(one_off, carries)
    check("one crate overridden, the message still there (lsof-cli's): FAILS",
          len(problems) == 1 and "lsof_core" in problems[0])
    problems, _, _ = judge(good, lacks)
    check("every profile checked but the binary lacks the message "
          "(RUSTFLAGS): FAILS", len(problems) == 1 and "lacks" in problems[0])
    third = good + [art("windows_sys", "lib", False,
                        pkg="registry+https://github.com/rust-lang/crates.io-index#windows-sys@0.59.0")]
    problems, infra, _ = judge(third, carries)
    check("a third-party crate is not this gate's", not problems and infra is None)
    script = good + [art("build_script_build", "custom-build", False)]
    problems, infra, _ = judge(script, carries)
    check("a build script is not shipped", not problems and infra is None)
    _, infra, _ = judge([], carries)
    check("an empty report is no pass (0-of-0)", infra is not None)
    _, infra, _ = judge(good[:2], carries)
    check("a report without the lsof binary is no pass", infra is not None)
    _, infra, _ = judge(good, {})
    check("a binary that cannot be read is no pass", infra is not None)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv):
    if argv == ["--self-test"]:
        return _self_test()
    if argv and argv[0] != "--":
        print(__doc__.split("Usage:")[1].strip(), file=sys.stderr)
        return 2
    return run(argv[1:])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
