#!/usr/bin/env python3
"""Oracle-substitution differential for winlsof's socket view.

The reference C ``lsof`` cannot run on Windows, so a same-binary differential is
impossible (RETROSPECTIVE-lsof.md sec. 5). This harness substitutes the OS's own
socket table as the oracle: it compares winlsof's ``-i`` output against
``Get-NetTCPConnection`` / ``Get-NetUDPEndpoint`` as a **set**, so a silently
dropped, extra, or misclassified socket row is a failure -- not something that
survives because one substring happened to match. This is the escalation the
survey called the single highest-leverage correctness improvement, and the
"oracle-substitution mode" the retrospective prescribed for the kit.

This module is pure-stdlib and platform-independent on purpose: the Windows-only
capture (``capture.ps1``) writes two artifacts -- winlsof's own output and the
oracle's JSON -- and this comparator parses, canonicalizes, and diffs them. That
split means the comparison logic is unit-tested off-Windows (test_oracle_diff.py)
while only the live capture needs a real runner.

Design mirrors the c2rust-port kit (now v1.0): normalize both sides identically,
diff, and honor a divergence ledger for intentional, documented differences.
"""

import argparse
import ipaddress
import json
import sys
from collections import Counter, namedtuple

# Exit codes, kept distinct so CI can tell a real divergence from broken plumbing.
EXIT_OK = 0
EXIT_DIVERGENCE = 1  # winlsof's set differs from the oracle's
EXIT_INFRA = 2       # empty/malformed capture -- the comparison never really ran

# A canonicalized socket endpoint row. Everything compared is already normalized
# so that == means "the same socket" regardless of which tool reported it.
SocketRow = namedtuple("SocketRow", ["proto", "family", "local", "remote", "state", "pid"])

# Windows and lsof spell TCP states differently; fold both onto lsof's names.
# Key is the source string lowercased with all non-alphanumerics removed.
_STATE = {
    "listen": "LISTEN",
    "established": "ESTABLISHED",
    "timewait": "TIME_WAIT",
    "closewait": "CLOSE_WAIT",
    "synsent": "SYN_SENT",
    "synreceived": "SYN_RCVD",
    "synrcvd": "SYN_RCVD",
    "finwait1": "FIN_WAIT1",
    "finwait2": "FIN_WAIT2",
    "closing": "CLOSING",
    "lastack": "LAST_ACK",
    "closed": "CLOSED",
    "bound": "BOUND",
    "deletetcb": "DELETE_TCB",
}

_WILDCARD_ADDRS = {"0.0.0.0", "::", "", "*", "[::]"}


def canon_addr(addr):
    """Normalize a host so wildcards and IPv6 spellings compare equal.

    IP literals are folded to one canonical form via ``ipaddress`` (RFC 5952
    for IPv6), so the Rust and Windows stacks never disagree merely on
    zero-run compression or embedded-IPv4 notation.
    """
    if addr is None:
        return "*"
    a = addr.strip()
    if a.startswith("[") and a.endswith("]"):
        a = a[1:-1]
    a = a.split("%", 1)[0]  # drop IPv6 zone id (fe80::1%12)
    a = a.lower()
    if a in _WILDCARD_ADDRS:
        return "*"
    try:
        ip = ipaddress.ip_address(a)
        return "*" if ip.is_unspecified else ip.compressed
    except ValueError:
        return a


def split_endpoint(s):
    """Split an ``addr:port`` string, tolerating bracketed/plain IPv6."""
    s = s.strip()
    if s.startswith("["):  # [::1]:80
        host, _, rest = s.partition("]")
        return host[1:], rest.lstrip(":")
    if ":" in s:
        host, port = s.rsplit(":", 1)
        return host, port
    return s, ""


def canon_ep(host, port):
    """Canonical ``addr:port`` for set comparison."""
    port = str(port).strip() if port is not None else ""
    return "{0}:{1}".format(canon_addr(host), port)


def canon_remote(host, port):
    """Remote endpoint, collapsing a listener's placeholder peer to '-'.

    Get-NetTCPConnection reports a listening socket's remote as 0.0.0.0:0; lsof
    (and winlsof) omit the peer entirely. Treat both as "no remote".
    """
    if host is None:
        return "-"
    p = str(port).strip() if port is not None else ""
    if canon_addr(host) == "*" and p in ("0", ""):
        return "-"
    return canon_ep(host, port)


def canon_state(s):
    if not s:
        return "-"
    key = "".join(ch for ch in s.lower() if ch.isalnum())
    return _STATE.get(key, s.strip().upper())


def canon_family(fam, host_hint=None):
    """Normalize family to IPv4/IPv6; infer from the address if not given."""
    if fam:
        f = fam.strip().lower()
        if "6" in f:
            return "IPv6"
        if "4" in f:
            return "IPv4"
    if host_hint and ":" in canon_addr(host_hint):
        return "IPv6"
    return "IPv4"


# --------------------------------------------------------------------------- #
# Parsers -- each returns a list[SocketRow]                                    #
# --------------------------------------------------------------------------- #

def parse_winlsof_json(text):
    """Parse winlsof ``-i -J`` output. Socket rows carry a ``protocol`` key."""
    text = _strip_banner(text)
    data = json.loads(text)
    rows = []
    for proc in data.get("processes", []):
        pid = proc.get("pid")
        for f in proc.get("files", []):
            proto = f.get("protocol")
            if not proto:
                continue  # not a socket
            lh, lp = split_endpoint(f["local"]) if f.get("local") else (None, None)
            if f.get("remote"):
                rh, rp = split_endpoint(f["remote"])
                remote = canon_remote(rh, rp)
            else:
                remote = "-"
            rows.append(SocketRow(
                proto=proto.upper(),
                family=canon_family(f.get("type"), lh),
                local=canon_ep(lh, lp) if lh is not None else "-",
                remote=remote,
                state=canon_state(f.get("state")),
                pid=pid,
            ))
    return rows


def parse_winlsof_fields(text):
    """Parse winlsof ``-i -F`` output (newline-terminated token stream).

    A ``p`` token opens a process set; ``f`` opens a file. A file is a socket
    once a ``P`` (protocol) token appears. ``n`` carries ``local->remote (STATE)``
    (or just ``local`` for a stateless UDP socket); ``T`` carries ``ST=<state>``.
    """
    pid = None
    fam = proto = state = name = None
    have_sock = False
    rows = []

    def flush():
        if not (have_sock and name is not None):
            return
        body, _, _ = name.partition(" (")  # strip the trailing " (STATE)"
        if "->" in body:
            lo, _, ro = body.partition("->")
            lh, lp = split_endpoint(lo)
            rh, rp = split_endpoint(ro)
            remote = canon_remote(rh, rp)
        else:
            lh, lp = split_endpoint(body)
            remote = "-"
        rows.append(SocketRow(
            proto=(proto or "").upper(),
            family=canon_family(fam, lh),
            local=canon_ep(lh, lp),
            remote=remote,
            state=canon_state(state),
            pid=pid,
        ))

    for line in _strip_banner(text).splitlines():
        if not line:
            continue
        code, val = line[0], line[1:]
        if code == "p":
            flush()
            pid = _to_int(val)
            fam = proto = state = name = None
            have_sock = False
        elif code == "f":
            flush()
            fam = proto = state = name = None
            have_sock = False
        elif code == "t":
            fam = val
        elif code == "P":
            proto = val
            have_sock = True
        elif code == "T":
            state = val[3:] if val.startswith("ST=") else val
        elif code == "n":
            name = val
    flush()
    return rows


def parse_oracle_json(text):
    """Parse the oracle capture emitted by capture.ps1.

    A JSON array of objects: proto, local_addr, local_port, remote_addr,
    remote_port, state, pid (remote_*/state null for UDP).
    """
    rows = []
    for o in json.loads(text):
        proto = (o.get("proto") or "").upper()
        rows.append(SocketRow(
            proto=proto,
            family=canon_family(o.get("family"), o.get("local_addr")),
            local=canon_ep(o.get("local_addr"), o.get("local_port")),
            remote=canon_remote(o.get("remote_addr"), o.get("remote_port")),
            state=canon_state(o.get("state")),
            pid=o.get("pid"),
        ))
    return rows


# --------------------------------------------------------------------------- #
# Ledger + diff                                                               #
# --------------------------------------------------------------------------- #

def load_ledger(path):
    """Load intentional-divergence patterns.

    JSON list of objects; each may pin proto/family/local/remote/state/side
    (side: 'missing'|'extra'|'any'). A divergence is suppressed when every key
    present in a rule matches (substring for endpoints, exact otherwise).
    """
    if not path:
        return []
    with open(path, "r", encoding="utf-8-sig") as fh:
        rules = json.load(fh)
    if not isinstance(rules, list):
        raise ValueError("ledger must be a JSON list of rules")
    return rules


def _row_matches_rule(row, side, rule):
    if rule.get("side", "any") not in ("any", side):
        return False
    for key in ("proto", "family", "state"):
        if key in rule and rule[key].upper() != getattr(row, key).upper():
            return False
    # Endpoints match exactly against the canonical form (e.g. "*:53",
    # "127.0.0.1:445"); exact, not substring, so "53" can't silence ":5353".
    for key in ("local", "remote"):
        if key in rule and rule[key] != getattr(row, key):
            return False
    return True


def _suppressed(row, side, ledger):
    for rule in ledger:
        if _row_matches_rule(row, side, rule):
            return rule.get("reason", "(ledgered)")
    return None


def _in_scope(row, scope_ports, scope_pid):
    if scope_pid is not None and row.pid != scope_pid:
        return False
    if scope_ports:
        lp = row.local.rsplit(":", 1)[-1]
        rp = row.remote.rsplit(":", 1)[-1] if row.remote != "-" else None
        if lp not in scope_ports and rp not in scope_ports:
            return False
    return True


def scoped(rows, scope_ports=None, scope_pid=None):
    """Rows within the pid/port scope -- also used for the empty-capture floor."""
    return [r for r in rows if _in_scope(r, scope_ports, scope_pid)]


def diff(winlsof_rows, oracle_rows, scope_ports=None, scope_pid=None, ledger=None):
    """Multiset diff of winlsof vs oracle within scope.

    Returns (missing, extra, notes); each item is (representative_row, why, count).

    missing = in oracle, under-reported by winlsof.
    extra   = in winlsof, not backed by the oracle.
    A *multiset* (not a set), so a duplicated/over-emitted row is caught rather
    than collapsing onto its twin. Ledgered divergences move to notes.
    """
    ledger = ledger or []
    w_rows = scoped(winlsof_rows, scope_ports, scope_pid)
    o_rows = scoped(oracle_rows, scope_ports, scope_pid)

    # Drop pid from the identity only when scope already pins one process; else
    # keep it so a cross-process mismatch cannot silently cancel out.
    def key(r):
        base = (r.proto, r.family, r.local, r.remote, r.state)
        return base if scope_pid is not None else base + (r.pid,)

    wc, oc = Counter(map(key, w_rows)), Counter(map(key, o_rows))
    wrep = {key(r): r for r in w_rows}
    orep = {key(r): r for r in o_rows}

    missing, extra, notes = [], [], []
    for k in sorted(set(wc) | set(oc), key=repr):
        delta = wc[k] - oc[k]
        if delta < 0:  # oracle has more copies -> winlsof under-reports
            row = orep[k]
            why = _suppressed(row, "missing", ledger)
            (notes if why else missing).append((row, why, -delta))
        elif delta > 0:  # winlsof has more copies -> over-reports
            row = wrep[k]
            why = _suppressed(row, "extra", ledger)
            (notes if why else extra).append((row, why, delta))
    return missing, extra, notes


def _fmt(row, count=1):
    r = "" if row.remote == "-" else "->{0}".format(row.remote)
    st = "" if row.state == "-" else " ({0})".format(row.state)
    mult = "" if count == 1 else " x{0}".format(count)
    return "{0}/{1} {2}{3}{4} pid={5}{6}".format(row.proto, row.family, row.local, r, st, row.pid, mult)


# --------------------------------------------------------------------------- #
# Helpers + CLI                                                               #
# --------------------------------------------------------------------------- #

def _strip_banner(text):
    """Drop winlsof's non-Windows mock banner / any non-token preamble lines."""
    out = []
    for line in text.splitlines():
        if line.startswith("lsof:"):
            continue
        out.append(line)
    return "\n".join(out)


def _to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def main(argv=None):
    ap = argparse.ArgumentParser(description="winlsof socket oracle-substitution differential")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--winlsof-json", help="file with winlsof `-i -J` output")
    src.add_argument("--winlsof-fields", help="file with winlsof `-i -F` output")
    ap.add_argument("--oracle", required=True, help="oracle JSON from capture.ps1")
    ap.add_argument("--ledger", help="intentional-divergence ledger (JSON)")
    ap.add_argument("--scope-ports", help="comma-separated ports to restrict the comparison to")
    ap.add_argument("--scope-pid", type=int, help="restrict the comparison to one pid")
    ap.add_argument("--min-rows", type=int, default=1,
                    help="infra-fail (exit 2) if either side has fewer in-scope rows (default 1)")
    args = ap.parse_args(argv)

    try:
        if args.winlsof_json:
            winlsof_rows = parse_winlsof_json(_read(args.winlsof_json))
        else:
            winlsof_rows = parse_winlsof_fields(_read(args.winlsof_fields))
        oracle_rows = parse_oracle_json(_read(args.oracle))
    except (ValueError, json.JSONDecodeError) as exc:
        # Malformed/truncated capture (e.g. winlsof killed on the hang path) is
        # infrastructure breakage, not a socket-set divergence -- keep it a
        # distinct exit so CI triage doesn't read it as "winlsof is wrong".
        print("INFRA: malformed capture: {0}".format(exc))
        return EXIT_INFRA

    ledger = load_ledger(args.ledger)
    scope_ports = set(p.strip() for p in args.scope_ports.split(",")) if args.scope_ports else None

    w_scoped = scoped(winlsof_rows, scope_ports, args.scope_pid)
    o_scoped = scoped(oracle_rows, scope_ports, args.scope_pid)
    print("winlsof rows: {0} ({1} in scope)   oracle rows: {2} ({3} in scope)   scope: pid={4} ports={5}".format(
        len(winlsof_rows), len(w_scoped), len(oracle_rows), len(o_scoped),
        args.scope_pid, sorted(scope_ports) if scope_ports else "all"))

    # Empty-capture floor. If either side has nothing in scope the comparison is
    # vacuous: an empty==empty "match" would hide a winlsof enumeration
    # regression, and an empty oracle would masquerade as all-EXTRA. Fail as
    # infra (exit 2), never as a divergence verdict.
    if len(w_scoped) < args.min_rows or len(o_scoped) < args.min_rows:
        print("INFRA: too few in-scope rows (winlsof={0}, oracle={1}, need >= {2}); "
              "capture likely empty/failed -- not a divergence verdict".format(
                  len(w_scoped), len(o_scoped), args.min_rows))
        return EXIT_INFRA

    missing, extra, notes = diff(winlsof_rows, oracle_rows, scope_ports, args.scope_pid, ledger)

    for row, why, count in notes:
        print("  LEDGERED  {0}  <- {1}".format(_fmt(row, count), why))
    for row, _why, count in missing:
        print("  MISSING   {0}   (oracle has it, winlsof does not)".format(_fmt(row, count)))
    for row, _why, count in extra:
        print("  EXTRA     {0}   (winlsof has it, oracle does not)".format(_fmt(row, count)))

    if missing or extra:
        print("DIFFERENTIAL FAILED: {0} missing, {1} extra ({2} ledgered)".format(
            len(missing), len(extra), len(notes)))
        return EXIT_DIVERGENCE
    print("DIFFERENTIAL OK: winlsof's socket set matches the OS oracle within scope "
          "({0} ledgered divergence(s))".format(len(notes)))
    return EXIT_OK


def _read(path):
    # The capture artifacts are UTF-8 (winlsof `-i -J` embeds every process's
    # command/user verbatim); decoding them as the Windows ANSI code page would
    # crash on the first non-ASCII byte. utf-8-sig also tolerates a BOM.
    with open(path, "r", encoding="utf-8-sig") as fh:
        return fh.read()


if __name__ == "__main__":
    sys.exit(main())
