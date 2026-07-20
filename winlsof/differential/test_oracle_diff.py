#!/usr/bin/env python3
"""Unit tests for oracle_diff.py -- runnable on any host (no Windows needed).

The winlsof fixtures below are the *verbatim* `-i -J` and `-i -F` output of the
real binary running its mock backend, so the parsers are tested against genuine
output shapes, not hand-guessed ones. The oracle fixture is the equivalent
Get-NetTCPConnection/Get-NetUDPEndpoint view of the same three sockets.
"""

import json
import unittest

import oracle_diff as od

# --- verbatim `target/debug/lsof -nP -i -J` (mock backend) ------------------
WINLSOF_JSON = (
    'lsof: non-Windows build: showing sample (mock) data\n'
    '{"processes":[{"pid":1500,"command":"server.exe","ppid":1000,'
    '"user":"EXAMPLE\\\\alice","files":['
    '{"fd":"72","type":"IPv4","name":"*:445 (LISTEN)","access":"u","node":"TCP",'
    '"protocol":"TCP","local":"0.0.0.0:445","state":"LISTEN"},'
    '{"fd":"88","type":"IPv4","name":"127.0.0.1:445->127.0.0.1:51000 (ESTABLISHED)",'
    '"access":"u","node":"TCP","protocol":"TCP","local":"127.0.0.1:445",'
    '"remote":"127.0.0.1:51000","state":"ESTABLISHED"},'
    '{"fd":"96","type":"IPv6","name":"[::]:53","access":"u","node":"UDP",'
    '"protocol":"UDP","local":"[::]:53"}]}]}'
)

# --- verbatim `target/debug/lsof -nP -i -F` (mock backend) ------------------
WINLSOF_FIELDS = (
    "lsof: non-Windows build: showing sample (mock) data\n"
    "p1500\nR1000\ncserver.exe\nLEXAMPLE\\alice\n"
    "f72\nau\ntIPv4\niTCP\nPTCP\nTST=LISTEN\nn*:445 (LISTEN)\n"
    "f88\nau\ntIPv4\niTCP\nPTCP\nTST=ESTABLISHED\n"
    "n127.0.0.1:445->127.0.0.1:51000 (ESTABLISHED)\n"
    "f96\nau\ntIPv6\niUDP\nPUDP\nn[::]:53\n"
)

# --- the OS oracle's view of the same three sockets -------------------------
ORACLE = json.dumps([
    {"proto": "TCP", "family": "IPv4", "local_addr": "0.0.0.0", "local_port": 445,
     "remote_addr": "0.0.0.0", "remote_port": 0, "state": "Listen", "pid": 1500},
    {"proto": "TCP", "family": "IPv4", "local_addr": "127.0.0.1", "local_port": 445,
     "remote_addr": "127.0.0.1", "remote_port": 51000, "state": "Established", "pid": 1500},
    {"proto": "UDP", "family": "IPv6", "local_addr": "::", "local_port": 53,
     "remote_addr": None, "remote_port": None, "state": None, "pid": 1500},
])


class ParserAgreement(unittest.TestCase):
    def test_json_and_fields_parse_to_same_rows(self):
        j = sorted(od.parse_winlsof_json(WINLSOF_JSON))
        f = sorted(od.parse_winlsof_fields(WINLSOF_FIELDS))
        self.assertEqual(j, f, "JSON and -F parsers must agree on the same data")
        self.assertEqual(len(j), 3)

    def test_json_row_fields(self):
        rows = {r.state: r for r in od.parse_winlsof_json(WINLSOF_JSON)}
        self.assertEqual(rows["LISTEN"].local, "*:445")      # 0.0.0.0 -> *
        self.assertEqual(rows["LISTEN"].remote, "-")          # listener has no peer
        self.assertEqual(rows["ESTABLISHED"].remote, "127.0.0.1:51000")
        self.assertEqual(rows["-"].proto, "UDP")              # UDP: no state
        self.assertEqual(rows["-"].local, "*:53")             # [::] -> *
        self.assertEqual(rows["-"].family, "IPv6")


class SetEquivalence(unittest.TestCase):
    def test_match_json(self):
        m, e, n = od.diff(od.parse_winlsof_json(WINLSOF_JSON), od.parse_oracle_json(ORACLE))
        self.assertEqual((m, e), ([], []), "identical socket sets must match")

    def test_match_fields(self):
        m, e, n = od.diff(od.parse_winlsof_fields(WINLSOF_FIELDS), od.parse_oracle_json(ORACLE))
        self.assertEqual((m, e), ([], []))

    def test_missing_row_is_caught(self):
        # winlsof drops the UDP socket -> oracle has one winlsof lacks.
        oracle = od.parse_oracle_json(ORACLE)
        winlsof = [r for r in od.parse_winlsof_json(WINLSOF_JSON) if r.proto != "UDP"]
        m, e, n = od.diff(winlsof, oracle)
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0][0].proto, "UDP")
        self.assertEqual(e, [])

    def test_extra_row_is_caught(self):
        # winlsof invents a socket the OS does not report.
        winlsof = od.parse_winlsof_json(WINLSOF_JSON)
        m, e, n = od.diff(winlsof, od.parse_oracle_json(ORACLE)[:2])  # oracle missing UDP
        self.assertEqual(len(e), 1)
        self.assertEqual(e[0][0].proto, "UDP")

    def test_misclassified_state_is_caught(self):
        # winlsof reports ESTABLISHED where the OS says CLOSE_WAIT: both a
        # missing (the true row) and an extra (the wrong row).
        oracle = json.loads(ORACLE)
        oracle[1]["state"] = "CloseWait"
        m, e, n = od.diff(od.parse_winlsof_json(WINLSOF_JSON),
                          od.parse_oracle_json(json.dumps(oracle)))
        self.assertEqual(len(m), 1)
        self.assertEqual(len(e), 1)
        self.assertEqual(m[0][0].state, "CLOSE_WAIT")
        self.assertEqual(e[0][0].state, "ESTABLISHED")


class Scoping(unittest.TestCase):
    def test_scope_ports_restricts(self):
        m, e, n = od.diff(od.parse_winlsof_json(WINLSOF_JSON),
                          od.parse_oracle_json(ORACLE), scope_ports={"53"})
        self.assertEqual((m, e), ([], []))

    def test_scope_pid_restricts(self):
        # An oracle row owned by another pid is out of scope and never compared.
        oracle = json.loads(ORACLE)
        oracle.append({"proto": "TCP", "family": "IPv4", "local_addr": "0.0.0.0",
                       "local_port": 9999, "remote_addr": "0.0.0.0", "remote_port": 0,
                       "state": "Listen", "pid": 4242})
        m, e, n = od.diff(od.parse_winlsof_json(WINLSOF_JSON),
                          od.parse_oracle_json(json.dumps(oracle)), scope_pid=1500)
        self.assertEqual((m, e), ([], []))


class Ledger(unittest.TestCase):
    def test_ledger_suppresses_missing(self):
        oracle = od.parse_oracle_json(ORACLE)
        winlsof = [r for r in od.parse_winlsof_json(WINLSOF_JSON) if r.proto != "UDP"]
        ledger = [{"proto": "UDP", "side": "missing", "reason": "AF_UNIX/UDP gap (known)"}]
        m, e, n = od.diff(winlsof, oracle, ledger=ledger)
        self.assertEqual((m, e), ([], []))
        self.assertEqual(len(n), 1)
        self.assertIn("known", n[0][1])

    def test_ledger_is_specific(self):
        # A ledger for UDP must not silence a TCP divergence.
        oracle = od.parse_oracle_json(ORACLE)
        winlsof = [r for r in od.parse_winlsof_json(WINLSOF_JSON) if r.state != "LISTEN"]
        ledger = [{"proto": "UDP", "side": "missing", "reason": "unrelated"}]
        m, e, n = od.diff(winlsof, oracle, ledger=ledger)
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0][0].state, "LISTEN")


class Canonicalization(unittest.TestCase):
    def test_wildcards_equal(self):
        self.assertEqual(od.canon_addr("0.0.0.0"), "*")
        self.assertEqual(od.canon_addr("::"), "*")
        self.assertEqual(od.canon_addr("[::]"), "*")

    def test_ipv6_zone_and_brackets(self):
        self.assertEqual(od.canon_addr("[fe80::1%12]"), "fe80::1")
        self.assertEqual(od.split_endpoint("[::1]:80"), ("::1", "80"))

    def test_state_folding(self):
        self.assertEqual(od.canon_state("Listen"), "LISTEN")
        self.assertEqual(od.canon_state("LISTEN"), "LISTEN")
        self.assertEqual(od.canon_state("TimeWait"), "TIME_WAIT")
        self.assertEqual(od.canon_state("FinWait2"), "FIN_WAIT2")

    def test_listener_placeholder_peer_is_no_remote(self):
        self.assertEqual(od.canon_remote("0.0.0.0", 0), "-")
        self.assertEqual(od.canon_remote("::", "0"), "-")
        self.assertEqual(od.canon_remote("127.0.0.1", 51000), "127.0.0.1:51000")


if __name__ == "__main__":
    unittest.main(verbosity=2)
