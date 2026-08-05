#!/usr/bin/env python3
"""Test suite for the SNMP monitoring skill. Standard library only.

    python3 tests/test_netmon.py

Covers BER encoding, RFC 3414 key derivation against the published test
vectors, counter-wrap arithmetic, a live end-to-end poll against the bundled
mock switch, and the alert state machine.
"""

import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import mock_switch  # noqa: E402
import netmon  # noqa: E402
import snmp  # noqa: E402


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class TestBER(unittest.TestCase):
    def test_oid_roundtrip(self):
        for oid in (
            ".1.3.6.1.2.1.1.1.0",
            ".1.3.6.1.2.1.2.2.1.10.4294967295",
            ".1.3.6.1.4.1.9.9.109.1.1.1.1.8.1",
            ".1.0",
        ):
            _, body, _ = snmp._dec_tlv(snmp._enc_oid(oid), 0)
            self.assertEqual(snmp._dec_oid(body), oid)

    def test_multibyte_subidentifiers(self):
        # Sub-identifiers above 127 use base-128 continuation bytes.
        _, body, _ = snmp._dec_tlv(snmp._enc_oid(".1.3.6.1.4.1.2011.5.25.31"), 0)
        self.assertEqual(snmp._dec_oid(body), ".1.3.6.1.4.1.2011.5.25.31")

    def test_integer_roundtrip(self):
        for value in (0, 1, 127, 128, 255, -1, -128, 2**31 - 1):
            tag, body, _ = snmp._dec_tlv(snmp._enc_int(value), 0)
            self.assertEqual(snmp._dec_value(snmp.T_INTEGER, body), value)

    def test_unsigned_high_bit_not_negative(self):
        # A Counter32 of 4294967295 must not decode as -1.
        _, body, _ = snmp._dec_tlv(snmp._enc_int(2**32 - 1, snmp.T_COUNTER32), 0)
        self.assertEqual(snmp._dec_value(snmp.T_COUNTER32, body), 2**32 - 1)
        _, body, _ = snmp._dec_tlv(snmp._enc_int(2**64 - 1, snmp.T_COUNTER64), 0)
        self.assertEqual(snmp._dec_value(snmp.T_COUNTER64, body), 2**64 - 1)

    def test_long_form_length(self):
        payload = b"x" * 500
        encoded = snmp._tlv(snmp.T_OCTETS, payload)
        tag, body, end = snmp._dec_tlv(encoded, 0)
        self.assertEqual(body, payload)
        self.assertEqual(end, len(encoded))

    def test_truncated_message_raises(self):
        with self.assertRaises(snmp.SnmpError):
            snmp._dec_tlv(b"\x30\x82\x01", 0)


class TestUsmKeys(unittest.TestCase):
    """Official test vectors from RFC 3414 appendix A.3."""

    ENGINE = bytes.fromhex("000000000000000000000002")

    def test_md5_localized_key(self):
        self.assertEqual(
            snmp.password_to_key("maplesyrup", self.ENGINE, "MD5").hex(),
            "526f5eed9fcce26f8964c2930787d82b",
        )

    def test_sha1_localized_key(self):
        self.assertEqual(
            snmp.password_to_key("maplesyrup", self.ENGINE, "SHA").hex(),
            "6695febc9288e36282235fc7151f128497b38f3f",
        )

    def test_empty_password_rejected(self):
        with self.assertRaises(snmp.SnmpError):
            snmp.password_to_key("", self.ENGINE, "SHA")

    def test_unknown_protocol_rejected(self):
        with self.assertRaises(snmp.SnmpError):
            snmp.password_to_key("secret", self.ENGINE, "SHA3")


class TestCounterDelta(unittest.TestCase):
    def test_normal_increase(self):
        self.assertEqual(netmon.counter_delta(100, 250, 64), 150)

    def test_32bit_wrap(self):
        # 1 Gb/s saturates a 32-bit octet counter in ~34s, so wraps are routine.
        delta = netmon.counter_delta(2**32 - 100, 50, 32, max_plausible=10_000)
        self.assertEqual(delta, 150)

    def test_reset_is_discarded_not_reported_as_a_spike(self):
        # Agent restarted: counter went 4e9 -> 5. Treating that as a wrap would
        # invent a ~4 GB burst, so it must be discarded instead.
        self.assertIsNone(
            netmon.counter_delta(4_000_000_000, 5, 32, max_plausible=1_000_000)
        )

    def test_missing_previous_sample(self):
        self.assertIsNone(netmon.counter_delta(None, 500, 64))

    def test_64bit_counters_do_not_need_a_wrap_guard(self):
        self.assertEqual(netmon.counter_delta(2**63, 2**63 + 42, 64), 42)


class TestHelpers(unittest.TestCase):
    def test_human_bps(self):
        self.assertEqual(netmon.human_bps(1_500_000_000), "1.50 Gb/s")
        self.assertEqual(netmon.human_bps(2_500_000), "2.50 Mb/s")
        self.assertEqual(netmon.human_bps(None), "-")

    def test_human_uptime(self):
        self.assertEqual(netmon.human_uptime(100 * 86400 * 3), "3d 0h 0m")
        self.assertEqual(netmon.human_uptime(None), "-")

    def test_ignore_patterns(self):
        patterns = netmon.DEFAULT_CONFIG["ignore_ports"]
        self.assertTrue(netmon.ignored("Vlan100", patterns))
        self.assertTrue(netmon.ignored("GigabitEthernet0/1.200", patterns))
        self.assertFalse(netmon.ignored("GigabitEthernet0/1", patterns))

    def test_env_expansion(self):
        import os

        os.environ["NETMON_TEST_SECRET"] = "s3cret"
        self.assertEqual(
            netmon.expand_env({"community": "${NETMON_TEST_SECRET}"}),
            {"community": "s3cret"},
        )

    def test_missing_env_var_is_a_clear_error(self):
        with self.assertRaises(SystemExit):
            netmon.expand_env("${NETMON_DEFINITELY_NOT_SET}")


class TestAgainstMockSwitch(unittest.TestCase):
    """End-to-end over a real UDP socket against the bundled fake switch."""

    @classmethod
    def setUpClass(cls):
        cls.port = free_port()
        cls.switch = mock_switch.MockSwitch(ports=12, name="test-sw")
        cls.thread = threading.Thread(
            target=mock_switch.serve,
            args=("127.0.0.1", cls.port, "testcomm", cls.switch),
            kwargs={"quiet": True},
            daemon=True,
        )
        cls.thread.start()
        time.sleep(0.3)
        cls.target = f"127.0.0.1:{cls.port}"

    def session(self, **kwargs):
        kwargs.setdefault("community", "testcomm")
        kwargs.setdefault("timeout", 2.0)
        return snmp.Session(self.target, **kwargs)

    def test_get_system_group(self):
        with self.session() as session:
            result = session.get(["1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.3.0"])
            self.assertEqual(result["1.3.6.1.2.1.1.5.0"].text(), "test-sw")
            self.assertEqual(result["1.3.6.1.2.1.1.3.0"].type, "TimeTicks")

    def test_walk_returns_every_row_and_stops_at_subtree_edge(self):
        with self.session() as session:
            rows = session.walk("1.3.6.1.2.1.2.2.1.2")
            self.assertEqual(len(rows), 12)
            self.assertTrue(all(r.oid.startswith(".1.3.6.1.2.1.2.2.1.2.")
                                for r in rows))

    def test_getnext_walk_matches_getbulk_walk(self):
        with self.session(version="2c") as bulk, self.session(version="1") as slow:
            self.assertEqual(
                [(r.oid, r.text()) for r in bulk.walk("1.3.6.1.2.1.2.2.1.2")],
                [(r.oid, r.text()) for r in slow.walk("1.3.6.1.2.1.2.2.1.2")],
            )

    def test_high_capacity_counters_are_64_bit(self):
        with self.session() as session:
            rows = session.walk("1.3.6.1.2.1.31.1.1.1.6")
            self.assertEqual(len(rows), 12)
            self.assertEqual(rows[0].type, "Counter64")

    def test_table_join_by_index(self):
        with self.session() as session:
            rows = session.walk_table(
                {"name": "1.3.6.1.2.1.2.2.1.2", "oper": "1.3.6.1.2.1.2.2.1.8"}
            )
            self.assertEqual(len(rows), 12)
            self.assertEqual(rows["1"]["name"].text(), "GigabitEthernet0/1")
            self.assertIn(rows["1"]["oper"].value, (1, 2))

    def test_unsupported_oid_returns_none_not_an_exception(self):
        with self.session() as session:
            self.assertIsNone(session.get_one("1.3.6.1.2.1.99.99.99.0"))

    def test_wrong_community_times_out(self):
        with self.session(community="wrong", timeout=0.4, retries=0) as session:
            with self.assertRaises(snmp.SnmpTimeout):
                session.get(["1.3.6.1.2.1.1.5.0"])

    def test_poll_device_collects_ports(self):
        snapshot = netmon.poll_device(
            {"host": self.target, "community": "testcomm"}, netmon.DEFAULT_CONFIG
        )
        self.assertTrue(snapshot["reachable"])
        self.assertEqual(len(snapshot["ports"]), 12)
        self.assertEqual(snapshot["ports"][0]["counter_bits"], 64)
        self.assertIsNotNone(snapshot["system"]["descr"])

    def test_poll_of_dead_host_reports_error_without_raising(self):
        snapshot = netmon.poll_device(
            {"host": f"127.0.0.1:{free_port()}", "community": "x",
             "timeout": 0.4, "retries": 0},
            netmon.DEFAULT_CONFIG,
        )
        self.assertFalse(snapshot["reachable"])
        self.assertIsInstance(snapshot["error"], str)


@unittest.skipUnless(
    shutil.which("snmpd"), "net-snmp not installed; skipping interoperability tests"
)
class TestInteropWithNetSnmp(unittest.TestCase):
    """Validate against a real net-snmp agent, not just our own simulator.

    Self-consistent tests cannot catch a message we encode wrongly but also
    decode wrongly, so these run against the reference implementation.
    Skipped automatically when snmpd is unavailable.
    """

    AUTH = "AuthPassphrase123"
    PRIV = "PrivPassphrase123"

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="netmon-interop-")
        cls.port = free_port()
        conf = Path(cls.tmp) / "snmpd.conf"
        conf.write_text(
            "rocommunity testcomm 127.0.0.1\n"
            f'createUser authonly SHA "{cls.AUTH}"\n'
            "rouser authonly auth\n"
            f'createUser authpriv SHA "{cls.AUTH}" AES "{cls.PRIV}"\n'
            "rouser authpriv priv\n"
            'sysLocation "Comms Room A"\n'
        )
        persist = Path(cls.tmp) / "persist"
        persist.mkdir()
        cls.proc = subprocess.Popen(
            ["snmpd", "-f", "-Lo", "-C", "-c", str(conf),
             f"--persistentDir={persist}",
             f"udp:127.0.0.1:{cls.port}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.target = f"127.0.0.1:{cls.port}"
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                with snmp.Session(cls.target, community="testcomm",
                                  timeout=0.5, retries=0) as probe:
                    probe.get(["1.3.6.1.2.1.1.6.0"])
                    return
            except snmp.SnmpError:
                time.sleep(0.3)
        raise unittest.SkipTest("snmpd did not become ready")

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def location(self, **kwargs):
        with snmp.Session(self.target, timeout=3, retries=1, **kwargs) as session:
            return session.get_one("1.3.6.1.2.1.1.6.0").text()

    def test_v2c(self):
        self.assertIn("Comms Room A", self.location(community="testcomm"))

    def test_v1(self):
        self.assertIn("Comms Room A", self.location(community="testcomm",
                                                    version="1"))

    def test_v3_auth_no_priv(self):
        self.assertIn("Comms Room A", self.location(
            version="3", username="authonly", auth_proto="SHA",
            auth_pass=self.AUTH))

    def test_v3_auth_priv_aes(self):
        # 'cryptography' being importable is not enough -- a broken build
        # (missing _cffi_backend, ABI mismatch) imports and then fails.
        try:
            snmp._load_cipher("AES")(b"\x00" * 16, b"\x00" * 16, b"probe", True)
        except snmp.SnmpError as exc:
            self.skipTest(f"AES privacy unavailable: {exc}")
        self.assertIn("Comms Room A", self.location(
            version="3", username="authpriv", auth_proto="SHA",
            auth_pass=self.AUTH, priv_proto="AES", priv_pass=self.PRIV))

    def test_v3_wrong_password_is_reported_clearly(self):
        with self.assertRaises(snmp.SnmpAuthError) as ctx:
            self.location(version="3", username="authonly", auth_proto="SHA",
                          auth_pass="TotallyWrongPassphrase")
        self.assertIn("digest", str(ctx.exception))

    def test_v3_unknown_user_is_reported_clearly(self):
        with self.assertRaises(snmp.SnmpAuthError) as ctx:
            self.location(version="3", username="nosuchuser", auth_proto="SHA",
                          auth_pass=self.AUTH)
        self.assertIn("user name", str(ctx.exception))

    def test_bulk_walk_matches_reference_client(self):
        """Our GETBULK walk must return what snmpbulkwalk returns."""
        if not shutil.which("snmpbulkwalk"):
            self.skipTest("snmpbulkwalk not available")
        output = subprocess.run(
            ["snmpbulkwalk", "-v2c", "-c", "testcomm", "-On", self.target,
             "1.3.6.1.2.1.2.2.1.2"],
            capture_output=True, text=True, timeout=30,
        ).stdout.strip().splitlines()
        reference = [line.split(" = ")[0].strip() for line in output if line]
        with snmp.Session(self.target, community="testcomm") as session:
            ours = [r.oid for r in session.walk("1.3.6.1.2.1.2.2.1.2")]
        self.assertEqual(ours, reference)

    def test_netmon_poll_against_real_agent(self):
        snapshot = netmon.poll_device(
            {"host": self.target, "community": "testcomm"}, netmon.DEFAULT_CONFIG
        )
        self.assertTrue(snapshot["reachable"], snapshot["error"])
        self.assertGreater(len(snapshot["ports"]), 0)


class TestAlertStateMachine(unittest.TestCase):
    def setUp(self):
        self.conn = netmon.open_db(Path(":memory:"))
        self.config = netmon.deep_merge(netmon.DEFAULT_CONFIG, {})

    def snapshot(self, ts, oper=1, in_octets=0, out_octets=0, errors=0, uptime=10**6):
        return {
            "host": "sw1", "ts": ts, "reachable": True, "error": None,
            "rtt_ms": 5.0,
            "system": {"name": "sw1", "descr": "test", "uptime": uptime,
                       "location": "lab"},
            "ports": [{
                "ifindex": 1, "name": "Gi0/1", "alias": "", "admin": 1,
                "oper": oper, "speed_bps": 1_000_000_000,
                "in_octets": in_octets, "out_octets": out_octets,
                "counter_bits": 64, "in_errors": errors, "out_errors": 0,
                "in_discards": 0, "out_discards": 0,
            }],
        }

    def test_port_down_transition_opens_and_recovery_closes(self):
        netmon.store_and_evaluate(self.conn, self.snapshot(1000, oper=1), self.config)
        alerts = netmon.store_and_evaluate(
            self.conn, self.snapshot(1060, oper=2), self.config
        )
        self.assertEqual([a["kind"] for a in alerts], ["port_down"])
        self.assertEqual(alerts[0]["severity"], "critical")

        # Still down: must not re-notify.
        again = netmon.store_and_evaluate(
            self.conn, self.snapshot(1120, oper=2), self.config
        )
        self.assertEqual(again, [])

        recovered = netmon.store_and_evaluate(
            self.conn, self.snapshot(1180, oper=1), self.config
        )
        self.assertEqual(recovered[0]["state"], "resolved")

    def test_port_down_at_first_sight_is_not_alerted_by_default(self):
        alerts = netmon.store_and_evaluate(
            self.conn, self.snapshot(1000, oper=2), self.config
        )
        self.assertEqual(alerts, [])

    def test_utilization_alert_uses_computed_rate(self):
        # 60s apart, 7 GB transferred = ~933 Mb/s on a 1 Gb/s port.
        netmon.store_and_evaluate(self.conn, self.snapshot(1000), self.config)
        alerts = netmon.store_and_evaluate(
            self.conn, self.snapshot(1060, in_octets=7_000_000_000), self.config
        )
        kinds = [a["kind"] for a in alerts]
        self.assertIn("high_utilization", kinds)
        row = self.conn.execute(
            "SELECT util_pct, in_bps FROM port_samples ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        self.assertAlmostEqual(row["in_bps"], 7_000_000_000 * 8 / 60, delta=1)
        self.assertLessEqual(row["util_pct"], 100.0)

    def test_error_rate_alert(self):
        netmon.store_and_evaluate(self.conn, self.snapshot(1000), self.config)
        alerts = netmon.store_and_evaluate(
            self.conn, self.snapshot(1060, errors=100), self.config
        )
        self.assertIn("errors", [a["kind"] for a in alerts])

    def test_device_unreachable_needs_consecutive_failures(self):
        down = {"host": "sw1", "ts": 0, "reachable": False, "error": "timeout",
                "rtt_ms": 2000.0, "system": {}, "ports": []}
        for i in range(1, 3):
            self.assertEqual(
                netmon.store_and_evaluate(self.conn, {**down, "ts": i}, self.config),
                [],
                f"alerted too early at failure {i}",
            )
        alerts = netmon.store_and_evaluate(self.conn, {**down, "ts": 3}, self.config)
        self.assertEqual([a["kind"] for a in alerts], ["unreachable"])

        back = netmon.store_and_evaluate(self.conn, self.snapshot(4), self.config)
        self.assertEqual(back[0]["state"], "resolved")

    def test_restart_detected_from_uptime_going_backwards(self):
        netmon.store_and_evaluate(
            self.conn, self.snapshot(1000, uptime=50_000_000), self.config
        )
        alerts = netmon.store_and_evaluate(
            self.conn, self.snapshot(1060, uptime=500), self.config
        )
        self.assertIn("restart", [a["kind"] for a in alerts])


if __name__ == "__main__":
    unittest.main(verbosity=2)
