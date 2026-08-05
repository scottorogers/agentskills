#!/usr/bin/env python3
"""A fake SNMP-speaking switch, for demos and tests. Standard library only.

Serves a realistic MIB-II / IF-MIB tree for a 24-port switch with live
counters, so `netmon.py` can be demonstrated end to end with no hardware.

    python3 mock_switch.py --port 11161
    python3 netmon.py check 127.0.0.1:11161

Fault injection lets you show alerting actually firing:

    python3 mock_switch.py --port 11161 --flap 8 --errors 12 --saturate 3
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from snmp import (  # noqa: E402
    T_COUNTER32,
    T_COUNTER64,
    T_ENDOFMIBVIEW,
    T_GAUGE32,
    T_GET,
    T_GETBULK,
    T_GETNEXT,
    T_INTEGER,
    T_OCTETS,
    T_OID,
    T_RESPONSE,
    T_SEQUENCE,
    T_TIMETICKS,
    _dec_oid,
    _dec_tlv,
    _enc_int,
    _enc_oid,
    _tlv,
)

SYS_DESCR = (
    "MockSwitch 24-Port Gigabit Managed Switch, Software Version 3.4.1, "
    "Compiled 2024-11-02"
)
SYS_OBJECT_ID = ".1.3.6.1.4.1.99999.1.24"
SYS_CONTACT = "netops@example.com"
SYS_LOCATION = "Comms Room A, Rack 3"


def _oid(s: str) -> tuple[int, ...]:
    return tuple(int(p) for p in s.strip(". ").split("."))


class MockSwitch:
    def __init__(self, ports=24, name="mock-sw-01", flap=None, errors=None,
                 saturate=None, seed=7, flap_period=90):
        self.ports = ports
        self.name = name
        self.flap_port = flap
        self.flap_period = max(4, flap_period)
        self.error_port = errors
        self.saturate_port = saturate
        self.start = time.time()
        self.rng = random.Random(seed)
        # Per-port state: base rate in bits/s, link status, counters.
        self.iface = {}
        for i in range(1, ports + 1):
            up = i <= ports - 4  # last few ports unplugged, as in real life
            self.iface[i] = {
                "name": f"GigabitEthernet0/{i}",
                "alias": "uplink to core" if i == 1 else "",
                "speed": 1_000_000_000,
                "admin": 1,
                "oper": 1 if up else 2,
                "in_octets": self.rng.randint(10**7, 10**9),
                "out_octets": self.rng.randint(10**7, 10**9),
                "in_err": 0,
                "out_err": 0,
                "in_disc": 0,
                "out_disc": 0,
                "mac": bytes([0x00, 0x1B, 0x2C, 0x00, 0x10, i]),
                "rate": self.rng.uniform(2e6, 6e7) if up else 0.0,
            }
        self.last_tick = time.time()

    # -- simulation ------------------------------------------------------

    def tick(self):
        now = time.time()
        dt = now - self.last_tick
        if dt <= 0:
            return
        self.last_tick = now
        elapsed = now - self.start
        for idx, port in self.iface.items():
            if idx == self.flap_port:
                # Down for the first third of every flap period.
                cycle = elapsed % self.flap_period
                port["oper"] = 2 if cycle < self.flap_period / 3 else 1
            if port["oper"] != 1:
                continue
            rate = port["rate"]
            if idx == self.saturate_port:
                rate = port["speed"] * 0.93
            jitter = self.rng.uniform(0.8, 1.2)
            rate = min(rate * jitter, port["speed"])  # never exceed line rate
            port["in_octets"] += int(rate * dt / 8)
            port["out_octets"] += int(rate * 0.6 * dt / 8)
            if idx == self.error_port:
                port["in_err"] += int(self.rng.uniform(3, 9) * dt)
                port["in_disc"] += int(self.rng.uniform(1, 4) * dt)

    # -- MIB -------------------------------------------------------------

    def mib(self) -> list[tuple[tuple[int, ...], int, object]]:
        self.tick()
        uptime = int((time.time() - self.start) * 100)
        rows: list[tuple[tuple[int, ...], int, object]] = [
            (_oid(".1.3.6.1.2.1.1.1.0"), T_OCTETS, SYS_DESCR.encode()),
            (_oid(".1.3.6.1.2.1.1.2.0"), T_OID, SYS_OBJECT_ID),
            (_oid(".1.3.6.1.2.1.1.3.0"), T_TIMETICKS, uptime),
            (_oid(".1.3.6.1.2.1.1.4.0"), T_OCTETS, SYS_CONTACT.encode()),
            (_oid(".1.3.6.1.2.1.1.5.0"), T_OCTETS, self.name.encode()),
            (_oid(".1.3.6.1.2.1.1.6.0"), T_OCTETS, SYS_LOCATION.encode()),
            (_oid(".1.3.6.1.2.1.1.7.0"), T_INTEGER, 74),
            (_oid(".1.3.6.1.2.1.2.1.0"), T_INTEGER, self.ports),
        ]
        for i, port in sorted(self.iface.items()):
            base = ".1.3.6.1.2.1.2.2.1."
            rows += [
                (_oid(f"{base}1.{i}"), T_INTEGER, i),
                (_oid(f"{base}2.{i}"), T_OCTETS, port["name"].encode()),
                (_oid(f"{base}3.{i}"), T_INTEGER, 6),
                (_oid(f"{base}5.{i}"), T_GAUGE32, port["speed"]),
                (_oid(f"{base}6.{i}"), T_OCTETS, port["mac"]),
                (_oid(f"{base}7.{i}"), T_INTEGER, port["admin"]),
                (_oid(f"{base}8.{i}"), T_INTEGER, port["oper"]),
                (_oid(f"{base}10.{i}"), T_COUNTER32, port["in_octets"] % 2**32),
                (_oid(f"{base}13.{i}"), T_COUNTER32, port["in_disc"] % 2**32),
                (_oid(f"{base}14.{i}"), T_COUNTER32, port["in_err"] % 2**32),
                (_oid(f"{base}16.{i}"), T_COUNTER32, port["out_octets"] % 2**32),
                (_oid(f"{base}19.{i}"), T_COUNTER32, port["out_disc"] % 2**32),
                (_oid(f"{base}20.{i}"), T_COUNTER32, port["out_err"] % 2**32),
            ]
        for i, port in sorted(self.iface.items()):
            x = ".1.3.6.1.2.1.31.1.1.1."
            rows += [
                (_oid(f"{x}1.{i}"), T_OCTETS, port["name"].encode()),
                (_oid(f"{x}6.{i}"), T_COUNTER64, port["in_octets"]),
                (_oid(f"{x}10.{i}"), T_COUNTER64, port["out_octets"]),
                (_oid(f"{x}15.{i}"), T_GAUGE32, port["speed"] // 1_000_000),
                (_oid(f"{x}18.{i}"), T_OCTETS, port["alias"].encode()),
            ]
        rows.sort(key=lambda r: r[0])
        return rows

    # -- protocol --------------------------------------------------------

    def _encode_value(self, tag: int, value) -> bytes:
        if tag == T_OCTETS:
            return _tlv(T_OCTETS, value)
        if tag == T_OID:
            return _enc_oid(value)
        if tag in (T_INTEGER, T_COUNTER32, T_COUNTER64, T_GAUGE32, T_TIMETICKS):
            return _enc_int(value, tag)
        raise ValueError(f"unhandled tag {tag}")

    def handle(self, data: bytes, community: str) -> bytes | None:
        try:
            _, body, _ = _dec_tlv(data, 0)
            pos = 0
            _, ver_raw, pos = _dec_tlv(body, pos)
            _, comm, pos = _dec_tlv(body, pos)
            if comm.decode(errors="replace") != community:
                return None  # real agents stay silent on a bad community
            pdu_tag, pdu, _ = _dec_tlv(body, pos)
            ppos = 0
            _, rid_raw, ppos = _dec_tlv(pdu, ppos)
            _, a_raw, ppos = _dec_tlv(pdu, ppos)
            _, b_raw, ppos = _dec_tlv(pdu, ppos)
            _, vb_blob, ppos = _dec_tlv(pdu, ppos)
        except Exception:
            return None

        request_id = int.from_bytes(rid_raw, "big", signed=True) if rid_raw else 0
        max_reps = int.from_bytes(b_raw, "big") if b_raw else 0
        non_rep = int.from_bytes(a_raw, "big") if a_raw else 0

        requested: list[tuple[int, ...]] = []
        vpos = 0
        while vpos < len(vb_blob):
            _, one, vpos = _dec_tlv(vb_blob, vpos)
            opos = 0
            _, oid_raw, opos = _dec_tlv(one, opos)
            requested.append(_oid(_dec_oid(oid_raw)))

        mib = self.mib()
        out: list[bytes] = []

        def emit(oid_t, tag, value):
            out.append(
                _tlv(
                    T_SEQUENCE,
                    _enc_oid("." + ".".join(map(str, oid_t)))
                    + self._encode_value(tag, value),
                )
            )

        def next_after(oid_t):
            for row in mib:
                if row[0] > oid_t:
                    return row
            return None

        if pdu_tag == T_GET:
            for oid_t in requested:
                match = next((r for r in mib if r[0] == oid_t), None)
                if match is None:
                    out.append(
                        _tlv(
                            T_SEQUENCE,
                            _enc_oid("." + ".".join(map(str, oid_t)))
                            + _tlv(0x80, b""),  # noSuchObject
                        )
                    )
                else:
                    emit(*match)
        elif pdu_tag == T_GETNEXT:
            for oid_t in requested:
                row = next_after(oid_t)
                if row is None:
                    out.append(
                        _tlv(
                            T_SEQUENCE,
                            _enc_oid("." + ".".join(map(str, oid_t)))
                            + _tlv(T_ENDOFMIBVIEW, b""),
                        )
                    )
                else:
                    emit(*row)
        elif pdu_tag == T_GETBULK:
            for oid_t in requested[:non_rep]:
                row = next_after(oid_t)
                if row:
                    emit(*row)
            for oid_t in requested[non_rep:]:
                cursor = oid_t
                for _ in range(max(0, max_reps)):
                    row = next_after(cursor)
                    if row is None:
                        out.append(
                            _tlv(
                                T_SEQUENCE,
                                _enc_oid("." + ".".join(map(str, cursor)))
                                + _tlv(T_ENDOFMIBVIEW, b""),
                            )
                        )
                        break
                    emit(*row)
                    cursor = row[0]
        else:
            return None

        resp_pdu = _tlv(
            T_RESPONSE,
            _enc_int(request_id)
            + _enc_int(0)
            + _enc_int(0)
            + _tlv(T_SEQUENCE, b"".join(out)),
        )
        return _tlv(
            T_SEQUENCE, _enc_int(1) + _tlv(T_OCTETS, community.encode()) + resp_pdu
        )


def serve(host, port, community, switch, quiet=False):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    if not quiet:
        print(
            f"mock switch '{switch.name}' listening on {host}:{port} "
            f"(community '{community}', {switch.ports} ports)",
            flush=True,
        )
    try:
        while True:
            data, addr = sock.recvfrom(65535)
            reply = switch.handle(data, community)
            if reply:
                sock.sendto(reply, addr)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=11161)
    ap.add_argument("--community", default="public")
    ap.add_argument("--ports", type=int, default=24)
    ap.add_argument("--name", default="mock-sw-01")
    ap.add_argument("--flap", type=int, metavar="PORT",
                    help="port index that flaps up/down repeatedly")
    ap.add_argument("--flap-period", type=float, default=90,
                    help="seconds per flap cycle (default 90)")
    ap.add_argument("--errors", type=int, metavar="PORT",
                    help="port index that accumulates input errors")
    ap.add_argument("--saturate", type=int, metavar="PORT",
                    help="port index running at ~93%% of link speed")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    switch = MockSwitch(
        ports=args.ports, name=args.name, flap=args.flap,
        errors=args.errors, saturate=args.saturate,
        flap_period=args.flap_period,
    )
    serve(args.host, args.port, args.community, switch, args.quiet)


if __name__ == "__main__":
    main()
