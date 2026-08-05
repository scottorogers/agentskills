#!/usr/bin/env python3
"""netmon - SNMP switch monitoring with no dependencies to install.

    python3 netmon.py check 10.0.0.1                  one-off health check
    python3 netmon.py discover 10.0.0.0/24            find switches, write config
    python3 netmon.py poll                            one polling cycle
    python3 netmon.py watch                           poll + alert continuously
    python3 netmon.py report --out dashboard.html     self-contained dashboard
    python3 netmon.py events                          recent alerts

Everything is Python standard library. State lives in a SQLite file.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fnmatch
import html
import ipaddress
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from snmp import Session, SnmpAuthError, SnmpError, SnmpTimeout  # noqa: E402

# --------------------------------------------------------------------------
# OIDs
# --------------------------------------------------------------------------

SYS = {
    "descr": "1.3.6.1.2.1.1.1.0",
    "object_id": "1.3.6.1.2.1.1.2.0",
    "uptime": "1.3.6.1.2.1.1.3.0",
    "contact": "1.3.6.1.2.1.1.4.0",
    "name": "1.3.6.1.2.1.1.5.0",
    "location": "1.3.6.1.2.1.1.6.0",
}

IF_COLUMNS = {
    "descr": "1.3.6.1.2.1.2.2.1.2",
    "speed": "1.3.6.1.2.1.2.2.1.5",
    "admin": "1.3.6.1.2.1.2.2.1.7",
    "oper": "1.3.6.1.2.1.2.2.1.8",
    "in_octets32": "1.3.6.1.2.1.2.2.1.10",
    "in_discards": "1.3.6.1.2.1.2.2.1.13",
    "in_errors": "1.3.6.1.2.1.2.2.1.14",
    "out_octets32": "1.3.6.1.2.1.2.2.1.16",
    "out_discards": "1.3.6.1.2.1.2.2.1.19",
    "out_errors": "1.3.6.1.2.1.2.2.1.20",
}

IFX_COLUMNS = {
    "name": "1.3.6.1.2.1.31.1.1.1.1",
    "in_octets": "1.3.6.1.2.1.31.1.1.1.6",
    "out_octets": "1.3.6.1.2.1.31.1.1.1.10",
    "high_speed": "1.3.6.1.2.1.31.1.1.1.15",
    "alias": "1.3.6.1.2.1.31.1.1.1.18",
}

OPER_STATUS = {
    1: "up", 2: "down", 3: "testing", 4: "unknown",
    5: "dormant", 6: "notPresent", 7: "lowerLayerDown",
}
ADMIN_STATUS = {1: "up", 2: "down", 3: "testing"}

DEFAULT_CONFIG = {
    "defaults": {
        "version": "2c",
        "community": "public",
        "port": 161,
        "timeout": 2.0,
        "retries": 2,
        "interval": 60,
    },
    "thresholds": {
        "utilization_pct": 80.0,
        "errors_per_min": 10.0,
        "discards_per_min": 50.0,
        "unreachable_polls": 3,
    },
    "alerts": {
        "log": "netmon-alerts.log",
        "webhook": None,
        "command": None,
        "alert_on_down_at_start": False,
    },
    "retention_days": 30,
    "ignore_ports": ["Vlan*", "Null*", "Loopback*", "*.[0-9]*"],
    "devices": [],
}

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def now_ts() -> float:
    return time.time()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def human_bps(bps: float | None) -> str:
    if bps is None:
        return "-"
    for unit, scale in (("Gb/s", 1e9), ("Mb/s", 1e6), ("kb/s", 1e3)):
        if bps >= scale:
            return f"{bps / scale:.2f} {unit}"
    return f"{bps:.0f} b/s"


def human_uptime(ticks: int | None) -> str:
    if not ticks:
        return "-"
    seconds = ticks // 100
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def expand_env(value):
    """Allow ${VAR} in config strings so secrets stay out of the file."""
    if isinstance(value, str):
        def sub(match):
            name = match.group(1)
            if name not in os.environ:
                raise SystemExit(
                    f"config references ${{{name}}} but that environment "
                    f"variable is not set"
                )
            return os.environ[name]
        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", sub, value)
    if isinstance(value, dict):
        return {k: expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v) for v in value]
    return value


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path | None) -> dict:
    if path is None:
        env = os.environ.get("NETMON_CONFIG")
        path = Path(env) if env else Path("netmon.json")
    if not path.exists():
        return deep_merge(DEFAULT_CONFIG, {"_path": str(path), "_missing": True})
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"{path}: invalid JSON - {exc}")
    config = deep_merge(DEFAULT_CONFIG, expand_env(raw))
    config["_path"] = str(path)
    config["_missing"] = False
    mode = path.stat().st_mode & 0o077
    if mode and os.name != "nt":
        print(
            f"warning: {path} is readable by other users and holds SNMP "
            f"credentials; run: chmod 600 {path}",
            file=sys.stderr,
        )
    return config


def session_for(device: dict, defaults: dict) -> Session:
    merged = {**defaults, **{k: v for k, v in device.items() if v is not None}}
    return Session(
        host=device["host"],
        port=int(merged.get("port", 161)),
        version=str(merged.get("version", "2c")),
        community=merged.get("community", "public"),
        timeout=float(merged.get("timeout", 2.0)),
        retries=int(merged.get("retries", 2)),
        username=merged.get("username", "") or "",
        auth_proto=merged.get("auth_proto"),
        auth_pass=merged.get("auth_pass"),
        priv_proto=merged.get("priv_proto"),
        priv_pass=merged.get("priv_pass"),
        context=merged.get("context", "") or "",
    )


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    host TEXT PRIMARY KEY, name TEXT, descr TEXT, location TEXT,
    first_seen REAL, last_seen REAL, last_ok REAL, fail_streak INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS device_samples (
    host TEXT, ts REAL, reachable INTEGER, uptime INTEGER, rtt_ms REAL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS ix_dev_samples ON device_samples(host, ts);
CREATE TABLE IF NOT EXISTS port_samples (
    host TEXT, ifindex INTEGER, ts REAL, name TEXT, alias TEXT,
    admin INTEGER, oper INTEGER, speed_bps INTEGER,
    in_octets INTEGER, out_octets INTEGER,
    in_errors INTEGER, out_errors INTEGER,
    in_discards INTEGER, out_discards INTEGER,
    in_bps REAL, out_bps REAL, util_pct REAL,
    err_per_min REAL, disc_per_min REAL
);
CREATE INDEX IF NOT EXISTS ix_port_samples ON port_samples(host, ifindex, ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT, ifindex INTEGER, kind TEXT, severity TEXT, message TEXT,
    opened_ts REAL, closed_ts REAL
);
CREATE INDEX IF NOT EXISTS ix_events_open ON events(host, kind, ifindex, closed_ts);
"""


def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# --------------------------------------------------------------------------
# Polling
# --------------------------------------------------------------------------


def counter_delta(prev: int | None, cur: int | None, bits: int, max_plausible=None):
    """Delta across a possible counter wrap. None when the value is unusable."""
    if prev is None or cur is None:
        return None
    if cur >= prev:
        return cur - prev
    # Counter went backwards: either a wrap or an agent/counter reset.
    wrapped = cur + (1 << bits) - prev
    if max_plausible is not None and wrapped > max_plausible:
        return None  # reset, not a wrap - discard rather than invent a spike
    return wrapped


def ignored(name: str, patterns) -> bool:
    return any(fnmatch.fnmatch(name, pat) for pat in patterns)


def poll_device(device: dict, config: dict) -> dict:
    """Collect one snapshot from a device. Never raises for network problems."""
    defaults = config["defaults"]
    started = time.monotonic()
    result = {
        "host": device["host"],
        "ts": now_ts(),
        "reachable": False,
        "error": None,
        "system": {},
        "ports": [],
    }
    session = None
    try:
        session = session_for(device, defaults)
        system = session.get(list(SYS.values()))
        by_oid = {v: k for k, v in SYS.items()}
        info = {}
        for oid, bind in system.items():
            key = by_oid[oid]
            info[key] = bind.int() if key == "uptime" else bind.text()
        result["system"] = info
        result["reachable"] = True

        rows = session.walk_table(IF_COLUMNS)
        try:
            xrows = session.walk_table(IFX_COLUMNS)
        except SnmpError:
            xrows = {}  # older or cut-down agents lack ifXTable

        patterns = device.get("ignore_ports", config.get("ignore_ports", []))
        for index in sorted(rows, key=lambda i: int(i) if i.isdigit() else 0):
            row = rows[index]
            xrow = xrows.get(index, {})
            name = (
                xrow["name"].text() if "name" in xrow else ""
            ) or (row["descr"].text() if "descr" in row else f"if{index}")
            if ignored(name, patterns):
                continue
            speed = None
            if "high_speed" in xrow and xrow["high_speed"].int():
                speed = xrow["high_speed"].int() * 1_000_000
            elif "speed" in row and row["speed"].int():
                speed = row["speed"].int()

            # 64-bit counters are essential: a 32-bit octet counter wraps in
            # about 34 seconds on a saturated 1G port.
            in_oct = xrow["in_octets"].int() if "in_octets" in xrow else None
            out_oct = xrow["out_octets"].int() if "out_octets" in xrow else None
            bits = 64
            if in_oct is None:
                in_oct = row["in_octets32"].int() if "in_octets32" in row else None
                out_oct = row["out_octets32"].int() if "out_octets32" in row else None
                bits = 32

            result["ports"].append({
                "ifindex": int(index) if index.isdigit() else 0,
                "name": name,
                "alias": xrow["alias"].text() if "alias" in xrow else "",
                "admin": row["admin"].int() if "admin" in row else None,
                "oper": row["oper"].int() if "oper" in row else None,
                "speed_bps": speed,
                "in_octets": in_oct,
                "out_octets": out_oct,
                "counter_bits": bits,
                "in_errors": row["in_errors"].int() if "in_errors" in row else None,
                "out_errors": row["out_errors"].int() if "out_errors" in row else None,
                "in_discards": (
                    row["in_discards"].int() if "in_discards" in row else None
                ),
                "out_discards": (
                    row["out_discards"].int() if "out_discards" in row else None
                ),
            })
    except SnmpAuthError as exc:
        result["error"] = f"authentication: {exc}"
    except SnmpTimeout as exc:
        result["error"] = str(exc)
    except SnmpError as exc:
        result["error"] = str(exc)
    except OSError as exc:
        result["error"] = f"network: {exc}"
    finally:
        if session is not None:
            session.close()
    result["rtt_ms"] = (time.monotonic() - started) * 1000
    return result


def store_and_evaluate(conn: sqlite3.Connection, snapshot: dict, config: dict):
    """Persist a snapshot, derive rates, and return the alerts it triggers."""
    host = snapshot["host"]
    ts = snapshot["ts"]
    thresholds = config["thresholds"]
    alerts: list[dict] = []

    row = conn.execute("SELECT * FROM devices WHERE host=?", (host,)).fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO devices(host, first_seen, last_seen, fail_streak) "
            "VALUES(?,?,?,0)",
            (host, ts, ts),
        )
        row = conn.execute("SELECT * FROM devices WHERE host=?", (host,)).fetchone()

    prev_dev = conn.execute(
        "SELECT * FROM device_samples WHERE host=? ORDER BY ts DESC LIMIT 1", (host,)
    ).fetchone()

    if not snapshot["reachable"]:
        streak = (row["fail_streak"] or 0) + 1
        conn.execute(
            "UPDATE devices SET last_seen=?, fail_streak=? WHERE host=?",
            (ts, streak, host),
        )
        conn.execute(
            "INSERT INTO device_samples(host, ts, reachable, uptime, rtt_ms, error) "
            "VALUES(?,?,0,NULL,?,?)",
            (host, ts, snapshot["rtt_ms"], snapshot["error"]),
        )
        if streak >= int(thresholds["unreachable_polls"]):
            alerts += open_event(
                conn, host, None, "unreachable", "critical",
                f"{host} unreachable ({streak} consecutive failed polls): "
                f"{snapshot['error']}",
                ts,
            )
        return alerts

    system = snapshot["system"]
    conn.execute(
        "UPDATE devices SET name=?, descr=?, location=?, last_seen=?, last_ok=?, "
        "fail_streak=0 WHERE host=?",
        (
            system.get("name"), system.get("descr"), system.get("location"),
            ts, ts, host,
        ),
    )
    conn.execute(
        "INSERT INTO device_samples(host, ts, reachable, uptime, rtt_ms, error) "
        "VALUES(?,?,1,?,?,NULL)",
        (host, ts, system.get("uptime"), snapshot["rtt_ms"]),
    )
    alerts += close_event(conn, host, None, "unreachable", ts,
                          f"{host} is reachable again")

    if prev_dev is not None and prev_dev["reachable"] and prev_dev["uptime"]:
        uptime = system.get("uptime") or 0
        if uptime < prev_dev["uptime"]:
            alerts += point_event(
                conn, host, None, "restart", "warning",
                f"{system.get('name') or host} restarted "
                f"(uptime went from {human_uptime(prev_dev['uptime'])} to "
                f"{human_uptime(uptime)})",
                ts,
            )

    for port in snapshot["ports"]:
        alerts += store_port(conn, host, ts, port, config, system)

    return alerts


def store_port(conn, host, ts, port, config, system) -> list[dict]:
    thresholds = config["thresholds"]
    alerts: list[dict] = []
    idx = port["ifindex"]
    prev = conn.execute(
        "SELECT * FROM port_samples WHERE host=? AND ifindex=? "
        "ORDER BY ts DESC LIMIT 1",
        (host, idx),
    ).fetchone()

    in_bps = out_bps = util = err_min = disc_min = None
    if prev is not None:
        dt = ts - prev["ts"]
        if dt > 0:
            speed = port["speed_bps"] or 0
            cap = (speed / 8) * dt * 1.5 if speed else None
            d_in = counter_delta(
                prev["in_octets"], port["in_octets"], port["counter_bits"], cap
            )
            d_out = counter_delta(
                prev["out_octets"], port["out_octets"], port["counter_bits"], cap
            )
            if d_in is not None:
                in_bps = d_in * 8 / dt
            if d_out is not None:
                out_bps = d_out * 8 / dt
            if speed and in_bps is not None and out_bps is not None:
                # Full duplex: utilisation is the busier direction, not the sum.
                util = max(in_bps, out_bps) / speed * 100
                # Skew between the agent's counter update and our poll clock can
                # push a raw calculation just past 100%. Cap it, as NMS tools do,
                # so operators do not see "112% utilised" and distrust the data.
                util = min(util, 100.0)
            d_err = (counter_delta(prev["in_errors"], port["in_errors"], 32) or 0) + (
                counter_delta(prev["out_errors"], port["out_errors"], 32) or 0
            )
            d_disc = (
                counter_delta(prev["in_discards"], port["in_discards"], 32) or 0
            ) + (counter_delta(prev["out_discards"], port["out_discards"], 32) or 0)
            err_min = d_err * 60 / dt
            disc_min = d_disc * 60 / dt

    conn.execute(
        "INSERT INTO port_samples(host, ifindex, ts, name, alias, admin, oper, "
        "speed_bps, in_octets, out_octets, in_errors, out_errors, in_discards, "
        "out_discards, in_bps, out_bps, util_pct, err_per_min, disc_per_min) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            host, idx, ts, port["name"], port["alias"], port["admin"], port["oper"],
            port["speed_bps"], port["in_octets"], port["out_octets"],
            port["in_errors"], port["out_errors"], port["in_discards"],
            port["out_discards"], in_bps, out_bps, util, err_min, disc_min,
        ),
    )

    label = f"{system.get('name') or host} {port['name']}"
    if port["alias"]:
        label += f" ({port['alias']})"

    admin_up = port["admin"] == 1
    oper_up = port["oper"] == 1
    first_sight = prev is None
    alert_at_start = config["alerts"].get("alert_on_down_at_start", False)

    if admin_up and not oper_up:
        # By default only alert on a real transition. A port that was already
        # down when monitoring started is usually just an empty socket.
        if not first_sight or alert_at_start:
            was_up = prev is not None and prev["oper"] == 1
            if was_up or alert_at_start:
                alerts += open_event(
                    conn, host, idx, "port_down", "critical",
                    f"{label} is DOWN "
                    f"(admin up, oper {OPER_STATUS.get(port['oper'], '?')})",
                    ts,
                )
    elif oper_up:
        alerts += close_event(conn, host, idx, "port_down", ts, f"{label} is back UP")

    if util is not None and util >= float(thresholds["utilization_pct"]):
        alerts += open_event(
            conn, host, idx, "high_utilization", "warning",
            f"{label} at {util:.0f}% utilisation "
            f"(in {human_bps(in_bps)}, out {human_bps(out_bps)})",
            ts,
        )
    elif util is not None:
        alerts += close_event(
            conn, host, idx, "high_utilization", ts,
            f"{label} utilisation back to {util:.0f}%",
        )

    if err_min is not None and err_min >= float(thresholds["errors_per_min"]):
        alerts += open_event(
            conn, host, idx, "errors", "warning",
            f"{label} logging {err_min:.0f} interface errors/min "
            f"(check cabling, duplex, or SFP)",
            ts,
        )
    elif err_min is not None:
        alerts += close_event(conn, host, idx, "errors", ts,
                              f"{label} error rate back to normal")

    if disc_min is not None and disc_min >= float(thresholds["discards_per_min"]):
        alerts += open_event(
            conn, host, idx, "discards", "warning",
            f"{label} discarding {disc_min:.0f} packets/min (congestion)", ts,
        )
    elif disc_min is not None:
        alerts += close_event(conn, host, idx, "discards", ts,
                              f"{label} discards back to normal")
    return alerts


def _find_open(conn, host, ifindex, kind):
    return conn.execute(
        "SELECT * FROM events WHERE host=? AND kind=? AND closed_ts IS NULL "
        "AND ifindex IS ? ORDER BY id DESC LIMIT 1",
        (host, kind, ifindex),
    ).fetchone()


def open_event(conn, host, ifindex, kind, severity, message, ts) -> list[dict]:
    if _find_open(conn, host, ifindex, kind) is not None:
        return []  # already firing; do not re-notify every cycle
    conn.execute(
        "INSERT INTO events(host, ifindex, kind, severity, message, opened_ts) "
        "VALUES(?,?,?,?,?,?)",
        (host, ifindex, kind, severity, message, ts),
    )
    return [{"state": "open", "host": host, "ifindex": ifindex, "kind": kind,
             "severity": severity, "message": message, "ts": ts}]


def close_event(conn, host, ifindex, kind, ts, message) -> list[dict]:
    existing = _find_open(conn, host, ifindex, kind)
    if existing is None:
        return []
    conn.execute("UPDATE events SET closed_ts=? WHERE id=?", (ts, existing["id"]))
    duration = ts - existing["opened_ts"]
    return [{"state": "resolved", "host": host, "ifindex": ifindex, "kind": kind,
             "severity": "info",
             "message": f"{message} (after {int(duration // 60)}m "
                        f"{int(duration % 60)}s)",
             "ts": ts}]


def point_event(conn, host, ifindex, kind, severity, message, ts) -> list[dict]:
    conn.execute(
        "INSERT INTO events(host, ifindex, kind, severity, message, opened_ts, "
        "closed_ts) VALUES(?,?,?,?,?,?,?)",
        (host, ifindex, kind, severity, message, ts, ts),
    )
    return [{"state": "open", "host": host, "ifindex": ifindex, "kind": kind,
             "severity": severity, "message": message, "ts": ts}]


# --------------------------------------------------------------------------
# Notification
# --------------------------------------------------------------------------


def notify(alerts: list[dict], config: dict, quiet=False):
    if not alerts:
        return
    settings = config["alerts"]
    for alert in alerts:
        line = (
            f"[{iso(alert['ts'])}] {alert['severity'].upper():8} "
            f"{alert['state']:8} {alert['message']}"
        )
        if not quiet:
            print(line, flush=True)
        if settings.get("log"):
            try:
                with open(settings["log"], "a") as fh:
                    fh.write(line + "\n")
            except OSError as exc:
                print(f"warning: cannot write alert log: {exc}", file=sys.stderr)
        if settings.get("webhook"):
            post_webhook(settings["webhook"], alert)
        if settings.get("command"):
            run_command(settings["command"], alert)


def post_webhook(url: str, alert: dict):
    payload = json.dumps({
        "text": f"[{alert['severity']}] {alert['message']}",
        **alert,
    }).encode()
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except (urllib.error.URLError, OSError) as exc:
        print(f"warning: webhook delivery failed: {exc}", file=sys.stderr)


def run_command(command: str, alert: dict):
    env = dict(os.environ)
    env.update({
        "NETMON_SEVERITY": alert["severity"],
        "NETMON_STATE": alert["state"],
        "NETMON_HOST": alert["host"],
        "NETMON_KIND": alert["kind"],
        "NETMON_MESSAGE": alert["message"],
        "NETMON_IFINDEX": str(alert["ifindex"] or ""),
    })
    try:
        subprocess.run(shlex.split(command), env=env, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"warning: alert command failed: {exc}", file=sys.stderr)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def build_device(args, config) -> dict:
    device = {"host": args.host}
    for key in ("community", "version", "username", "auth_proto", "auth_pass",
                "priv_proto", "priv_pass", "port", "timeout", "retries"):
        value = getattr(args, key, None)
        if value is not None:
            device[key] = value
    known = {d["host"]: d for d in config.get("devices", [])}
    if args.host in known:
        device = {**known[args.host], **device}
    return device


def cmd_check(args, config):
    """One-off health check against a single device, no config needed."""
    device = build_device(args, config)
    snapshot = poll_device(device, config)
    if args.json:
        print(json.dumps(snapshot, indent=2, default=str))
        return 0 if snapshot["reachable"] else 1

    if not snapshot["reachable"]:
        print(f"FAILED to poll {device['host']}\n  {snapshot['error']}")
        print("\nMost common causes, in order:")
        print("  1. SNMP not enabled on the switch, or this host not in its "
              "allow-list")
        print("  2. Wrong community string / v3 credentials")
        print("  3. UDP 161 blocked by a firewall or ACL between here and there")
        print("  See references/troubleshooting.md")
        return 1

    system = snapshot["system"]
    print(f"{system.get('name') or device['host']}  ({device['host']})")
    print(f"  {system.get('descr', '')}")
    print(f"  uptime {human_uptime(system.get('uptime'))}"
          f"   location: {system.get('location') or '-'}"
          f"   response {snapshot['rtt_ms']:.0f} ms")

    ports = snapshot["ports"]
    up = sum(1 for p in ports if p["oper"] == 1)
    print(f"\n  {len(ports)} interfaces, {up} up, {len(ports) - up} down\n")

    header = f"  {'#':>4}  {'interface':<24} {'admin':<6} {'oper':<8} {'speed':>9}  description"
    print(header)
    print("  " + "-" * (len(header) - 2))
    for port in ports:
        if args.up_only and port["oper"] != 1:
            continue
        speed = human_bps(port["speed_bps"]) if port["speed_bps"] else "-"
        flag = "" if port["oper"] == 1 or port["admin"] != 1 else "  <-- DOWN"
        print(
            f"  {port['ifindex']:>4}  {port['name'][:24]:<24} "
            f"{ADMIN_STATUS.get(port['admin'], '?'):<6} "
            f"{OPER_STATUS.get(port['oper'], '?'):<8} {speed:>9}  "
            f"{port['alias'][:30]}{flag}"
        )
    print("\nTraffic rates need two polls - run 'netmon.py watch' for bandwidth.")
    return 0


def cmd_discover(args, config):
    """Probe hosts or a CIDR range and write a config file."""
    targets: list[str] = []
    for target in args.targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.num_addresses > 1024:
                raise SystemExit(
                    f"{target} covers {network.num_addresses} addresses; "
                    f"scan a /22 or smaller"
                )
            targets += [str(ip) for ip in network.hosts()] or [str(network.network_address)]
        except ValueError:
            targets.append(target)

    communities = args.community or [config["defaults"].get("community", "public")]
    print(f"probing {len(targets)} address(es) with "
          f"{len(communities)} community string(s)...", flush=True)

    found = []

    def probe(host):
        for community in communities:
            device = {"host": host, "community": community,
                      "timeout": args.timeout, "retries": 0}
            snapshot = poll_device(device, config)
            if snapshot["reachable"]:
                return host, community, snapshot
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for outcome in pool.map(probe, targets):
            if outcome is None:
                continue
            host, community, snapshot = outcome
            system = snapshot["system"]
            found.append({"host": host, "community": community,
                          "name": system.get("name"), "descr": system.get("descr"),
                          "ports": len(snapshot["ports"])})
            print(f"  found {host:<16} {system.get('name', '?'):<20} "
                  f"{len(snapshot['ports'])} ports  {system.get('descr', '')[:60]}",
                  flush=True)

    if not found:
        print("\nNo SNMP devices answered. Check the community string and that "
              "UDP 161 is reachable (see references/troubleshooting.md).")
        return 1

    path = Path(args.out or config.get("_path") or "netmon.json")
    existing = {}
    if path.exists() and not args.overwrite:
        existing = json.loads(path.read_text())
    devices = {d["host"]: d for d in existing.get("devices", [])}
    for item in found:
        devices[item["host"]] = {"host": item["host"], "name": item["name"],
                                 "community": item["community"]}
    out = deep_merge(
        {k: v for k, v in DEFAULT_CONFIG.items()},
        {k: v for k, v in existing.items() if not k.startswith("_")},
    )
    out["devices"] = list(devices.values())
    path.write_text(json.dumps(out, indent=2) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"\nwrote {len(found)} device(s) to {path} (mode 600)")
    print(f"next: python3 {Path(__file__).name} watch --config {path}")
    return 0


def poll_all(conn, config, quiet=False):
    devices = config.get("devices", [])
    if not devices:
        raise SystemExit(
            f"no devices configured in {config.get('_path')}. Run: "
            f"python3 {Path(__file__).name} discover <host-or-cidr>"
        )
    workers = min(16, max(1, len(devices)))
    alerts: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        snapshots = list(pool.map(lambda d: poll_device(d, config), devices))
    for snapshot in snapshots:
        alerts += store_and_evaluate(conn, snapshot, config)
    conn.commit()
    notify(alerts, config, quiet=quiet)
    return snapshots, alerts


def prune(conn, config):
    days = float(config.get("retention_days", 30))
    if days <= 0:
        return
    cutoff = now_ts() - days * 86400
    conn.execute("DELETE FROM port_samples WHERE ts < ?", (cutoff,))
    conn.execute("DELETE FROM device_samples WHERE ts < ?", (cutoff,))
    conn.execute(
        "DELETE FROM events WHERE closed_ts IS NOT NULL AND closed_ts < ?", (cutoff,)
    )
    conn.commit()


def cmd_poll(args, config):
    conn = open_db(Path(args.db))
    snapshots, alerts = poll_all(conn, config, quiet=args.json)
    prune(conn, config)
    if args.json:
        print(json.dumps({"snapshots": snapshots, "alerts": alerts},
                         indent=2, default=str))
    else:
        ok = sum(1 for s in snapshots if s["reachable"])
        print(f"polled {len(snapshots)} device(s): {ok} up, "
              f"{len(snapshots) - ok} unreachable, {len(alerts)} alert(s)")
    conn.close()
    return 0


def cmd_watch(args, config):
    conn = open_db(Path(args.db))
    interval = args.interval or float(config["defaults"].get("interval", 60))
    print(f"watching {len(config.get('devices', []))} device(s) every "
          f"{interval:g}s; Ctrl-C to stop", flush=True)
    cycle = 0
    try:
        while True:
            started = time.monotonic()
            snapshots, alerts = poll_all(conn, config)
            cycle += 1
            if not alerts and not args.quiet:
                ok = sum(1 for s in snapshots if s["reachable"])
                print(f"[{iso(now_ts())}] cycle {cycle}: {ok}/{len(snapshots)} "
                      f"device(s) healthy", flush=True)
            if cycle % 60 == 0:
                prune(conn, config)
            if args.once:
                break
            time.sleep(max(1.0, interval - (time.monotonic() - started)))
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        conn.close()
    return 0


def cmd_events(args, config):
    conn = open_db(Path(args.db))
    query = "SELECT * FROM events"
    if args.open_only:
        query += " WHERE closed_ts IS NULL"
    query += " ORDER BY opened_ts DESC LIMIT ?"
    rows = conn.execute(query, (args.limit,)).fetchall()
    if not rows:
        print("no events recorded")
        return 0
    for row in rows:
        state = "OPEN" if row["closed_ts"] is None else "resolved"
        print(f"{iso(row['opened_ts'])}  {row['severity'].upper():8} "
              f"{state:9} {row['message']}")
    conn.close()
    return 0


# --------------------------------------------------------------------------
# HTML report
# --------------------------------------------------------------------------


def sparkline(values, width=110, height=26, color="#3b82f6"):
    values = [v for v in values if v is not None]
    if len(values) < 2:
        return ""
    peak = max(values) or 1
    step = width / (len(values) - 1)
    points = " ".join(
        f"{i * step:.1f},{height - (v / peak) * (height - 3):.1f}"
        for i, v in enumerate(values)
    )
    return (
        f'<svg viewBox="0 0 {width} {height}" preserveAspectRatio="none" '
        f'class="spark"><polyline points="{points}" fill="none" '
        f'stroke="{color}" stroke-width="1.6"/></svg>'
    )


def cmd_report(args, config):
    conn = open_db(Path(args.db))
    devices = conn.execute("SELECT * FROM devices ORDER BY host").fetchall()
    if not devices:
        raise SystemExit("no data yet - run 'netmon.py poll' or 'watch' first")

    window = now_ts() - args.hours * 3600
    blocks = []
    total_ports = total_up = 0

    for device in devices:
        host = device["host"]
        latest = conn.execute(
            "SELECT MAX(ts) AS ts FROM port_samples WHERE host=?", (host,)
        ).fetchone()["ts"]
        ports = conn.execute(
            "SELECT * FROM port_samples WHERE host=? AND ts=? ORDER BY ifindex",
            (host, latest),
        ).fetchall() if latest else []

        rows = []
        for port in ports:
            total_ports += 1
            oper = OPER_STATUS.get(port["oper"], "?")
            if port["oper"] == 1:
                total_up += 1
            history = conn.execute(
                "SELECT in_bps, out_bps FROM port_samples WHERE host=? AND "
                "ifindex=? AND ts>=? ORDER BY ts",
                (host, port["ifindex"], window),
            ).fetchall()
            spark = sparkline([h["in_bps"] for h in history])
            util = port["util_pct"]
            bar_width = min(100.0, util or 0.0)
            bar_class = (
                "bar-crit" if util and util >= 90
                else "bar-warn" if util and util >= 70
                else "bar-ok"
            )
            state_class = {"up": "ok", "down": "crit"}.get(oper, "warn")
            if port["admin"] != 1:
                state_class, oper = "muted", "admin down"
            rows.append(f"""
        <tr>
          <td class="idx">{port['ifindex']}</td>
          <td class="name">{html.escape(port['name'] or '')}
            <span class="alias">{html.escape(port['alias'] or '')}</span></td>
          <td><span class="pill {state_class}">{oper}</span></td>
          <td class="num">{human_bps(port['speed_bps'])}</td>
          <td class="num">{human_bps(port['in_bps'])}</td>
          <td class="num">{human_bps(port['out_bps'])}</td>
          <td class="util">
            <div class="bar"><i class="{bar_class}" style="width:{bar_width:.0f}%">
            </i></div>
            <span>{'-' if util is None else f'{util:.0f}%'}</span>
          </td>
          <td class="num {'bad' if (port['err_per_min'] or 0) > 0 else ''}">
            {'-' if port['err_per_min'] is None else f"{port['err_per_min']:.0f}"}</td>
          <td class="spark-cell">{spark}</td>
        </tr>""")

        reachable = device["fail_streak"] == 0
        uptime_row = conn.execute(
            "SELECT uptime FROM device_samples WHERE host=? AND reachable=1 "
            "ORDER BY ts DESC LIMIT 1", (host,)
        ).fetchone()
        blocks.append(f"""
    <section class="device">
      <header>
        <h2>{html.escape(device['name'] or host)}
          <span class="pill {'ok' if reachable else 'crit'}">
            {'reachable' if reachable else 'UNREACHABLE'}</span></h2>
        <p class="meta">{html.escape(host)} &middot;
          {html.escape((device['descr'] or '')[:110])}<br>
          uptime {human_uptime(uptime_row['uptime'] if uptime_row else None)}
          &middot; last polled {iso(device['last_seen']) if device['last_seen'] else '-'}
        </p>
      </header>
      <div class="scroll"><table>
        <thead><tr><th>#</th><th>interface</th><th>state</th><th>speed</th>
          <th>in</th><th>out</th><th>utilisation</th><th>err/min</th>
          <th>in, last {args.hours}h</th></tr></thead>
        <tbody>{''.join(rows) or '<tr><td colspan="9">no port data</td></tr>'}</tbody>
      </table></div>
    </section>""")

    events = conn.execute(
        "SELECT * FROM events WHERE opened_ts>=? ORDER BY opened_ts DESC LIMIT 100",
        (window,),
    ).fetchall()
    event_rows = "".join(
        f"<tr><td>{iso(e['opened_ts'])}</td>"
        f"<td><span class='pill {'crit' if e['severity'] == 'critical' else 'warn'}'>"
        f"{e['severity']}</span></td>"
        f"<td>{'OPEN' if e['closed_ts'] is None else 'resolved'}</td>"
        f"<td>{html.escape(e['message'])}</td></tr>"
        for e in events
    ) or "<tr><td colspan='4'>no events in this window</td></tr>"

    open_count = sum(1 for e in events if e["closed_ts"] is None)
    down_devices = sum(1 for d in devices if d["fail_streak"])

    doc = REPORT_TEMPLATE.format(
        generated=iso(now_ts()),
        hours=args.hours,
        devices=len(devices),
        down_devices=down_devices,
        ports=total_ports,
        ports_up=total_up,
        open_events=open_count,
        blocks="".join(blocks),
        events=event_rows,
    )
    out = Path(args.out)
    out.write_text(doc)
    print(f"wrote {out} ({out.stat().st_size // 1024} KB, self-contained)")
    if args.open:
        import webbrowser
        webbrowser.open(out.resolve().as_uri())
    conn.close()
    return 0


REPORT_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network switch status</title>
<style>
  :root {{
    --bg:#f6f7f9; --card:#fff; --ink:#111827; --muted:#6b7280; --line:#e5e7eb;
    --ok:#059669; --warn:#d97706; --crit:#dc2626; --accent:#3b82f6;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#0b0f17; --card:#141a24; --ink:#e5e7eb; --muted:#9ca3af;
      --line:#232c3b; --ok:#34d399; --warn:#fbbf24; --crit:#f87171;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; padding:24px; background:var(--bg); color:var(--ink);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); margin:0 0 20px; font-size:13px; }}
  .cards {{ display:grid; gap:12px; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
    margin-bottom:22px; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:10px;
    padding:14px 16px; }}
  .card b {{ display:block; font-size:26px; font-weight:650; }}
  .card span {{ color:var(--muted); font-size:12px; }}
  section.device {{ background:var(--card); border:1px solid var(--line);
    border-radius:10px; margin-bottom:18px; overflow:hidden; }}
  section.device header {{ padding:14px 16px; border-bottom:1px solid var(--line); }}
  h2 {{ font-size:15px; margin:0 0 4px; display:flex; align-items:center; gap:8px; }}
  .meta {{ margin:0; color:var(--muted); font-size:12px; }}
  .scroll {{ overflow-x:auto; }}
  table {{ border-collapse:collapse; width:100%; min-width:820px; }}
  th, td {{ padding:7px 10px; text-align:left; border-bottom:1px solid var(--line);
    font-size:13px; white-space:nowrap; }}
  th {{ color:var(--muted); font-weight:600; font-size:11px;
    text-transform:uppercase; letter-spacing:.04em; }}
  tbody tr:last-child td {{ border-bottom:none; }}
  .num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .idx {{ color:var(--muted); }}
  .name {{ font-weight:550; }}
  .alias {{ color:var(--muted); font-weight:400; margin-left:6px; }}
  .bad {{ color:var(--crit); font-weight:600; }}
  .pill {{ display:inline-block; padding:1px 8px; border-radius:99px; font-size:11px;
    font-weight:600; }}
  .pill.ok {{ background:color-mix(in srgb,var(--ok) 16%,transparent); color:var(--ok); }}
  .pill.warn {{ background:color-mix(in srgb,var(--warn) 18%,transparent); color:var(--warn); }}
  .pill.crit {{ background:color-mix(in srgb,var(--crit) 16%,transparent); color:var(--crit); }}
  .pill.muted {{ background:color-mix(in srgb,var(--muted) 16%,transparent); color:var(--muted); }}
  .util {{ display:flex; align-items:center; gap:8px; min-width:150px; }}
  .bar {{ flex:1; height:6px; background:var(--line); border-radius:3px; overflow:hidden; }}
  .bar i {{ display:block; height:100%; }}
  .bar-ok {{ background:var(--ok); }} .bar-warn {{ background:var(--warn); }}
  .bar-crit {{ background:var(--crit); }}
  .spark {{ width:110px; height:26px; display:block; }}
  .spark-cell {{ width:120px; }}
  footer {{ color:var(--muted); font-size:12px; margin-top:20px; }}
</style></head><body>
<h1>Network switch status</h1>
<p class="sub">Generated {generated} &middot; showing the last {hours} h</p>
<div class="cards">
  <div class="card"><b>{devices}</b><span>devices monitored</span></div>
  <div class="card"><b>{down_devices}</b><span>devices unreachable</span></div>
  <div class="card"><b>{ports_up}/{ports}</b><span>ports up</span></div>
  <div class="card"><b>{open_events}</b><span>open alerts</span></div>
</div>
{blocks}
<section class="device">
  <header><h2>Events</h2><p class="meta">Most recent first</p></header>
  <div class="scroll"><table>
    <thead><tr><th>time</th><th>severity</th><th>state</th><th>detail</th></tr></thead>
    <tbody>{events}</tbody>
  </table></div>
</section>
<footer>Collected over SNMP by netmon. Rates are derived from 64-bit
interface counters between consecutive polls.</footer>
</body></html>
"""


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="netmon.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", type=Path, help="config file (default netmon.json)")
    parser.add_argument("--db", default=os.environ.get("NETMON_DB", "netmon.db"),
                        help="SQLite history file (default netmon.db)")
    sub = parser.add_subparsers(dest="command", required=True)

    def creds(p):
        p.add_argument("-c", "--community", help="SNMP v1/v2c community string")
        p.add_argument("-v", "--version", choices=["1", "2c", "3"],
                       help="SNMP version (default 2c)")
        p.add_argument("--port", type=int)
        p.add_argument("--timeout", type=float)
        p.add_argument("--retries", type=int)
        p.add_argument("-u", "--username", help="SNMPv3 user")
        p.add_argument("--auth-proto", dest="auth_proto",
                       help="SNMPv3 auth: MD5, SHA, SHA256, ...")
        p.add_argument("--auth-pass", dest="auth_pass")
        p.add_argument("--priv-proto", dest="priv_proto", help="SNMPv3 priv: DES, AES")
        p.add_argument("--priv-pass", dest="priv_pass")

    p_check = sub.add_parser("check", help="one-off health check of one device")
    p_check.add_argument("host")
    p_check.add_argument("--json", action="store_true")
    p_check.add_argument("--up-only", action="store_true",
                         help="only list interfaces that are up")
    creds(p_check)
    p_check.set_defaults(func=cmd_check)

    p_disc = sub.add_parser("discover", help="probe hosts/CIDR and write a config")
    p_disc.add_argument("targets", nargs="+", help="IPs, hostnames, or CIDRs")
    p_disc.add_argument("-c", "--community", action="append",
                        help="community to try (repeatable)")
    p_disc.add_argument("--timeout", type=float, default=1.0)
    p_disc.add_argument("--workers", type=int, default=64)
    p_disc.add_argument("--out", help="config file to write")
    p_disc.add_argument("--overwrite", action="store_true")
    p_disc.set_defaults(func=cmd_discover)

    p_poll = sub.add_parser("poll", help="one polling cycle over all devices")
    p_poll.add_argument("--json", action="store_true")
    p_poll.set_defaults(func=cmd_poll)

    p_watch = sub.add_parser("watch", help="poll continuously and alert")
    p_watch.add_argument("--interval", type=float)
    p_watch.add_argument("--once", action="store_true")
    p_watch.add_argument("--quiet", action="store_true")
    p_watch.set_defaults(func=cmd_watch)

    p_report = sub.add_parser("report", help="write a self-contained HTML dashboard")
    p_report.add_argument("--out", default="netmon-report.html")
    p_report.add_argument("--hours", type=float, default=24)
    p_report.add_argument("--open", action="store_true", help="open in a browser")
    p_report.set_defaults(func=cmd_report)

    p_events = sub.add_parser("events", help="list recorded alerts")
    p_events.add_argument("--limit", type=int, default=40)
    p_events.add_argument("--open-only", action="store_true")
    p_events.set_defaults(func=cmd_events)

    # Long-running commands are usually piped into tee or a log file; block
    # buffering would hide every alert until the process exits.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass

    args = parser.parse_args(argv)
    config = load_config(args.config)
    try:
        return args.func(args, config)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
