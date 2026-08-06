"""Standalone app layer: a local web dashboard over the SNMP poller.

This file is not run directly. `build_app.py` inlines snmp.py and netmon.py
into it to produce a single self-contained `netmon-app.py`.

Run with no arguments -> starts the dashboard and opens a browser.
Run with arguments    -> behaves as the netmon CLI (check, poll, report, ...).
"""

from __future__ import annotations

# These two modules are inlined into this file by app/build_app.py, so the
# star imports exist only to make this source runnable and checkable on its
# own. F405 ("may be undefined from star imports") is therefore expected.
# ruff: noqa: F405
from snmp import *  # noqa: F403  # BUILD:INLINE snmp.py
from netmon import *  # noqa: F403  # BUILD:INLINE netmon.py

import http.server
import os
import json
import socket
import sqlite3
import sys
import threading
import time
import traceback
import webbrowser
from pathlib import Path

APP_TITLE = "Switch Monitor"
DEFAULT_INTERVAL = 30.0


# --------------------------------------------------------------------------
# Application state
# --------------------------------------------------------------------------


class Monitor:
    """Owns the config, the database, and the background polling thread."""

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.config_path = base_dir / "switches.json"
        self.db_path = base_dir / "switch-history.db"
        self.log_path = base_dir / "alerts.log"

        # One connection shared across the poller thread and request handlers,
        # guarded by a mutex. SQLite is fine with this; it is not fine with
        # unguarded concurrent use.
        self.conn = sqlite3.connect(
            str(self.db_path), timeout=30, check_same_thread=False
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

        self.config = self._load_config()
        self.interval = float(self.config["defaults"].get("interval", DEFAULT_INTERVAL))
        self.recent: list[dict] = []
        self.last_poll: float | None = None
        self.last_error: str | None = None
        self.polling = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # -- config ------------------------------------------------------------

    def _load_config(self) -> dict:
        if self.config_path.exists():
            try:
                raw = json.loads(self.config_path.read_text())
            except json.JSONDecodeError:
                raw = {}
        else:
            raw = {}
        config = deep_merge(DEFAULT_CONFIG, raw)
        config["defaults"].setdefault("interval", DEFAULT_INTERVAL)
        config["alerts"]["log"] = str(self.log_path)
        config["_path"] = str(self.config_path)
        config["_missing"] = False
        return config

    def save_config(self) -> None:
        out = {k: v for k, v in self.config.items() if not k.startswith("_")}
        self.config_path.write_text(json.dumps(out, indent=2) + "\n")
        try:
            self.config_path.chmod(0o600)
        except OSError:
            pass

    # -- devices -----------------------------------------------------------

    def add_device(self, device: dict) -> dict:
        """Probe a device before saving it, so bad credentials fail loudly."""
        host = (device.get("host") or "").strip()
        if not host:
            raise ValueError("Enter the switch's IP address or hostname.")

        candidate = {"host": host, "timeout": 3.0, "retries": 1}
        for key in ("community", "version", "username", "auth_proto",
                    "auth_pass", "priv_proto", "priv_pass"):
            value = (device.get(key) or "").strip()
            if value:
                candidate[key] = value
        candidate.setdefault("version", "2c")
        if candidate["version"] != "3":
            candidate.setdefault("community", "public")

        snapshot = poll_device(candidate, self.config)
        if not snapshot["reachable"]:
            raise ValueError(snapshot["error"] or "no response from that address")

        candidate["name"] = snapshot["system"].get("name") or host
        candidate.pop("timeout", None)
        candidate.pop("retries", None)

        devices = [d for d in self.config["devices"] if d.get("host") != host]
        devices.append(candidate)
        self.config["devices"] = devices
        self.save_config()

        with self.lock:
            alerts = store_and_evaluate(self.conn, snapshot, self.config)
            self.conn.commit()
        self._record(alerts)
        return {"host": host, "name": candidate["name"],
                "ports": len(snapshot["ports"])}

    def remove_device(self, host: str) -> None:
        self.config["devices"] = [
            d for d in self.config["devices"] if d.get("host") != host
        ]
        self.save_config()
        with self.lock:
            for table in ("devices", "device_samples", "port_samples", "events"):
                self.conn.execute(f"DELETE FROM {table} WHERE host=?", (host,))
            self.conn.commit()

    # -- polling -----------------------------------------------------------

    def poll_once(self) -> list[dict]:
        devices = self.config.get("devices", [])
        if not devices:
            return []
        alerts: list[dict] = []
        try:
            for device in devices:
                snapshot = poll_device(device, self.config)
                with self.lock:
                    alerts += store_and_evaluate(self.conn, snapshot, self.config)
                    self.conn.commit()
            self.last_error = None
        except Exception:
            self.last_error = traceback.format_exc(limit=2)
        self.last_poll = now_ts()
        self._record(alerts)
        if alerts:
            try:
                notify(alerts, self.config, quiet=True)
            except Exception:
                pass
        return alerts

    def _record(self, alerts: list[dict]) -> None:
        for alert in alerts:
            self.recent.insert(0, {
                "ts": alert["ts"], "when": iso(alert["ts"]),
                "severity": alert["severity"], "state": alert["state"],
                "message": alert["message"],
            })
        del self.recent[200:]

    def start(self, interval: float | None = None) -> None:
        if interval:
            self.interval = max(5.0, float(interval))
            self.config["defaults"]["interval"] = self.interval
            self.save_config()
        if self.polling:
            return
        self._stop.clear()
        self.polling = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self.polling = False
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            self.poll_once()
            if self._stop.wait(max(1.0, self.interval - (time.monotonic() - started))):
                break

    # -- state for the UI --------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            rows = self.conn.execute("SELECT * FROM devices ORDER BY host").fetchall()
            devices = []
            for row in rows:
                latest = self.conn.execute(
                    "SELECT MAX(ts) AS ts FROM port_samples WHERE host=?",
                    (row["host"],),
                ).fetchone()["ts"]
                ports = self.conn.execute(
                    "SELECT * FROM port_samples WHERE host=? AND ts=? "
                    "ORDER BY ifindex",
                    (row["host"], latest),
                ).fetchall() if latest else []
                uptime_row = self.conn.execute(
                    "SELECT uptime FROM device_samples WHERE host=? AND reachable=1 "
                    "ORDER BY ts DESC LIMIT 1", (row["host"],)
                ).fetchone()
                devices.append({
                    "host": row["host"],
                    "name": row["name"] or row["host"],
                    "descr": (row["descr"] or "")[:120],
                    "reachable": (row["fail_streak"] or 0) == 0,
                    "uptime": human_uptime(
                        uptime_row["uptime"] if uptime_row else None
                    ),
                    "last_seen": iso(row["last_seen"]) if row["last_seen"] else "-",
                    "ports": [{
                        "ifindex": p["ifindex"],
                        "name": p["name"] or "",
                        "alias": p["alias"] or "",
                        "state": (
                            "admin down" if p["admin"] != 1
                            else OPER_STATUS.get(p["oper"], "?")
                        ),
                        "speed": human_bps(p["speed_bps"]),
                        "in_bps": human_bps(p["in_bps"]),
                        "out_bps": human_bps(p["out_bps"]),
                        "util": None if p["util_pct"] is None else round(p["util_pct"]),
                        "errors": (
                            None if p["err_per_min"] is None
                            else round(p["err_per_min"])
                        ),
                    } for p in ports],
                })
            open_events = self.conn.execute(
                "SELECT * FROM events WHERE closed_ts IS NULL "
                "ORDER BY opened_ts DESC LIMIT 50"
            ).fetchall()

        return {
            "devices": devices,
            "open_events": [{
                "when": iso(e["opened_ts"]), "severity": e["severity"],
                "message": e["message"],
            } for e in open_events],
            "recent": self.recent[:60],
            "polling": self.polling,
            "interval": self.interval,
            "last_poll": iso(self.last_poll) if self.last_poll else None,
            "last_error": self.last_error,
            "folder": str(self.base_dir),
            "thresholds": self.config["thresholds"],
        }


# --------------------------------------------------------------------------
# HTTP server
# --------------------------------------------------------------------------


class Handler(http.server.BaseHTTPRequestHandler):
    monitor: Monitor = None  # set on the class before serving
    server_version = "SwitchMonitor"

    def log_message(self, fmt, *args):  # keep the console quiet
        pass

    def _send(self, code: int, body: bytes, content_type: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, payload, code: int = 200) -> None:
        self._send(code, json.dumps(payload).encode(), "application/json")

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, APP_HTML.encode(), "text/html; charset=utf-8")
        elif self.path == "/api/state":
            self._json(self.monitor.snapshot())
        elif self.path == "/api/report":
            path = self.monitor.base_dir / "dashboard.html"
            try:
                self._build_report(path)
                self._json({"ok": True, "path": str(path)})
            except SystemExit as exc:
                self._json({"ok": False, "error": str(exc)}, 400)
            except Exception as exc:
                self._json({"ok": False, "error": str(exc)}, 500)
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        body = self._body()
        try:
            if self.path == "/api/devices/add":
                self._json({"ok": True, "device": self.monitor.add_device(body)})
            elif self.path == "/api/devices/remove":
                self.monitor.remove_device(body.get("host", ""))
                self._json({"ok": True})
            elif self.path == "/api/poll":
                self.monitor.poll_once()
                self._json({"ok": True})
            elif self.path == "/api/start":
                self.monitor.start(body.get("interval"))
                self._json({"ok": True})
            elif self.path == "/api/stop":
                self.monitor.stop()
                self._json({"ok": True})
            else:
                self._send(404, b"not found", "text/plain")
        except ValueError as exc:
            self._json({"ok": False, "error": str(exc)}, 400)
        except Exception as exc:
            self._json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 500)

    def _build_report(self, path: Path) -> None:
        class Args:
            db = str(self.monitor.db_path)
            out = str(path)
            hours = 24.0
            open = False
        cmd_report(Args(), self.monitor.config)


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def pick_port(preferred: int = 8765) -> int:
    for port in range(preferred, preferred + 40):
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    return 0  # let the OS choose


def run_app(argv=None) -> int:
    base_dir = Path(
        os.environ.get("SWITCH_MONITOR_HOME")
        or (Path.home() / "SwitchMonitor")
    )
    base_dir.mkdir(parents=True, exist_ok=True)

    monitor = Monitor(base_dir)
    Handler.monitor = monitor

    port = pick_port()
    # Bound to loopback only. SNMP credentials live behind this interface;
    # it must never be reachable from the network.
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"

    if monitor.config.get("devices"):
        monitor.start()

    print("=" * 62)
    print(f"  {APP_TITLE} is running")
    print(f"  Open this in your browser:  {url}")
    print(f"  Data is stored in:          {base_dir}")
    print("  Close this window to stop.")
    print("=" * 62, flush=True)

    try:
        webbrowser.open(url)
    except Exception:
        pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping...")
    finally:
        monitor.stop()
        server.shutdown()
    return 0


APP_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Switch Monitor</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--ink:#111827;--muted:#6b7280;--line:#e5e7eb;
    --ok:#059669;--warn:#d97706;--crit:#dc2626;--accent:#2563eb}
  @media (prefers-color-scheme:dark){:root{--bg:#0b0f17;--card:#141a24;
    --ink:#e5e7eb;--muted:#9ca3af;--line:#232c3b;--ok:#34d399;--warn:#fbbf24;
    --crit:#f87171;--accent:#60a5fa}}
  *{box-sizing:border-box}
  body{margin:0;padding:22px;background:var(--bg);color:var(--ink);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px}
  h1{font-size:19px;margin:0}
  .sub{color:var(--muted);font-size:13px;margin:0 0 18px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;
    margin-bottom:16px;overflow:hidden}
  .card>header{padding:13px 16px;border-bottom:1px solid var(--line);margin:0;
    display:flex;justify-content:space-between;align-items:center;gap:10px}
  h2{font-size:15px;margin:0;display:flex;align-items:center;gap:8px}
  .meta{color:var(--muted);font-size:12px;margin:2px 0 0}
  .pad{padding:14px 16px}
  .row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
  input,select,button{font:inherit;padding:7px 10px;border-radius:7px;
    border:1px solid var(--line);background:var(--card);color:var(--ink)}
  input:focus,select:focus{outline:2px solid var(--accent);outline-offset:-1px}
  button{cursor:pointer;background:var(--accent);color:#fff;border-color:transparent;
    font-weight:550}
  button:hover{filter:brightness(1.08)}
  button.ghost{background:transparent;color:var(--ink);border-color:var(--line);
    font-weight:400}
  button:disabled{opacity:.5;cursor:default}
  .scroll{overflow-x:auto}
  table{border-collapse:collapse;width:100%;min-width:760px}
  th,td{padding:7px 12px;text-align:left;border-bottom:1px solid var(--line);
    font-size:13px;white-space:nowrap}
  th{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.04em;font-weight:600}
  tbody tr:last-child td{border-bottom:none}
  .num{text-align:right;font-variant-numeric:tabular-nums}
  .pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:11px;
    font-weight:600}
  .ok{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
  .warn{background:color-mix(in srgb,var(--warn) 18%,transparent);color:var(--warn)}
  .crit{background:color-mix(in srgb,var(--crit) 16%,transparent);color:var(--crit)}
  .muted{background:color-mix(in srgb,var(--muted) 16%,transparent);color:var(--muted)}
  .bar{display:inline-block;width:70px;height:6px;background:var(--line);
    border-radius:3px;overflow:hidden;vertical-align:middle;margin-right:7px}
  .bar i{display:block;height:100%;background:var(--ok)}
  .bar i.w{background:var(--warn)} .bar i.c{background:var(--crit)}
  .bad{color:var(--crit);font-weight:600}
  .err{background:color-mix(in srgb,var(--crit) 10%,transparent);
    border:1px solid var(--crit);color:var(--crit);padding:9px 12px;
    border-radius:8px;margin-bottom:12px;font-size:13px;white-space:pre-wrap}
  .empty{color:var(--muted);padding:24px 16px;text-align:center}
  .feed div{padding:6px 16px;border-bottom:1px solid var(--line);font-size:13px}
  .feed div:last-child{border-bottom:none}
  .when{color:var(--muted);font-variant-numeric:tabular-nums;margin-right:8px}
  .adv{display:none} .adv.on{display:flex}
  label{font-size:12px;color:var(--muted);display:block;margin-bottom:3px}
  .f{display:flex;flex-direction:column}
</style></head><body>

<header><h1>Switch Monitor</h1><span id="status" class="pill muted">starting</span></header>
<p class="sub" id="sub">&nbsp;</p>

<div id="banner"></div>

<div class="card">
  <header><h2>Add a switch</h2>
    <button class="ghost" id="advBtn" type="button">SNMPv3 / advanced</button>
  </header>
  <div class="pad">
    <div class="row">
      <div class="f"><label>IP address or hostname</label>
        <input id="host" placeholder="192.168.1.254" size="010" style="width:190px"></div>
      <div class="f"><label>Community string</label>
        <input id="community" placeholder="public" style="width:150px"></div>
      <div class="f"><label>Version</label>
        <select id="version">
          <option value="2c">v2c (usual)</option>
          <option value="1">v1</option>
          <option value="3">v3</option>
        </select></div>
      <div class="f"><label>&nbsp;</label><button id="add">Add switch</button></div>
    </div>
    <div class="row adv" id="adv" style="margin-top:10px">
      <div class="f"><label>v3 username</label><input id="username" style="width:130px"></div>
      <div class="f"><label>Auth</label>
        <select id="auth_proto"><option value="">none</option><option>SHA</option>
        <option>SHA256</option><option>MD5</option></select></div>
      <div class="f"><label>Auth password</label>
        <input id="auth_pass" type="password" style="width:150px"></div>
      <div class="f"><label>Privacy</label>
        <select id="priv_proto"><option value="">none</option><option>AES</option>
        <option>DES</option></select></div>
      <div class="f"><label>Privacy password</label>
        <input id="priv_pass" type="password" style="width:150px"></div>
    </div>
    <p class="meta" style="margin-top:10px">The switch is contacted straight away —
      if the credentials or address are wrong you will be told now, not later.</p>
  </div>
</div>

<div class="card">
  <header><h2>Monitoring</h2>
    <div class="row">
      <label style="margin:0">every</label>
      <select id="interval">
        <option value="15">15 s</option><option value="30" selected>30 s</option>
        <option value="60">60 s</option><option value="300">5 min</option>
      </select>
      <button id="toggle">Start</button>
      <button class="ghost" id="pollnow">Poll now</button>
      <button class="ghost" id="report">Save dashboard</button>
    </div>
  </header>
  <div class="pad meta" id="pollinfo">Not polling yet.</div>
</div>

<div id="devices"></div>

<div class="card">
  <header><h2>Current problems</h2></header>
  <div id="problems"></div>
</div>

<div class="card">
  <header><h2>Activity</h2></header>
  <div class="feed" id="feed"><div class="empty">Nothing yet.</div></div>
</div>

<script>
const $ = s => document.querySelector(s);
let polling = false;

function esc(s){ return (s??'').toString().replace(/[&<>"]/g,
  c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

function banner(msg, kind){
  $('#banner').innerHTML = msg ? `<div class="err">${esc(msg)}</div>` : '';
}

async function api(path, body){
  const opt = body ? {method:'POST', headers:{'Content-Type':'application/json'},
                      body: JSON.stringify(body)} : {};
  const r = await fetch(path, opt);
  const j = await r.json().catch(()=>({ok:false,error:'bad response'}));
  if(!r.ok || j.ok === false) throw new Error(j.error || 'request failed');
  return j;
}

function stateClass(s){
  if(s === 'up') return 'ok';
  if(s === 'down' || s === 'lowerLayerDown') return 'crit';
  if(s === 'admin down') return 'muted';
  return 'warn';
}

function renderDevices(devices){
  if(!devices.length){
    $('#devices').innerHTML = '<div class="card"><div class="empty">' +
      'No switches yet — add one above. No hardware handy? See the README for ' +
      'the built-in simulator.</div></div>';
    return;
  }
  $('#devices').innerHTML = devices.map(d => {
    const up = d.ports.filter(p => p.state === 'up').length;
    const rows = d.ports.map(p => {
      const u = p.util;
      const cls = u >= 90 ? 'c' : u >= 70 ? 'w' : '';
      const bar = u === null ? '<span class="meta">—</span>' :
        `<span class="bar"><i class="${cls}" style="width:${Math.min(u,100)}%"></i></span>${u}%`;
      return `<tr>
        <td class="meta">${p.ifindex}</td>
        <td><b>${esc(p.name)}</b> <span class="meta">${esc(p.alias)}</span></td>
        <td><span class="pill ${stateClass(p.state)}">${esc(p.state)}</span></td>
        <td class="num">${esc(p.speed)}</td>
        <td class="num">${esc(p.in_bps)}</td>
        <td class="num">${esc(p.out_bps)}</td>
        <td>${bar}</td>
        <td class="num ${p.errors ? 'bad' : ''}">${p.errors === null ? '—' : p.errors}</td>
      </tr>`; }).join('');
    return `<div class="card">
      <header>
        <div><h2>${esc(d.name)}
          <span class="pill ${d.reachable?'ok':'crit'}">
            ${d.reachable?'reachable':'UNREACHABLE'}</span></h2>
          <p class="meta">${esc(d.host)} · ${esc(d.descr)}<br>
            uptime ${esc(d.uptime)} · ${up}/${d.ports.length} ports up ·
            last polled ${esc(d.last_seen)}</p></div>
        <button class="ghost" onclick="removeDevice('${esc(d.host)}')">Remove</button>
      </header>
      <div class="scroll"><table>
        <thead><tr><th>#</th><th>interface</th><th>state</th><th>speed</th>
          <th>in</th><th>out</th><th>utilisation</th><th>err/min</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="empty">no port data yet</td></tr>'}</tbody>
      </table></div></div>`;
  }).join('');
}

async function removeDevice(host){
  if(!confirm('Stop monitoring ' + host + ' and delete its history?')) return;
  try { await api('/api/devices/remove', {host}); await refresh(); }
  catch(e){ banner(e.message); }
}

async function refresh(){
  let s;
  try { s = await (await fetch('/api/state')).json(); }
  catch(e){ $('#status').className='pill crit'; $('#status').textContent='app stopped';
            return; }
  polling = s.polling;
  $('#status').className = 'pill ' + (s.polling ? 'ok' : 'muted');
  $('#status').textContent = s.polling ? 'monitoring' : 'idle';
  $('#sub').textContent = 'Data folder: ' + s.folder;
  $('#toggle').textContent = s.polling ? 'Stop' : 'Start';
  // Reflect the interval the server is actually using, so the control never
  // disagrees with the "every Ns" text below it.
  const sel = $('#interval');
  if([...sel.options].some(o => +o.value === s.interval)) sel.value = String(s.interval);
  $('#pollinfo').textContent = s.last_poll
    ? `Last poll ${s.last_poll} · every ${s.interval}s · alerts at
       ${s.thresholds.utilization_pct}% utilisation and
       ${s.thresholds.errors_per_min} errors/min`
    : 'Not polling yet.';
  if(s.last_error) banner(s.last_error); else banner('');

  renderDevices(s.devices);

  $('#problems').innerHTML = s.open_events.length
    ? '<div class="feed">' + s.open_events.map(e =>
        `<div><span class="when">${esc(e.when)}</span>
         <span class="pill ${e.severity==='critical'?'crit':'warn'}">${esc(e.severity)}</span>
         ${esc(e.message)}</div>`).join('') + '</div>'
    : '<div class="empty">Nothing wrong right now.</div>';

  $('#feed').innerHTML = s.recent.length
    ? s.recent.map(e => `<div><span class="when">${esc(e.when)}</span>
        <span class="pill ${e.severity==='critical'?'crit':e.severity==='warning'?'warn':'ok'}">
        ${esc(e.state)}</span> ${esc(e.message)}</div>`).join('')
    : '<div class="empty">Nothing yet.</div>';
}

$('#advBtn').onclick = () => $('#adv').classList.toggle('on');

$('#add').onclick = async () => {
  const btn = $('#add'); btn.disabled = true; btn.textContent = 'Checking…';
  banner('');
  try {
    const d = await api('/api/devices/add', {
      host: $('#host').value, community: $('#community').value,
      version: $('#version').value, username: $('#username').value,
      auth_proto: $('#auth_proto').value, auth_pass: $('#auth_pass').value,
      priv_proto: $('#priv_proto').value, priv_pass: $('#priv_pass').value});
    $('#host').value = '';
    if(!polling) await api('/api/start', {interval: +$('#interval').value});
    await refresh();
  } catch(e){ banner('Could not reach that switch:\n' + e.message); }
  btn.disabled = false; btn.textContent = 'Add switch';
};

$('#toggle').onclick = async () => {
  try {
    if(polling) await api('/api/stop', {});
    else await api('/api/start', {interval: +$('#interval').value});
    await refresh();
  } catch(e){ banner(e.message); }
};

$('#pollnow').onclick = async () => {
  const b = $('#pollnow'); b.disabled = true; b.textContent = 'Polling…';
  try { await api('/api/poll', {}); await refresh(); } catch(e){ banner(e.message); }
  b.disabled = false; b.textContent = 'Poll now';
};

$('#report').onclick = async () => {
  try { const r = await api('/api/report'); alert('Saved to:\n' + r.path); }
  catch(e){ banner(e.message); }
};

$('#interval').onchange = () => { if(polling) $('#toggle').onclick(); };
$('#host').addEventListener('keydown', e => { if(e.key === 'Enter') $('#add').click(); });

refresh();
setInterval(refresh, 3000);
</script></body></html>
"""


def run_selftest() -> int:
    """Check this machine can actually run the app, and say what failed.

    Written to be pasted back verbatim by a non-technical user, so every
    line is either PASS or an actionable FAIL.
    """
    import platform

    results: list[tuple[bool, str]] = []

    def check(label: str, fn):
        try:
            detail = fn()
            results.append((True, f"PASS  {label}" + (f" -- {detail}" if detail else "")))
        except Exception as exc:
            results.append((False, f"FAIL  {label} -- {type(exc).__name__}: {exc}"))

    print("=" * 66)
    print("  Switch Monitor self-test")
    print("=" * 66)
    print(f"  Python     {sys.version.split()[0]}  ({sys.executable})")
    print(f"  System     {platform.platform()}")
    print(f"  Machine    {platform.machine()}")
    print("-" * 66)

    def _stdlib():
        import http.server, sqlite3, webbrowser  # noqa: F401
        return None

    def _loopback():
        port = pick_port()
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", port))
        probe.close()
        return f"can bind 127.0.0.1:{port}"

    def _udp():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        sock.close()
        return "UDP socket available (needed to reach switches)"

    def _writable():
        base = Path(
            os.environ.get("SWITCH_MONITOR_HOME") or (Path.home() / "SwitchMonitor")
        )
        base.mkdir(parents=True, exist_ok=True)
        probe = base / ".write-test"
        probe.write_text("ok")
        probe.unlink()
        return f"data folder writable: {base}"

    sim_port = {"value": None}

    def _simulator():
        port = pick_port(SIMULATOR_PORT)
        switch = MockSwitch(ports=8, name="selftest-switch")
        thread = threading.Thread(
            target=serve, args=("127.0.0.1", port, "public", switch),
            kwargs={"quiet": True}, daemon=True,
        )
        thread.start()
        time.sleep(0.4)
        sim_port["value"] = port
        return f"simulated switch listening on 127.0.0.1:{port}"

    def _poll():
        port = sim_port["value"]
        if port is None:
            raise RuntimeError("simulator did not start, so polling was not tried")
        snap = poll_device(
            {"host": f"127.0.0.1:{port}", "community": "public"}, DEFAULT_CONFIG
        )
        if not snap["reachable"]:
            raise RuntimeError(snap["error"])
        return f"polled {len(snap['ports'])} ports over real SNMP"

    def _crypto():
        # A broken 'cryptography' install can panic in native code and write
        # straight to the process's stderr, which a Python-level redirect
        # cannot intercept. Swap the file descriptors so the self-test's own
        # output stays clean and trustworthy.
        saved = (os.dup(1), os.dup(2))
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            try:
                _load_cipher("AES")(b"\x00" * 16, b"\x00" * 16, b"probe", True)
                available = True
            except SnmpError:
                available = False
        finally:
            os.dup2(saved[0], 1)
            os.dup2(saved[1], 2)
            for fd in (*saved, devnull):
                os.close(fd)
        return (
            "SNMPv3 encryption available" if available
            else "not available (only needed for SNMPv3 authPriv; v2c is fine)"
        )

    def _database():
        import tempfile

        port = sim_port["value"]
        if port is None:
            raise RuntimeError("simulator did not start, so storage was not tried")
        with tempfile.TemporaryDirectory() as tmp:
            conn = sqlite3.connect(str(Path(tmp) / "probe.db"))
            conn.row_factory = sqlite3.Row
            conn.executescript(SCHEMA)
            try:
                snap = poll_device(
                    {"host": f"127.0.0.1:{port}", "community": "public"},
                    DEFAULT_CONFIG,
                )
                store_and_evaluate(conn, snap, DEFAULT_CONFIG)
                conn.commit()
                stored = conn.execute(
                    "SELECT COUNT(*) AS n FROM port_samples"
                ).fetchone()["n"]
            finally:
                conn.close()
        if not stored:
            raise RuntimeError("nothing was written to the database")
        return f"wrote and read back {stored} port samples"

    def _webserver():
        import tempfile
        import urllib.request

        with tempfile.TemporaryDirectory() as tmp:
            monitor = Monitor(Path(tmp))
            Handler.monitor = monitor
            server = ThreadingHTTPServer(("127.0.0.1", pick_port(8900)), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            url = f"http://127.0.0.1:{server.server_address[1]}"
            try:
                with urllib.request.urlopen(f"{url}/api/state", timeout=5) as resp:
                    state = json.loads(resp.read())
                with urllib.request.urlopen(url + "/", timeout=5) as resp:
                    page = resp.read()
            finally:
                server.shutdown()
                server.server_close()
                monitor.conn.close()
        if "devices" not in state:
            raise RuntimeError("the dashboard API returned something unexpected")
        if b"Switch Monitor" not in page:
            raise RuntimeError("the dashboard page did not render")
        return f"served the dashboard ({len(page) // 1024} KB) and its data feed"

    check("Standard library complete", _stdlib)
    check("Local web server can start", _loopback)
    check("Network sockets usable", _udp)
    check("Data folder writable", _writable)
    check("Built-in simulator starts", _simulator)
    check("SNMP polling works", _poll)
    check("History database works", _database)
    check("Dashboard serves pages", _webserver)
    check("Optional encryption", _crypto)

    for _, line in results:
        print("  " + line)
    print("-" * 66)

    failures = [line for ok, line in results if not ok]
    if failures:
        print(f"  {len(failures)} check(s) FAILED. Send the lines above to whoever")
        print("  gave you this app -- they identify the problem exactly.")
        print("=" * 66)
        return 1
    print("  Everything works on this machine.")
    print("  Start the app by running it with no arguments.")
    print("=" * 66)
    return 0


SIMULATOR_PORT = 11161


def start_simulator(port: int = SIMULATOR_PORT) -> int:
    """Run the bundled fake switch in-process, for demos without hardware."""
    switch = MockSwitch(
        ports=24, name="demo-switch", flap=8, errors=12, saturate=3,
        flap_period=45,
    )
    thread = threading.Thread(
        target=serve,
        args=("127.0.0.1", port, "public", switch),
        kwargs={"quiet": True},
        daemon=True,
    )
    thread.start()
    time.sleep(0.3)
    print(
        f"\n  Simulator running. In the dashboard, add:\n"
        f"      address    127.0.0.1:{port}\n"
        f"      community  public\n"
        f"  One port flaps, one logs errors, one runs at full capacity.\n"
    )
    return port


def main_dispatch(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    if "--selftest" in argv:
        return run_selftest()

    simulate = "--simulate" in argv
    if simulate:
        argv.remove("--simulate")

    cli_commands = {"check", "discover", "poll", "watch", "report", "events"}
    if argv and (argv[0] in cli_commands or argv[0].startswith("-")):
        if simulate:
            start_simulator()
        return main(argv)

    if simulate:
        start_simulator()
    return run_app(argv)


if __name__ == "__main__":
    sys.exit(main_dispatch())
