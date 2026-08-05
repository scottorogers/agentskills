# SNMP switch monitoring

Monitor network switches over SNMP. Nothing to install — it runs on the Python
standard library that ships with every Mac and Linux box, and with Python on
Windows.

## For someone using Claude

Drop this folder into your skills directory and ask in plain English:

> Check the switch at 192.168.1.254, the community string is `public`

> Find every SNMP device on 10.0.0.0/24 and start monitoring them

> Which ports went down overnight?

> Build me a dashboard of the last 24 hours

Claude picks the right command, interprets the output, and explains what it
means. You do not need to know any of the syntax below.

## For someone using it directly

```bash
# One-off health check — proves credentials and connectivity in one step
python3 scripts/netmon.py check 192.168.1.254 -c public

# Find switches on a subnet and write netmon.json
python3 scripts/netmon.py discover 192.168.1.0/24 -c public

# Monitor continuously, alert on port down / saturation / errors
python3 scripts/netmon.py watch

# Self-contained HTML dashboard you can email to someone
python3 scripts/netmon.py report --out dashboard.html --open

# What has gone wrong recently?
python3 scripts/netmon.py events --open-only
```

SNMPv3:

```bash
python3 scripts/netmon.py check 10.0.0.1 -v 3 -u netmon \
  --auth-proto SHA --auth-pass 'AuthPassphrase' \
  --priv-proto AES --priv-pass 'PrivPassphrase'
```

## Try it with no hardware

A simulated 24-port switch is included, with fault injection:

```bash
python3 scripts/mock_switch.py --port 11161 --flap 8 --errors 12 --saturate 3 &
python3 scripts/netmon.py check 127.0.0.1:11161
```

Port 8 flaps, port 12 logs errors, port 3 runs near line rate — so you can
watch alerts fire before pointing it at production kit.

## What it monitors

- Device reachability, uptime, and unexpected restarts
- Per-port admin/operational status, with alerts on links going down
- Bandwidth in and out, and utilisation against link speed
- Interface errors and discards, with rate-based alerting
- History in SQLite, so trends and past incidents survive restarts

Alerts go to a log file, a webhook (Slack, Teams, or anything accepting JSON),
or a shell command of your choosing.

## Safety

This tool only **reads**. It issues SNMP GET, GETNEXT and GETBULK requests and
never SET, so it cannot change a device's configuration.

Use a read-only community and restrict it by source IP on the device.
`netmon.json` holds credentials and is written mode 600; to keep them out of
the file entirely, reference an environment variable:

```json
{ "defaults": { "community": "${SW_COMMUNITY}" } }
```

## Requirements

Python 3.9 or newer, and UDP/161 reachability to the devices. SNMPv3 with
encryption (authPriv) additionally needs `pip install cryptography`; SNMPv3
with authentication only, and all of v1/v2c, need nothing.

## Tests

```bash
python3 tests/test_netmon.py
```

43 tests. Where the `net-snmp` daemon is installed, the suite also runs
interoperability checks against that real agent (v1, v2c, and v3 with and
without encryption) rather than only against the bundled simulator.

## Licence

Apache 2.0.
