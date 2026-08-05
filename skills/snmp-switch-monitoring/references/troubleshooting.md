# Troubleshooting

## Symptom to cause

| Symptom | Most likely cause | Check |
|---|---|---|
| `no response ... after N attempts` | Wrong community, source IP not permitted, or UDP/161 filtered. All three look identical from here. | Try from a host that is already allowed; check the device's SNMP ACL |
| `nothing is listening on UDP/161` | Host is up, SNMP agent is off | Enable SNMP (`device-setup.md`) |
| `cannot resolve <host>` | DNS | Use the IP address |
| `authentication: SNMPv3 rejected: unknown user name` | v3 user does not exist on the device | `show snmp user` |
| `SNMPv3 rejected: wrong digest` | Wrong auth passphrase | Re-enter; check auth protocol matches (SHA vs MD5) |
| `SNMPv3 rejected: decryption error` | Wrong priv passphrase or wrong cipher | Confirm AES vs DES on the device |
| `SNMPv3 rejected: not in time window` | Device clock skew >150 s | Fix NTP on the device; the tool resynchronises once automatically |
| `SNMPv3 privacy needs the 'cryptography' package` | authPriv requested without the optional dep | `pip install cryptography`, or switch to authNoPriv |
| `noSuchName` on v1 | OID unsupported, or 64-bit counters requested over v1 | Use v2c |
| System info works, port table empty | ACL/view restricts the OID tree | Widen the SNMP view to include `1.3.6.1.2.1` |
| Some ports missing | Filtered by `ignore_ports` | Check the patterns in `netmon.json` |
| Bandwidth always `-` | Only one poll so far | Rates need two polls — run `watch` |
| Bandwidth wildly too high | 32-bit counter wrapped between polls | Confirm ifXTable support; poll more often |
| Utilisation stuck near 0 on a busy port | `ifSpeed` misreported (often 4294967295 on 10G) | The tool prefers `ifHighSpeed`; if absent, set speed manually |
| Constant flapping alerts | Real flap, or a poll interval shorter than the device's counter refresh | Raise `interval`; check the physical link |
| Everything times out intermittently | UDP loss, or the device rate-limits SNMP | Raise `timeout`/`retries`, lower polling frequency |

## Wrong credentials are silent by design

An SNMP agent that receives a bad community string **does not reply**. RFC 1157
specifies silence (optionally an authenticationFailure trap). So from the
poller, a wrong community, a blocking ACL, and an unplugged cable all produce
the identical symptom: nothing.

The only way to distinguish them is from the device side, or by testing from a
host known to be permitted. Do not waste time inferring it from the poller —
check the device's SNMP configuration first.

The one exception the tool can detect: if the host is reachable and no agent
is bound to the port, the OS returns ICMP port-unreachable, which surfaces as
"nothing is listening on UDP/161". That definitively separates "no agent"
from "agent ignoring us".

## Verifying reachability by hand

```bash
# Is UDP/161 open? (nmap UDP scanning is slow but authoritative)
nmap -sU -p 161 --script snmp-info 10.0.0.1

# If net-snmp is installed, cross-check with a known-good client
snmpget -v2c -c public 10.0.0.1 1.3.6.1.2.1.1.1.0
snmpbulkwalk -v2c -c public 10.0.0.1 1.3.6.1.2.1.31.1.1.1.6
```

If `snmpget` works and `netmon.py` does not, that is a bug in this skill —
capture both with `tcpdump -i any -n udp port 161 -X` and compare.

## Slow or heavy polling

Each device costs roughly one GETBULK round trip per interface column
(about 15). For large estates:

- Raise `interval` to 300 s. Port state changes are still caught within
  five minutes, and traffic averages get smoother, not worse.
- Trim `ignore_ports`. On a router with thousands of subinterfaces, the
  default `"*.[0-9]*"` pattern is doing a lot of work.
- Devices with weak CPUs (older ProCurve, small MikroTik) can drop SNMP under
  load. If polling correlates with CPU alarms, poll less often.

`netmon.py` polls up to 16 devices concurrently, so wall-clock time scales
with the slowest device, not the total count.

## Data that looks wrong

**Counters jumping backwards.** Either a 32-bit wrap (handled) or an agent
restart (discarded rather than reported as a spike). If it happens constantly,
the device is resetting counters — some cheap switches do this on any config
change.

**Uptime resets without a reboot.** `sysUpTime` wraps after 497 days. The
restart alert cannot distinguish this from a real reboot; cross-check
`snmpEngineTime` (`1.3.6.1.6.3.10.2.1.3.0`) which does not wrap.

**ifIndex changed and history broke.** Many vendors renumber interfaces after
a reboot or module change. History is keyed by ifIndex, so a renumber orphans
the old series. Port names in the report will make this obvious.

**A port shows up but passes no traffic.** `ifOperStatus` up only means link
is established. Check for a VLAN misconfiguration, or `ifInErrors` climbing.

## Inspecting the database directly

```bash
sqlite3 netmon.db "SELECT name, oper, in_bps, util_pct FROM port_samples
  WHERE host='10.0.0.1' ORDER BY ts DESC LIMIT 20;"

sqlite3 netmon.db "SELECT * FROM events WHERE closed_ts IS NULL;"
```

Schema: `devices`, `device_samples`, `port_samples`, `events`. Rates are
stored alongside raw counters so historical rates never need recomputing.
