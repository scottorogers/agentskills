# OID catalogue

Everything in the "standard" section is supported by essentially any managed
switch. Vendor sections are best-effort: probe with `get_one()`, which returns
`None` when the device does not implement the OID.

## System (MIB-II, RFC 1213) — universally supported

| OID | Name | Notes |
|---|---|---|
| `1.3.6.1.2.1.1.1.0` | sysDescr | Model and firmware string |
| `1.3.6.1.2.1.1.2.0` | sysObjectID | Identifies the vendor/model; use it to pick vendor OIDs |
| `1.3.6.1.2.1.1.3.0` | sysUpTime | Hundredths of a second since boot; wraps after 497 days |
| `1.3.6.1.2.1.1.4.0` | sysContact | |
| `1.3.6.1.2.1.1.5.0` | sysName | Configured hostname |
| `1.3.6.1.2.1.1.6.0` | sysLocation | |
| `1.3.6.1.2.1.2.1.0` | ifNumber | Interface count |

`sysUpTime` wrapping at 497 days matters: a wrap looks identical to a reboot.
`netmon.py` reports a restart when uptime decreases, so a 497-day-uptime device
will produce one spurious restart event. Cross-check with
`snmpEngineTime` (`1.3.6.1.6.3.10.2.1.3.0`) if that matters.

## Interfaces (IF-MIB, RFC 2863)

Index these by ifIndex. **Do not assume ifIndex is stable across reboots** —
many vendors renumber. Match on `ifName`/`ifDescr` when identity must persist.

### ifTable — `1.3.6.1.2.1.2.2.1.<column>`

| Column | Name | Notes |
|---|---|---|
| 1 | ifIndex | |
| 2 | ifDescr | e.g. `GigabitEthernet0/1` |
| 3 | ifType | 6 = ethernetCsmacd, 53 = propVirtual, 161 = ieee8023adLag |
| 5 | ifSpeed | Gauge32 bits/s; **pins at 4294967295 above 1 Gb/s** |
| 6 | ifPhysAddress | MAC |
| 7 | ifAdminStatus | 1 up, 2 down, 3 testing |
| 8 | ifOperStatus | 1 up, 2 down, 3 testing, 4 unknown, 5 dormant, 6 notPresent, 7 lowerLayerDown |
| 10 | ifInOctets | **32-bit — wraps in ~34 s at 1 Gb/s** |
| 13 | ifInDiscards | Congestion, not corruption |
| 14 | ifInErrors | CRC/framing: cabling, duplex mismatch, failing SFP |
| 16 | ifOutOctets | 32-bit |
| 19 | ifOutDiscards | Usually output queue drops |
| 20 | ifOutErrors | |

### ifXTable — `1.3.6.1.2.1.31.1.1.1.<column>` — prefer these

| Column | Name | Notes |
|---|---|---|
| 1 | ifName | Short form, e.g. `Gi0/1` |
| 6 | ifHCInOctets | **Counter64 — use this for traffic** |
| 10 | ifHCOutOctets | Counter64 |
| 7 / 11 | ifHCInUcastPkts / ifHCOutUcastPkts | Counter64 packet counts |
| 15 | ifHighSpeed | Speed in **Mb/s** — correct above 1 Gb/s |
| 18 | ifAlias | The port description an engineer configured; the most useful label on the whole device |

ifXTable requires SNMP v2c or v3. On v1 you are limited to 32-bit counters,
which is a reason to avoid v1 for traffic monitoring entirely.

## Other standard tables worth knowing

| OID | Purpose |
|---|---|
| `1.3.6.1.2.1.17.7.1.2.2.1.2` | dot1qTpFdbPort — MAC address table (which MAC on which port) |
| `1.3.6.1.2.1.17.1.4.1.2` | dot1dBasePortIfIndex — maps bridge port to ifIndex; needed to interpret the FDB |
| `1.3.6.1.2.1.4.22.1.2` | ipNetToMediaPhysAddress — ARP table (IP to MAC) |
| `1.3.6.1.2.1.31.1.2.1.3` | ifStackStatus — LAG/port-channel membership |
| `1.3.6.1.2.1.25.3.3.1.2` | hrProcessorLoad — CPU %, on devices with HOST-RESOURCES-MIB |
| `1.3.6.1.2.1.25.2.3.1.5/6` | hrStorageSize / hrStorageUsed — memory |
| `1.3.6.1.2.1.10.7.2.1.19` | dot3StatsDuplexStatus — 2 = half duplex, a classic error source |
| `1.3.6.1.2.1.105.1.1.1.*` | POWER-ETHERNET-MIB — standard PoE |

An LLDP neighbour table (`1.0.8802.1.1.2.1.4.1.1.*`, LLDP-MIB) is the fastest
route to an accurate topology map if the user wants one.

## Vendor OIDs

Probe these; do not assume. `sysObjectID` tells you which family you have.

### Cisco IOS / IOS-XE

| OID | Metric |
|---|---|
| `1.3.6.1.4.1.9.9.109.1.1.1.1.8` | cpmCPUTotal5minRev — CPU % over 5 min |
| `1.3.6.1.4.1.9.9.109.1.1.1.1.7` | cpmCPUTotal1minRev |
| `1.3.6.1.4.1.9.9.48.1.1.1.5` | ciscoMemoryPoolUsed |
| `1.3.6.1.4.1.9.9.48.1.1.1.6` | ciscoMemoryPoolFree |
| `1.3.6.1.4.1.9.9.13.1.3.1.3` | ciscoEnvMonTemperatureValue (°C) |
| `1.3.6.1.4.1.9.9.13.1.5.1.3` | ciscoEnvMonSupplyState — PSU health |
| `1.3.6.1.4.1.9.9.13.1.4.1.3` | ciscoEnvMonFanState |
| `1.3.6.1.4.1.9.9.402.1.2.1.7` | cpeExtPsePortPwrConsumption — PoE draw per port |

### HPE / Aruba (ProCurve, ArubaOS-Switch)

| OID | Metric |
|---|---|
| `1.3.6.1.4.1.11.2.14.11.5.1.9.6.1.0` | CPU % |
| `1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.6` | Memory allocated |
| `1.3.6.1.4.1.11.2.14.11.5.1.1.2.1.1.1.7` | Memory free |
| `1.3.6.1.4.1.11.2.14.11.5.1.55.1.1.1.1.4` | Temperature |

Aruba CX (newer) uses the ENTITY-SENSOR-MIB instead:
`1.3.6.1.2.1.99.1.1.1.4` (entPhySensorValue).

### Juniper

| OID | Metric |
|---|---|
| `1.3.6.1.4.1.2636.3.1.13.1.8` | jnxOperatingCPU |
| `1.3.6.1.4.1.2636.3.1.13.1.11` | jnxOperatingBuffer — memory % |
| `1.3.6.1.4.1.2636.3.1.13.1.7` | jnxOperatingTemp |

### MikroTik RouterOS

| OID | Metric |
|---|---|
| `1.3.6.1.2.1.25.3.3.1.2.1` | CPU load % (uses HOST-RESOURCES) |
| `1.3.6.1.4.1.14988.1.1.3.10.0` | Temperature (×0.1 °C) |
| `1.3.6.1.4.1.14988.1.1.3.8.0` | Voltage (×0.1 V) |
| `1.3.6.1.4.1.14988.1.1.1.3.1.*` | Wireless registration table |

### Ubiquiti

UniFi and EdgeSwitch expose standard MIB-II and HOST-RESOURCES; use
`1.3.6.1.2.1.25.3.3.1.2` for CPU. EdgeRouter adds
`1.3.6.1.4.1.41112.1.5.*`. UniFi APs report clients under
`1.3.6.1.4.1.41112.1.6.1.2.1.8`.

### Net-SNMP (Linux hosts, some appliances)

| OID | Metric |
|---|---|
| `1.3.6.1.4.1.2021.10.1.3.1` | 1-minute load average |
| `1.3.6.1.4.1.2021.4.5.0` | Total RAM |
| `1.3.6.1.4.1.2021.4.6.0` | Available RAM |
| `1.3.6.1.4.1.2021.11.11.0` | CPU idle % |

## Interpreting error counters

- **ifInErrors rising** — physical layer. Bad patch lead, dirty fibre, failing
  SFP, or duplex mismatch. Check `dot3StatsDuplexStatus`; half duplex on a
  modern link is nearly always a misconfiguration.
- **ifInDiscards / ifOutDiscards rising** — the link is fine, the device is
  congested or a buffer overflowed. Correlate with utilisation.
- **Errors on one port only** — cable or optic.
- **Errors across many ports at once** — the switch itself, or a shared
  upstream fault.
