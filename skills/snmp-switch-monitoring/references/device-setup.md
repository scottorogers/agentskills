# Enabling SNMP, per vendor

Read-only access is all this skill needs. Never configure a read-write
community for monitoring — it converts a monitoring credential leak into a
device-takeover.

Two rules that apply everywhere:

- **Restrict by source IP.** An ACL limiting SNMP to the polling host is the
  single most valuable control here, because v1/v2c community strings cross
  the wire in cleartext.
- **Do not use `public`.** It is the default everyone scans for.

## Cisco IOS / IOS-XE

```
! Read-only community restricted to the poller
access-list 20 permit 10.0.0.5
snmp-server community S0me-Long-Random-String RO 20
snmp-server location "Comms Room A, Rack 3"
snmp-server contact "netops@example.com"
```

SNMPv3 (preferred — authenticated and encrypted):

```
snmp-server group MONITOR v3 priv
snmp-server user netmon MONITOR v3 auth sha AuthPassphrase priv aes 128 PrivPassphrase
```

Then poll with:

```bash
python3 scripts/netmon.py check 10.0.0.1 -v 3 -u netmon \
  --auth-proto SHA --auth-pass AuthPassphrase \
  --priv-proto AES --priv-pass PrivPassphrase
```

Verify on the device with `show snmp community` and `show snmp user`.

## Cisco NX-OS

```
snmp-server community S0me-Long-Random-String group network-operator
snmp-server user netmon network-operator auth sha AuthPassphrase priv aes-128 PrivPassphrase
```

## HPE / Aruba (ProCurve, ArubaOS-Switch)

```
snmp-server community "S0me-Long-Random-String" operator restricted
snmp-server host 10.0.0.5 community "S0me-Long-Random-String"
```

`restricted` is read-only; `unrestricted` is read-write — do not use it.

## Aruba CX

```
snmp-server vrf mgmt
snmp-server community S0me-Long-Random-String
snmpv3 user netmon auth sha auth-pass plaintext AuthPassphrase priv aes priv-pass plaintext PrivPassphrase
```

## Juniper Junos

```
set snmp community S0me-Long-Random-String authorization read-only
set snmp community S0me-Long-Random-String clients 10.0.0.5/32
set snmp location "Comms Room A"
commit
```

## MikroTik RouterOS

```
/snmp community set [find default=yes] name=S0me-Long-Random-String addresses=10.0.0.5/32
/snmp set enabled=yes contact="netops@example.com" location="Comms Room A"
```

RouterOS ships with SNMP **disabled**; `enabled=yes` is required.

## Ubiquiti UniFi

SNMP is set network-wide, not per device: UniFi Network application →
Settings → System → Advanced → SNMP. Enable v1/v2c and set the community.
Changes provision out to the switches and APs within a minute or two.

## Ubiquiti EdgeSwitch / EdgeRouter

```
configure
set service snmp community S0me-Long-Random-String authorization ro
set service snmp community S0me-Long-Random-String client 10.0.0.5
commit ; save
```

## Netgear smart switches (GS/M series)

Web UI → System → SNMP → Community Configuration. Add a community with
access `Read Only`, set the management station IP, and confirm the SNMP
service is enabled under SNMP → Global Configuration. Many Netgear "Plus"
(non-smart) models do not support SNMP at all.

## TP-Link JetStream

Web UI → Maintenance → SNMP → SNMP Config. Enable SNMP, create a View
(default `viewDefault` covers `1.3.6.1`), a Group with read-only access, and
a Community bound to that group.

## Linux / BSD hosts (net-snmp)

```bash
sudo apt install snmpd          # or: dnf install net-snmp
```

`/etc/snmp/snmpd.conf`:

```
agentAddress udp:161
rocommunity S0me-Long-Random-String 10.0.0.5
sysLocation  "Comms Room A"
sysContact   netops@example.com
```

```bash
sudo systemctl restart snmpd
```

Debian's default config binds to `127.0.0.1` only — the `agentAddress` line
above is what makes it reachable from the network.

## Confirming it worked

From the polling host:

```bash
python3 scripts/netmon.py check <device-ip> -c <community>
```

A full port table means SNMP is correctly configured. Silence means the
community is wrong, the source IP is not permitted, or UDP/161 is filtered —
see `troubleshooting.md`.

## SNMPv3 notes

- `authNoPriv` (auth, no encryption) works with **no extra packages**.
- `authPriv` (encrypted) needs `pip install cryptography` for AES/DES.
- Auth protocols supported: MD5, SHA, SHA224, SHA256, SHA384, SHA512.
  Prefer SHA256 or better; MD5 and SHA1 remain common on older hardware.
- Passphrases must be at least 8 characters — devices reject shorter ones.
- v3 keys are localised to the device's engine ID, so the same passphrase
  produces a different key on each device. This is expected, and it is why
  the tool performs engine discovery before the first authenticated request.
