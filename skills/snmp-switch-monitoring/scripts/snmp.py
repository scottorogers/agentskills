"""Minimal SNMP client using only the Python standard library.

Supports SNMP v1, v2c and v3 (USM) over UDP. No pip install required.

Why not pysnmp: the ubiquitous `from pysnmp.hlapi import *` / `getCmd()`
recipe is the pysnmp 4.x API and does not work on pysnmp 6.x. Depending on
it makes a deployment fail at `pip install` time on a customer's jump box.
This module is ~600 lines of stdlib and has no such failure mode.

Public API:

    s = Session("10.0.0.1", community="public")
    s.get(["1.3.6.1.2.1.1.1.0"])          -> {oid: VarBind}
    s.walk("1.3.6.1.2.1.2.2.1.2")         -> [VarBind, ...]
    s.close()

SNMPv3:

    s = Session("10.0.0.1", version="3", username="netmon",
                auth_proto="SHA", auth_pass="...", priv_proto="AES",
                priv_pass="...")
"""

from __future__ import annotations

import hashlib
import hmac
import os
import random
import socket
import struct
import time
from typing import Iterable, NamedTuple

__all__ = [
    "Session",
    "VarBind",
    "SnmpError",
    "SnmpTimeout",
    "SnmpAuthError",
    "SnmpPduError",
    "oid_lt",
    "oid_startswith",
]

# --------------------------------------------------------------------------
# Errors
# --------------------------------------------------------------------------


class SnmpError(Exception):
    """Base class for all SNMP failures."""


class SnmpTimeout(SnmpError):
    """No response from the agent within timeout*(retries+1)."""


class SnmpAuthError(SnmpError):
    """Wrong community string, unknown v3 user, or bad auth/priv password."""


class SnmpPduError(SnmpError):
    """Agent answered with a non-zero error-status."""

    def __init__(self, status: int, index: int, oid: str | None = None):
        self.status = status
        self.index = index
        self.oid = oid
        name = PDU_ERRORS.get(status, f"error {status}")
        where = f" at {oid}" if oid else (f" at varbind {index}" if index else "")
        super().__init__(f"{name}{where}")


PDU_ERRORS = {
    1: "tooBig",
    2: "noSuchName (OID not supported by this device)",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    6: "noAccess",
    7: "wrongType",
    8: "wrongLength",
    9: "wrongEncoding",
    10: "wrongValue",
    11: "noCreation",
    12: "inconsistentValue",
    13: "resourceUnavailable",
    14: "commitFailed",
    15: "undoFailed",
    16: "authorizationError",
    17: "notWritable",
    18: "inconsistentName",
}

# --------------------------------------------------------------------------
# BER / ASN.1
# --------------------------------------------------------------------------

T_INTEGER = 0x02
T_OCTETS = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQUENCE = 0x30
T_IPADDRESS = 0x40
T_COUNTER32 = 0x41
T_GAUGE32 = 0x42
T_TIMETICKS = 0x43
T_OPAQUE = 0x44
T_COUNTER64 = 0x46
T_NOSUCHOBJECT = 0x80
T_NOSUCHINSTANCE = 0x81
T_ENDOFMIBVIEW = 0x82

T_GET = 0xA0
T_GETNEXT = 0xA1
T_RESPONSE = 0xA2
T_SET = 0xA3
T_TRAP_V1 = 0xA4
T_GETBULK = 0xA5
T_INFORM = 0xA6
T_TRAP_V2 = 0xA7
T_REPORT = 0xA8

_TYPE_NAMES = {
    T_INTEGER: "INTEGER",
    T_OCTETS: "STRING",
    T_NULL: "NULL",
    T_OID: "OID",
    T_IPADDRESS: "IpAddress",
    T_COUNTER32: "Counter32",
    T_GAUGE32: "Gauge32",
    T_TIMETICKS: "TimeTicks",
    T_OPAQUE: "Opaque",
    T_COUNTER64: "Counter64",
    T_NOSUCHOBJECT: "noSuchObject",
    T_NOSUCHINSTANCE: "noSuchInstance",
    T_ENDOFMIBVIEW: "endOfMibView",
}

# Tags whose value is an unsigned integer.
_UNSIGNED = (T_COUNTER32, T_GAUGE32, T_TIMETICKS, T_COUNTER64)
# Tags that mean "this OID has no value here" rather than carrying data.
_EXCEPTIONS = (T_NOSUCHOBJECT, T_NOSUCHINSTANCE, T_ENDOFMIBVIEW)


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(payload)) + payload


def _enc_int(value: int, tag: int = T_INTEGER) -> bytes:
    # Minimal two's-complement encoding. Unsigned SNMP types reuse this, which
    # correctly prepends a 0x00 byte when the high bit would look negative.
    length = 1
    while True:
        try:
            body = value.to_bytes(length, "big", signed=True)
            break
        except OverflowError:
            length += 1
    return _tlv(tag, body)


def _enc_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.strip(". ").split(".") if p != ""]
    if len(parts) < 2:
        raise SnmpError(f"OID too short: {oid!r}")
    body = bytearray()
    body.append(40 * parts[0] + parts[1])
    for num in parts[2:]:
        if num < 0:
            raise SnmpError(f"negative sub-identifier in OID: {oid!r}")
        chunk = [num & 0x7F]
        num >>= 7
        while num:
            chunk.append((num & 0x7F) | 0x80)
            num >>= 7
        body.extend(reversed(chunk))
    return _tlv(T_OID, bytes(body))


def _dec_tlv(buf: bytes, pos: int) -> tuple[int, bytes, int]:
    """Return (tag, content, next_pos)."""
    if pos + 2 > len(buf):
        raise SnmpError("truncated SNMP message (header)")
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        nbytes = length & 0x7F
        if nbytes == 0 or pos + nbytes > len(buf):
            raise SnmpError("truncated SNMP message (length)")
        length = int.from_bytes(buf[pos : pos + nbytes], "big")
        pos += nbytes
    end = pos + length
    if end > len(buf):
        raise SnmpError("truncated SNMP message (content)")
    return tag, buf[pos:end], end


def _dec_oid(body: bytes) -> str:
    if not body:
        raise SnmpError("empty OID")
    parts = [body[0] // 40, body[0] % 40]
    acc = 0
    for byte in body[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(acc)
            acc = 0
    return "." + ".".join(str(p) for p in parts)


def _dec_value(tag: int, body: bytes):
    if tag == T_INTEGER:
        return int.from_bytes(body, "big", signed=True) if body else 0
    if tag in _UNSIGNED:
        return int.from_bytes(body, "big", signed=False) if body else 0
    if tag == T_OCTETS or tag == T_OPAQUE:
        return body
    if tag == T_OID:
        return _dec_oid(body)
    if tag == T_IPADDRESS:
        return ".".join(str(b) for b in body)
    if tag == T_NULL or tag in _EXCEPTIONS:
        return None
    return body


# --------------------------------------------------------------------------
# VarBind
# --------------------------------------------------------------------------


class VarBind(NamedTuple):
    oid: str
    type: str
    value: object

    @property
    def is_exception(self) -> bool:
        """True when the agent said this OID has no value (end of MIB etc)."""
        return self.type in ("noSuchObject", "noSuchInstance", "endOfMibView")

    def text(self) -> str:
        """Human-readable rendering, with the usual octet-string caveats."""
        v = self.value
        if v is None:
            return self.type if self.is_exception else ""
        if isinstance(v, bytes):
            # Physical addresses and some sysDescr values are binary.
            try:
                s = v.decode("utf-8")
            except UnicodeDecodeError:
                return ":".join(f"{b:02x}" for b in v)
            if any(ord(c) < 32 and c not in "\r\n\t" for c in s):
                return ":".join(f"{b:02x}" for b in v)
            return s.strip()
        return str(v)

    def int(self, default: int | None = None) -> int | None:
        if isinstance(self.value, int):
            return self.value
        return default


def _oid_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.strip(". ").split(".") if p != "")


def oid_lt(a: str, b: str) -> bool:
    """Lexicographic OID ordering, as SNMP agents use for GETNEXT."""
    return _oid_tuple(a) < _oid_tuple(b)


def oid_startswith(oid: str, root: str) -> bool:
    o, r = _oid_tuple(oid), _oid_tuple(root)
    return o[: len(r)] == r


# --------------------------------------------------------------------------
# SNMPv3 USM key derivation and crypto (RFC 3414 / RFC 3826 / RFC 7860)
# --------------------------------------------------------------------------

AUTH_PROTOCOLS = {
    # name: (hash constructor, digest length carried in the message)
    "MD5": (hashlib.md5, 12),
    "SHA": (hashlib.sha1, 12),
    "SHA1": (hashlib.sha1, 12),
    "SHA224": (hashlib.sha224, 16),
    "SHA256": (hashlib.sha256, 24),
    "SHA384": (hashlib.sha384, 32),
    "SHA512": (hashlib.sha512, 48),
}

PRIV_PROTOCOLS = {"DES", "AES", "AES128"}


def password_to_key(password: str, engine_id: bytes, proto: str) -> bytes:
    """RFC 3414 s2.6 password-to-key, then localization to the engine."""
    try:
        hash_ctor, _ = AUTH_PROTOCOLS[proto.upper()]
    except KeyError:
        raise SnmpError(
            f"unknown auth protocol {proto!r}; choose from {sorted(AUTH_PROTOCOLS)}"
        ) from None
    pw = password.encode("utf-8")
    if not pw:
        raise SnmpError("SNMPv3 auth password must not be empty")
    # RFC 3414 A.2.1 digests exactly 1048576 octets taken from the password
    # cyclically with a *running* index -- successive 64-byte blocks differ
    # unless len(password) divides 64, so the stream must not be built by
    # repeating one fixed block.
    total = 1048576
    stream = (pw * (total // len(pw) + 1))[:total]
    ku = hash_ctor(stream).digest()
    return hash_ctor(ku + engine_id + ku).digest()


def _localize_priv_key(key: bytes, proto: str, hash_ctor, engine_id: bytes) -> bytes:
    """Extend a localized auth key to the length a cipher needs.

    DES/AES-128 need 16 bytes. MD5 gives exactly 16; SHA-1 and friends give
    more, so we truncate. (Key extension for longer ciphers follows RFC 7860's
    approach of re-hashing, which we do not need for DES/AES-128.)
    """
    need = 16
    if len(key) >= need:
        return key[:need]
    out = key
    while len(out) < need:
        out += hash_ctor(out + engine_id + out).digest()
    return out[:need]


def _des_encrypt(key: bytes, boots: int, plaintext: bytes) -> tuple[bytes, bytes]:
    des_key, pre_iv = key[:8], key[8:16]
    salt = struct.pack(">II", boots, random.getrandbits(31))
    iv = bytes(a ^ b for a, b in zip(pre_iv, salt))
    pad = (-len(plaintext)) % 8
    plaintext += b"\x00" * pad
    return _des_cbc(des_key, iv, plaintext, encrypt=True), salt


def _des_decrypt(key: bytes, salt: bytes, ciphertext: bytes) -> bytes:
    if len(salt) != 8:
        raise SnmpError("bad DES privacy parameters")
    des_key, pre_iv = key[:8], key[8:16]
    iv = bytes(a ^ b for a, b in zip(pre_iv, salt))
    return _des_cbc(des_key, iv, ciphertext, encrypt=False)


def _des_cbc(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = _load_cipher("DES")
    return cipher(key, iv, data, encrypt)


def _aes_cfb(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = _load_cipher("AES")
    return cipher(key, iv, data, encrypt)


def _load_cipher(kind: str):
    """Return a cipher callable, or raise a clear message about the extra."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError:
        raise SnmpError(
            "SNMPv3 privacy (encryption) needs the 'cryptography' package:\n"
            "    pip install cryptography\n"
            "Auth-only v3 (authNoPriv) and v2c work with no dependencies."
        ) from None
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:
        # A half-broken install (missing _cffi_backend, ABI mismatch) raises
        # things that are not ImportError -- including pyo3 PanicException,
        # which does not even inherit from Exception.
        raise SnmpError(
            f"the 'cryptography' package is installed but not usable "
            f"({type(exc).__name__}: {exc}). Reinstall it with "
            f"'pip install --force-reinstall cryptography', or use SNMPv3 "
            f"authNoPriv / v2c, which need no packages."
        ) from None

    # SNMPv3's ciphers are old, and 'cryptography' is progressively relocating
    # them to its 'decrepit' namespace: TripleDES in 43+, CFB mode in 49+.
    try:
        from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    except ImportError:
        TripleDES = getattr(algorithms, "TripleDES", None)
    try:
        from cryptography.hazmat.decrepit.ciphers.modes import CFB
    except ImportError:
        CFB = getattr(modes, "CFB", None)

    def run(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
        if kind == "DES":
            if TripleDES is None:
                raise SnmpError(
                    "this build of 'cryptography' no longer provides DES; "
                    "use AES privacy instead"
                )
            algo = TripleDES(key * 3)  # DES via 3DES with K1=K2=K3
            mode = modes.CBC(iv)
        else:
            if CFB is None:
                raise SnmpError(
                    "this build of 'cryptography' does not provide CFB mode, "
                    "which SNMPv3 AES privacy requires"
                )
            algo = algorithms.AES(key)
            mode = CFB(iv)
        cipher = Cipher(algo, mode)
        op = cipher.encryptor() if encrypt else cipher.decryptor()
        return op.update(data) + op.finalize()

    return run


# --------------------------------------------------------------------------
# Session
# --------------------------------------------------------------------------

VERSION_CODES = {"1": 0, "2c": 1, "3": 3}


class Session:
    """A UDP SNMP conversation with one agent.

    Not thread-safe; create one Session per thread.
    """

    def __init__(
        self,
        host: str,
        community: str = "public",
        port: int = 161,
        version: str = "2c",
        timeout: float = 2.0,
        retries: int = 2,
        username: str = "",
        auth_proto: str | None = None,
        auth_pass: str | None = None,
        priv_proto: str | None = None,
        priv_pass: str | None = None,
        context: str = "",
    ):
        # Allow "host:port" for lab/simulator use.
        if ":" in host and not host.count(":") > 1:
            maybe_host, _, maybe_port = host.rpartition(":")
            if maybe_port.isdigit():
                host, port = maybe_host, int(maybe_port)
        self.host = host
        self.port = int(port)
        self.version = str(version).lower()
        if self.version not in VERSION_CODES:
            raise SnmpError(
                f"unsupported SNMP version {version!r}; use '1', '2c' or '3'"
            )
        self.community = community
        self.timeout = float(timeout)
        self.retries = int(retries)
        self.username = username
        self.auth_proto = (auth_proto or "").upper() or None
        self.auth_pass = auth_pass
        self.priv_proto = (priv_proto or "").upper() or None
        self.priv_pass = priv_pass
        self.context = context

        if self.priv_proto in ("AES128",):
            self.priv_proto = "AES"
        if self.version == "3":
            if not username:
                raise SnmpError("SNMPv3 requires username=")
            if self.priv_proto and not self.auth_proto:
                raise SnmpError("SNMPv3 privacy requires authentication as well")
            if self.priv_proto and self.priv_proto not in PRIV_PROTOCOLS:
                raise SnmpError(
                    f"unknown priv protocol {priv_proto!r}; use DES or AES"
                )

        self._sock: socket.socket | None = None
        self._request_id = random.randint(1, 0x7FFFFFFF)
        # v3 engine state, learned by discovery.
        self._engine_id = b""
        self._engine_boots = 0
        self._engine_time = 0
        self._engine_time_at = 0.0
        self._auth_key = b""
        self._priv_key = b""

    # -- lifecycle ---------------------------------------------------------

    def _socket(self) -> socket.socket:
        if self._sock is None:
            try:
                infos = socket.getaddrinfo(
                    self.host, self.port, 0, socket.SOCK_DGRAM
                )
            except socket.gaierror as exc:
                raise SnmpError(f"cannot resolve {self.host!r}: {exc}") from None
            family, _, _, _, sockaddr = infos[0]
            sock = socket.socket(family, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            # connect() on a UDP socket does two useful things: the kernel drops
            # datagrams from any other source, and ICMP port-unreachable is
            # reported to us as ECONNREFUSED instead of silently vanishing --
            # which is what distinguishes "no SNMP agent" from "firewalled".
            sock.connect(sockaddr)
            self._sock = sock
        return self._sock

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- high level operations --------------------------------------------

    def get(self, oids: Iterable[str]) -> dict[str, VarBind]:
        """GET one or more OIDs. Returns {requested_oid: VarBind}."""
        oids = list(oids)
        binds = self._request(T_GET, [(o, None) for o in oids])
        out: dict[str, VarBind] = {}
        for requested, bind in zip(oids, binds):
            out[requested] = bind
        return out

    def get_one(self, oid: str) -> VarBind | None:
        """GET a single OID, returning None if unsupported by the device."""
        bind = self.get([oid]).get(oid)
        if bind is None or bind.is_exception:
            return None
        return bind

    def get_next(self, oids: Iterable[str]) -> list[VarBind]:
        return self._request(T_GETNEXT, [(o, None) for o in oids])

    def walk(self, root: str, max_rows: int = 20000) -> list[VarBind]:
        """Walk a subtree. Uses GETBULK on v2c/v3, GETNEXT on v1.

        Stops at the first OID outside `root`, which is what makes a walk of a
        single column cheap even on a 48-port switch with a big MIB.
        """
        root = root if root.startswith(".") else "." + root.lstrip(".")
        results: list[VarBind] = []
        current = root
        use_bulk = self.version in ("2c", "3")
        repetitions = 25
        while len(results) < max_rows:
            if use_bulk:
                try:
                    binds = self._request(
                        T_GETBULK,
                        [(current, None)],
                        non_repeaters=0,
                        max_repetitions=repetitions,
                    )
                except SnmpPduError as exc:
                    if exc.status == 1 and repetitions > 1:  # tooBig
                        repetitions = max(1, repetitions // 4)
                        continue
                    raise
            else:
                binds = self._request(T_GETNEXT, [(current, None)])
            if not binds:
                break
            progressed = False
            for bind in binds:
                if bind.type == "endOfMibView" or not oid_startswith(bind.oid, root):
                    return results
                if not oid_lt(current, bind.oid) and current != root:
                    # Agent is not advancing; bail out rather than loop forever.
                    return results
                results.append(bind)
                current = bind.oid
                progressed = True
                if len(results) >= max_rows:
                    break
            if not progressed:
                break
        return results

    def walk_table(self, columns: dict[str, str], root_hint: str | None = None):
        """Walk several columns and join them by row index.

        `columns` maps a friendly name to a column OID. Returns
        {index: {name: VarBind}} where index is the trailing OID fragment.
        """
        rows: dict[str, dict[str, VarBind]] = {}
        for name, col_oid in columns.items():
            col = "." + col_oid.strip(". ")
            for bind in self.walk(col):
                index = bind.oid[len(col) :].lstrip(".")
                rows.setdefault(index, {})[name] = bind
        return rows

    # -- protocol ----------------------------------------------------------

    def _next_request_id(self) -> int:
        self._request_id = (self._request_id + 1) & 0x7FFFFFFF or 1
        return self._request_id

    def _request(
        self,
        pdu_type: int,
        varbinds: list[tuple[str, object]],
        non_repeaters: int = 0,
        max_repetitions: int = 0,
    ) -> list[VarBind]:
        if self.version == "3":
            return self._request_v3(
                pdu_type, varbinds, non_repeaters, max_repetitions
            )
        return self._request_community(
            pdu_type, varbinds, non_repeaters, max_repetitions
        )

    def _encode_pdu(
        self,
        pdu_type: int,
        request_id: int,
        varbinds: list[tuple[str, object]],
        non_repeaters: int,
        max_repetitions: int,
    ) -> bytes:
        vb_blob = b"".join(
            _tlv(T_SEQUENCE, _enc_oid(oid) + _tlv(T_NULL, b""))
            for oid, _ in varbinds
        )
        if pdu_type == T_GETBULK:
            head = (
                _enc_int(request_id)
                + _enc_int(non_repeaters)
                + _enc_int(max_repetitions)
            )
        else:
            head = _enc_int(request_id) + _enc_int(0) + _enc_int(0)
        return _tlv(pdu_type, head + _tlv(T_SEQUENCE, vb_blob))

    def _decode_pdu(self, body: bytes) -> tuple[int, int, int, int, list[VarBind]]:
        """Return (pdu_type, request_id, error_status, error_index, varbinds)."""
        pdu_type, pdu_body, _ = _dec_tlv(body, 0)
        pos = 0
        _, rid_raw, pos = _dec_tlv(pdu_body, pos)
        request_id = int.from_bytes(rid_raw, "big", signed=True) if rid_raw else 0
        _, err_raw, pos = _dec_tlv(pdu_body, pos)
        error_status = int.from_bytes(err_raw, "big", signed=True) if err_raw else 0
        _, idx_raw, pos = _dec_tlv(pdu_body, pos)
        error_index = int.from_bytes(idx_raw, "big", signed=True) if idx_raw else 0
        _, vb_blob, pos = _dec_tlv(pdu_body, pos)

        binds: list[VarBind] = []
        vpos = 0
        while vpos < len(vb_blob):
            _, one, vpos = _dec_tlv(vb_blob, vpos)
            opos = 0
            tag, oid_raw, opos = _dec_tlv(one, opos)
            if tag != T_OID:
                raise SnmpError("malformed varbind (expected OID)")
            vtag, vraw, opos = _dec_tlv(one, opos)
            binds.append(
                VarBind(
                    _dec_oid(oid_raw),
                    _TYPE_NAMES.get(vtag, f"tag-0x{vtag:02x}"),
                    _dec_value(vtag, vraw),
                )
            )
        return pdu_type, request_id, error_status, error_index, binds

    def _exchange(self, payload: bytes) -> bytes:
        sock = self._socket()
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                sock.settimeout(self.timeout)
                sock.send(payload)
                return sock.recv(65535)
            except socket.timeout as exc:
                last_exc = exc
                continue
            except ConnectionRefusedError:
                # ICMP port-unreachable: the host is up but no agent is bound.
                raise SnmpError(
                    f"nothing is listening on UDP/{self.port} at {self.host} "
                    f"- the host is reachable but its SNMP agent is not "
                    f"running or not enabled"
                ) from None
            except OSError as exc:
                last_exc = exc
                if attempt == self.retries:
                    raise SnmpError(
                        f"network error talking to {self.host}:{self.port}: {exc}"
                    ) from None
                continue
        raise SnmpTimeout(
            f"no response from {self.host}:{self.port} after "
            f"{self.retries + 1} attempt(s) of {self.timeout:g}s "
            f"(check reachability, UDP/{self.port} firewalling, and credentials)"
        ) from last_exc

    # -- v1 / v2c ----------------------------------------------------------

    def _request_community(
        self,
        pdu_type: int,
        varbinds: list[tuple[str, object]],
        non_repeaters: int,
        max_repetitions: int,
    ) -> list[VarBind]:
        if pdu_type == T_GETBULK and self.version == "1":
            raise SnmpError("GETBULK requires SNMP v2c or v3")
        request_id = self._next_request_id()
        pdu = self._encode_pdu(
            pdu_type, request_id, varbinds, non_repeaters, max_repetitions
        )
        message = _tlv(
            T_SEQUENCE,
            _enc_int(VERSION_CODES[self.version])
            + _tlv(T_OCTETS, self.community.encode())
            + pdu,
        )
        raw = self._exchange(message)

        _, body, _ = _dec_tlv(raw, 0)
        pos = 0
        _, _, pos = _dec_tlv(body, pos)  # version
        _, _, pos = _dec_tlv(body, pos)  # community
        _, rid, status, index, binds = self._decode_pdu(body[pos:])
        if rid != request_id:
            raise SnmpError(
                f"response request-id {rid} does not match request {request_id}"
            )
        self._raise_for_status(status, index, varbinds)
        return binds

    def _raise_for_status(self, status, index, varbinds):
        if not status:
            return
        oid = None
        if 0 < index <= len(varbinds):
            oid = varbinds[index - 1][0]
        if status == 16:
            raise SnmpAuthError(
                "authorizationError: the credentials are valid but this view "
                "does not permit the requested OID"
            )
        raise SnmpPduError(status, index, oid)

    # -- v3 ----------------------------------------------------------------

    def _flags(self, reportable: bool = True) -> int:
        flags = 0x04 if reportable else 0x00
        if self.auth_proto:
            flags |= 0x01
        if self.priv_proto:
            flags |= 0x02
        return flags

    def _discover_engine(self) -> None:
        """RFC 3414 s4: an unauthenticated probe returns the engine ID."""
        msg_id = self._next_request_id()
        probe_pdu = self._encode_pdu(T_GET, self._next_request_id(), [], 0, 0)
        scoped = _tlv(
            T_SEQUENCE, _tlv(T_OCTETS, b"") + _tlv(T_OCTETS, b"") + probe_pdu
        )
        usm = _tlv(
            T_SEQUENCE,
            _tlv(T_OCTETS, b"")
            + _enc_int(0)
            + _enc_int(0)
            + _tlv(T_OCTETS, b"")
            + _tlv(T_OCTETS, b"")
            + _tlv(T_OCTETS, b""),
        )
        header = _tlv(
            T_SEQUENCE,
            _enc_int(msg_id) + _enc_int(65507) + _tlv(T_OCTETS, b"\x04") + _enc_int(3),
        )
        message = _tlv(
            T_SEQUENCE, _enc_int(3) + header + _tlv(T_OCTETS, usm) + scoped
        )
        raw = self._exchange(message)
        engine_id, boots, etime, _, _ = self._parse_v3_security(raw)
        if not engine_id:
            raise SnmpAuthError(
                "engine discovery returned no engine ID; the agent may not "
                "have SNMPv3 enabled"
            )
        self._engine_id = engine_id
        self._engine_boots = boots
        self._engine_time = etime
        self._engine_time_at = time.monotonic()
        if self.auth_proto:
            self._auth_key = password_to_key(
                self.auth_pass or "", engine_id, self.auth_proto
            )
        if self.priv_proto:
            hash_ctor, _ = AUTH_PROTOCOLS[self.auth_proto]
            base = password_to_key(self.priv_pass or "", engine_id, self.auth_proto)
            self._priv_key = _localize_priv_key(
                base, self.priv_proto, hash_ctor, engine_id
            )

    @staticmethod
    def _parse_v3_security(raw: bytes):
        """Pull engine id/boots/time, priv params and msgData out of a v3 message."""
        _, body, _ = _dec_tlv(raw, 0)
        pos = 0
        _, _, pos = _dec_tlv(body, pos)  # msgVersion
        _, header, pos = _dec_tlv(body, pos)  # msgGlobalData
        _, sec_blob, pos = _dec_tlv(body, pos)  # msgSecurityParameters
        data_tag, msg_data, _ = _dec_tlv(body, pos)

        hpos = 0
        _, _, hpos = _dec_tlv(header, hpos)  # msgID
        _, _, hpos = _dec_tlv(header, hpos)  # msgMaxSize
        _, flags_raw, hpos = _dec_tlv(header, hpos)
        flags = flags_raw[0] if flags_raw else 0

        _, usm, _ = _dec_tlv(sec_blob, 0)
        upos = 0
        _, engine_id, upos = _dec_tlv(usm, upos)
        _, boots_raw, upos = _dec_tlv(usm, upos)
        _, time_raw, upos = _dec_tlv(usm, upos)
        _, _user, upos = _dec_tlv(usm, upos)
        _, _auth_params, upos = _dec_tlv(usm, upos)
        _, priv_params, upos = _dec_tlv(usm, upos)

        boots = int.from_bytes(boots_raw, "big") if boots_raw else 0
        etime = int.from_bytes(time_raw, "big") if time_raw else 0
        return engine_id, boots, etime, priv_params, (data_tag, msg_data, flags)

    def _request_v3(
        self,
        pdu_type: int,
        varbinds: list[tuple[str, object]],
        non_repeaters: int,
        max_repetitions: int,
    ) -> list[VarBind]:
        if not self._engine_id:
            self._discover_engine()

        for attempt in (0, 1):
            request_id = self._next_request_id()
            msg_id = self._next_request_id()
            pdu = self._encode_pdu(
                pdu_type, request_id, varbinds, non_repeaters, max_repetitions
            )
            context_engine = self._engine_id
            scoped_plain = _tlv(
                T_SEQUENCE,
                _tlv(T_OCTETS, context_engine)
                + _tlv(T_OCTETS, self.context.encode())
                + pdu,
            )

            elapsed = int(time.monotonic() - self._engine_time_at)
            eng_time = self._engine_time + elapsed

            priv_params = b""
            if self.priv_proto:
                if self.priv_proto == "DES":
                    encrypted, priv_params = _des_encrypt(
                        self._priv_key, self._engine_boots, scoped_plain
                    )
                else:
                    salt = os.urandom(8)
                    iv = struct.pack(">II", self._engine_boots, eng_time) + salt
                    encrypted = _aes_cfb(
                        self._priv_key[:16], iv, scoped_plain, encrypt=True
                    )
                    priv_params = salt
                msg_data = _tlv(T_OCTETS, encrypted)
            else:
                msg_data = scoped_plain

            auth_len = AUTH_PROTOCOLS[self.auth_proto][1] if self.auth_proto else 0
            placeholder = b"\x00" * auth_len
            header = _tlv(
                T_SEQUENCE,
                _enc_int(msg_id)
                + _enc_int(65507)
                + _tlv(T_OCTETS, bytes([self._flags()]))
                + _enc_int(3),
            )

            def build(auth_params: bytes) -> bytes:
                usm = _tlv(
                    T_SEQUENCE,
                    _tlv(T_OCTETS, self._engine_id)
                    + _enc_int(self._engine_boots)
                    + _enc_int(eng_time)
                    + _tlv(T_OCTETS, self.username.encode())
                    + _tlv(T_OCTETS, auth_params)
                    + _tlv(T_OCTETS, priv_params),
                )
                return _tlv(
                    T_SEQUENCE,
                    _enc_int(3) + header + _tlv(T_OCTETS, usm) + msg_data,
                )

            message = build(placeholder)
            if self.auth_proto:
                hash_ctor, digest_len = AUTH_PROTOCOLS[self.auth_proto]
                mac = hmac.new(self._auth_key, message, hash_ctor).digest()[
                    :digest_len
                ]
                message = build(mac)

            raw = self._exchange(message)
            engine_id, boots, etime, resp_priv, (tag, data, flags) = (
                self._parse_v3_security(raw)
            )

            # _parse_v3_security already stripped the outer tag, so `data` is
            # the ScopedPDU's *content* when the message is unencrypted, but
            # the OCTET STRING's ciphertext when it is encrypted -- and
            # decrypting yields a whole ScopedPDU that still needs unwrapping.
            if self.priv_proto and tag == T_OCTETS:
                plaintext = self._decrypt(data, resp_priv, boots, etime)
                _, scoped, _ = _dec_tlv(plaintext, 0)
            else:
                scoped = data
            spos = 0
            _, _, spos = _dec_tlv(scoped, spos)  # contextEngineID
            _, _, spos = _dec_tlv(scoped, spos)  # contextName
            ptype, rid, status, index, binds = self._decode_pdu(scoped[spos:])

            if ptype == T_REPORT:
                # Time-window desync: resync once and retry, per RFC 3414 s3.2.
                if attempt == 0 and (boots != self._engine_boots or engine_id):
                    self._engine_id = engine_id or self._engine_id
                    self._engine_boots = boots
                    self._engine_time = etime
                    self._engine_time_at = time.monotonic()
                    continue
                raise SnmpAuthError(self._describe_report(binds))
            if rid != request_id:
                raise SnmpError(
                    f"response request-id {rid} does not match request {request_id}"
                )
            self._raise_for_status(status, index, varbinds)
            return binds
        raise SnmpAuthError("SNMPv3 authentication failed after resynchronisation")

    def _decrypt(self, data: bytes, priv_params: bytes, boots: int, etime: int) -> bytes:
        if self.priv_proto == "DES":
            return _des_decrypt(self._priv_key, priv_params, data)
        iv = struct.pack(">II", boots, etime) + priv_params
        return _aes_cfb(self._priv_key[:16], iv, data, encrypt=False)

    @staticmethod
    def _describe_report(binds: list[VarBind]) -> str:
        known = {
            ".1.3.6.1.6.3.15.1.1.1.0": "unsupported security level",
            ".1.3.6.1.6.3.15.1.1.2.0": "not in time window (clock skew)",
            ".1.3.6.1.6.3.15.1.1.3.0": "unknown user name",
            ".1.3.6.1.6.3.15.1.1.4.0": "unknown engine ID",
            ".1.3.6.1.6.3.15.1.1.5.0": "wrong digest (bad auth password)",
            ".1.3.6.1.6.3.15.1.1.6.0": "decryption error (bad priv password)",
        }
        for bind in binds:
            if bind.oid in known:
                return f"SNMPv3 rejected: {known[bind.oid]}"
        return "SNMPv3 rejected the request (report PDU)"
