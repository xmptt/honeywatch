#!/usr/bin/env python3
"""
Honeypot - Defensive Security Tool
Emulates SSH, Telnet, FTP, and HTTP services to detect and log attacker activity.
Captures credentials submitted by scanners/bots and logs all connection attempts.
Use only on systems you own or are authorized to monitor.

Dependencies:
    pip install requests  (optional, for online GeoIP fallback)

Optional GeoIP (offline, faster):
    pip install geoip2
    Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Default ports (no sudo required):
    SSH    -> 2222
    Telnet -> 2323
    FTP    -> 2121
    HTTP   -> 8880

Usage:
    python honeypot.py
    python honeypot.py --ssh-port 2222 --http-port 8880 --ioc-file iocs.txt
    sudo python honeypot.py --ssh-port 22 --http-port 80   # real ports need sudo
"""

import os
import ssl
import socket
import struct
import secrets
import threading
import logging
import argparse
import json
import ipaddress
import re
import time
from urllib.parse import parse_qs
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import geoip2.database
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("honeypot.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

ALERT_LOG = logging.getLogger("honeypot.alerts")
_alert_handler = logging.FileHandler("honeypot_alerts.log")
_alert_handler.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
ALERT_LOG.addHandler(_alert_handler)
ALERT_LOG.setLevel(logging.WARNING)
ALERT_LOG.propagate = False


# ---------------------------------------------------------------------------
# IOC Store
# ---------------------------------------------------------------------------

class IOCStore:
    def __init__(self, ioc_file: str = None):
        self.bad_ips: set[str] = set()
        self.bad_cidrs: list = []
        if ioc_file and Path(ioc_file).exists():
            self._load(ioc_file)
        else:
            log.info("No IOC file loaded. Create iocs.txt (one IP/CIDR per line) to enable matching.")

    def _load(self, path: str):
        count = 0
        with open(path) as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"):
                    continue
                try:
                    if "/" in entry:
                        self.bad_cidrs.append(ipaddress.ip_network(entry, strict=False))
                    else:
                        self.bad_ips.add(entry)
                    count += 1
                except ValueError:
                    log.warning(f"Invalid IOC entry skipped: {entry}")
        log.info(f"Loaded {count} IOCs from {path}")

    def is_malicious(self, ip: str) -> bool:
        if ip in self.bad_ips:
            return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.bad_cidrs)
        except ValueError:
            return False


# ---------------------------------------------------------------------------
# GeoIP
# ---------------------------------------------------------------------------

class GeoIP:
    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]

    def __init__(self, mmdb_path: str = "GeoLite2-City.mmdb"):
        self._reader = None
        self._cache: dict = {}
        self._lock = threading.Lock()

        if GEOIP2_AVAILABLE and Path(mmdb_path).exists():
            self._reader = geoip2.database.Reader(mmdb_path)
            log.info(f"GeoIP: using local database {mmdb_path}")
        elif REQUESTS_AVAILABLE:
            log.info("GeoIP: using ip-api.com (online). Install geoip2 + GeoLite2-City.mmdb for offline use.")
        else:
            log.warning("GeoIP unavailable — install 'requests' or 'geoip2'.")

    def _is_private(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self.PRIVATE_RANGES)
        except ValueError:
            return False

    def lookup(self, ip: str) -> dict:
        if self._is_private(ip):
            return {"country": "Private", "city": None, "org": None}

        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        result = {"country": None, "city": None, "org": None}
        try:
            if self._reader:
                r = self._reader.city(ip)
                result = {"country": r.country.name, "city": r.city.name, "org": None}
            elif REQUESTS_AVAILABLE:
                resp = requests.get(
                    f"http://ip-api.com/json/{ip}?fields=country,city,org,status",
                    timeout=3
                )
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "country": data.get("country"),
                        "city": data.get("city"),
                        "org": data.get("org")
                    }
        except Exception as e:
            log.debug(f"GeoIP lookup failed for {ip}: {e}")

        with self._lock:
            self._cache[ip] = result
        return result


# ---------------------------------------------------------------------------
# Shared event logger
# ---------------------------------------------------------------------------

def log_event(service: str, src_ip: str, src_port: int, geo: dict,
              ioc_match: bool, event_type: str, details: dict = None,
              force_alert: bool = False):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": service,
        "src_ip": src_ip,
        "src_port": src_port,
        "geo": geo,
        "ioc_match": ioc_match,
        "event": event_type,
        **(details or {})
    }
    log.info(json.dumps(entry))

    if ioc_match:
        msg = f"IOC MATCH — {src_ip} ({geo.get('country')}) probing {service} [{event_type}]"
        ALERT_LOG.warning(msg)
        print(f"\n  *** ALERT: {msg} ***\n")

    if event_type == "credential_capture":
        msg = (
            f"CREDENTIAL CAPTURE — {src_ip} ({geo.get('country')}) "
            f"on {service}: {json.dumps(details)}"
        )
        ALERT_LOG.warning(msg)
        print(f"\n  *** ALERT: {msg} ***\n")

    if force_alert and not ioc_match and event_type != "credential_capture":
        msg = f"{service} CONNECTION — {src_ip} ({geo.get('country')}) port {src_port}"
        if details:
            extra = {k: v for k, v in details.items() if v is not None}
            if extra:
                msg += f" {json.dumps(extra)}"
        ALERT_LOG.warning(msg)
        print(f"\n  *** ALERT: {msg} ***\n")


# ---------------------------------------------------------------------------
# SSH Honeypot
# ---------------------------------------------------------------------------

SSH_BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"


def handle_ssh(conn: socket.socket, addr, geoip: GeoIP, iocs: IOCStore):
    src_ip, src_port = addr
    geo = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    try:
        conn.sendall(SSH_BANNER)
        conn.settimeout(10)
        data = conn.recv(1024)
        payload_hex = data[:200].hex() if data else None
        log_event("SSH", src_ip, src_port, geo, ioc_match, "connection",
                  {"client_payload_hex": payload_hex})
    except Exception:
        log_event("SSH", src_ip, src_port, geo, ioc_match, "connection", {})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Telnet Honeypot
# ---------------------------------------------------------------------------

TELNET_BANNER   = b"\r\nUbuntu 22.04 LTS\r\n\r\nlogin: "
TELNET_PASS     = b"Password: "
TELNET_FAIL     = b"\r\nLogin incorrect\r\n\r\nlogin: "


def _recv_line(conn: socket.socket, max_bytes: int = 256) -> str:
    """Read until newline or max_bytes, returning decoded string."""
    buf = b""
    while len(buf) < max_bytes:
        ch = conn.recv(1)
        if not ch or ch in (b"\n", b"\r"):
            break
        buf += ch
    return buf.decode(errors="replace")


def handle_telnet(conn: socket.socket, addr, geoip: GeoIP, iocs: IOCStore):
    src_ip, src_port = addr
    geo = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    try:
        conn.sendall(TELNET_BANNER)
        conn.settimeout(15)

        username = _recv_line(conn, max_bytes=64).strip()
        if not username:
            return
        conn.sendall(TELNET_PASS)
        password = _recv_line(conn, max_bytes=64).strip()

        log_event("Telnet", src_ip, src_port, geo, ioc_match, "credential_capture",
                  {"username": username, "password": password})

        conn.sendall(TELNET_FAIL)
        time.sleep(1)
    except Exception:
        log_event("Telnet", src_ip, src_port, geo, ioc_match, "connection", {})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# FTP Honeypot
# ---------------------------------------------------------------------------

FTP_BANNER   = b"220 FTP Server ready.\r\n"
FTP_USER_OK  = b"331 Password required.\r\n"
FTP_FAIL     = b"530 Login incorrect.\r\n"
FTP_UNKNOWN  = b"500 Unknown command.\r\n"
FTP_BYE      = b"221 Goodbye.\r\n"


def handle_ftp(conn: socket.socket, addr, geoip: GeoIP, iocs: IOCStore):
    src_ip, src_port = addr
    geo = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    username = None
    try:
        conn.sendall(FTP_BANNER)
        conn.settimeout(15)
        log_event("FTP", src_ip, src_port, geo, ioc_match, "connection", {})

        for _ in range(10):
            line = _recv_line(conn, max_bytes=256).strip()
            if not line:
                break
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()

            if cmd == "USER":
                username = arg
                conn.sendall(FTP_USER_OK)
            elif cmd == "PASS":
                log_event("FTP", src_ip, src_port, geo, ioc_match, "credential_capture",
                          {"username": username, "password": arg})
                conn.sendall(FTP_FAIL)
                break
            elif cmd == "QUIT":
                conn.sendall(FTP_BYE)
                break
            else:
                conn.sendall(FTP_UNKNOWN)
    except Exception:
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP Honeypot
# ---------------------------------------------------------------------------

_LOGIN_PAGE_HTML = """\
<!DOCTYPE html>
<html>
<head><title>Admin Login</title>
<style>
  body{{font-family:Arial,sans-serif;background:#1a1a2e;display:flex;
       justify-content:center;align-items:center;height:100vh;margin:0}}
  .box{{background:#fff;padding:40px;border-radius:8px;width:320px;
       box-shadow:0 4px 20px rgba(0,0,0,.4)}}
  h2{{text-align:center;margin-bottom:24px;color:#333}}
  .error{{color:#c0392b;text-align:center;margin-bottom:12px;font-size:14px}}
  input{{width:100%;padding:10px;margin:8px 0 16px;box-sizing:border-box;
        border:1px solid #ccc;border-radius:4px}}
  button{{width:100%;padding:12px;background:#4a90d9;color:#fff;border:none;
         border-radius:4px;cursor:pointer;font-size:15px}}
  button:hover{{background:#357abd}}
</style>
</head>
<body><div class="box">
  <h2>Admin Panel</h2>
  {error}
  <form method="POST" action="/login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="off"/>
    <label>Password</label>
    <input type="password" name="password"/>
    <button type="submit">Login</button>
  </form>
</div></body></html>
"""

_ERROR_P = '<p class="error">Invalid credentials. Please try again.</p>'

def _http_response(body_html: str) -> bytes:
    body = body_html.encode()
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    ) + body

HTTP_LOGIN_PAGE = _http_response(_LOGIN_PAGE_HTML.format(error=""))
HTTP_LOGIN_FAIL = _http_response(_LOGIN_PAGE_HTML.format(error=_ERROR_P))
HTTP_NOT_FOUND  = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

# Paths that look like admin/login endpoints scanners commonly probe
LOGIN_PATHS = {"/login", "/admin", "/wp-login.php", "/administrator", "/"}


def _parse_http_request(raw: bytes):
    """Returns (method, path, headers_dict, body_bytes)."""
    try:
        header_section, _, body = raw.partition(b"\r\n\r\n")
        lines = header_section.decode(errors="replace").split("\r\n")
        parts = lines[0].split(" ")
        method = parts[0] if parts else "UNKNOWN"
        path   = parts[1] if len(parts) > 1 else "/"
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, _, v = line.partition(": ")
                headers[k.lower()] = v
        content_length = int(headers.get("content-length", 0))
        return method, path, headers, body[:content_length]
    except Exception:
        return "UNKNOWN", "/", {}, b""


def handle_http(conn: socket.socket, addr, geoip: GeoIP, iocs: IOCStore):
    src_ip, src_port = addr
    geo = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    try:
        conn.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            chunk = conn.recv(1024)
            if not chunk:
                break
            raw += chunk

        # Read body if Content-Length is present
        cl_match = re.search(rb"[Cc]ontent-[Ll]ength:\s*(\d+)", raw)
        if cl_match:
            cl = int(cl_match.group(1))
            body_so_far = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
            while len(body_so_far) < cl:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                raw += chunk
                body_so_far = raw.split(b"\r\n\r\n", 1)[1]

        method, path, headers, body = _parse_http_request(raw)

        log_event("HTTP", src_ip, src_port, geo, ioc_match, "request", {
            "method": method,
            "path": path,
            "user_agent": headers.get("user-agent", "")
        })

        if method == "POST" and path in LOGIN_PATHS:
            fields = {k: v[0] if v else "" for k, v in parse_qs(body.decode(errors="replace")).items()}
            username = fields.get("username") or fields.get("user") or fields.get("log", "")
            password = fields.get("password") or fields.get("pass") or fields.get("pwd", "")
            if username or password:
                log_event("HTTP", src_ip, src_port, geo, ioc_match, "credential_capture", {
                    "username": username,
                    "password": password,
                    "path": path
                })
            conn.sendall(HTTP_LOGIN_FAIL)
        elif method == "GET":
            conn.sendall(HTTP_LOGIN_PAGE)
        else:
            conn.sendall(HTTP_NOT_FOUND)
    except Exception as e:
        log.debug(f"HTTP handler error from {src_ip}: {e}")
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# RDP Honeypot
# ---------------------------------------------------------------------------

# Minimal X.224 Connection Confirm (CC) — no negotiation response.
# Enough to complete the TPKT/X.224 handshake and keep the client talking.
RDP_CC = bytes([
    0x03, 0x00, 0x00, 0x0B,  # TPKT: version=3, reserved=0, length=11
    0x06,                      # X.224 LI = 6
    0xD0,                      # CC TPDU code
    0x00, 0x00,                # DST-REF
    0x00, 0x00,                # SRC-REF
    0x00,                      # Class 0
])


def _parse_rdp_cr(data: bytes) -> dict:
    """
    Extract username/domain from the RDP Connection Request cookie and
    the requested security protocols from the RDP Negotiation Request.

    Many scanners and bots embed credentials in the initial CR packet as:
        Cookie: mstshash=DOMAIN\\username\\r\\n
    """
    result = {"username": None, "domain": None, "requested_protocols": None}
    try:
        text = data.decode(errors="replace")
        cookie_match = re.search(r"Cookie: mstshash=([^\r\n]+)", text)
        if cookie_match:
            value = cookie_match.group(1).strip()
            if "\\" in value:
                domain, _, username = value.partition("\\")
                result["domain"] = domain
                result["username"] = username
            else:
                result["username"] = value

        # RDP Negotiation Request starts with type=0x01, flags=0x00, length=0x0008
        neg_match = re.search(b"\x01\x00\x08\x00", data)
        if neg_match and neg_match.start() + 8 <= len(data):
            proto_bytes = data[neg_match.start() + 4: neg_match.start() + 8]
            protocols = int.from_bytes(proto_bytes, "little")
            proto_names = []
            if protocols & 0x01:
                proto_names.append("SSL/TLS")
            if protocols & 0x02:
                proto_names.append("NLA/CredSSP")
            if protocols & 0x08:
                proto_names.append("RDSTLS")
            if not proto_names:
                proto_names.append("Standard RDP")
            result["requested_protocols"] = proto_names
    except Exception:
        pass
    return result


def _parse_rdp_mcs(data: bytes) -> dict:
    """
    Extract the client hostname from the MCS Connect Initial PDU sent
    after the X.224 handshake.

    The TS_UD_CS_CORE block (type=0xC001) contains a 32-byte UTF-16LE
    clientName field at offset 24 from the block start. This is always
    sent in plaintext regardless of NLA/TLS negotiation.

    With NLA/CredSSP the actual login credentials are encrypted inside
    TLS and cannot be captured without a full TLS implementation.
    """
    result = {"client_hostname": None}
    try:
        # TS_UD_CS_CORE marker: type 0xC001 stored little-endian = bytes 01 C0.
        # There can be multiple 01 C0 byte sequences in the MCS data, so validate
        # the length field (bytes 2-3) to confirm this is the CS_CORE block.
        # CS_CORE is always >= 100 bytes.
        idx = -1
        search_pos = 0
        while True:
            found = data.find(b"\x01\xc0", search_pos)
            if found == -1 or found + 4 > len(data):
                break
            length = int.from_bytes(data[found + 2:found + 4], "little")
            if 100 <= length <= 2000:
                idx = found
                break
            search_pos = found + 1

        if idx != -1 and idx + 56 <= len(data):
            # clientName is 32 bytes of UTF-16LE starting at offset 24 from block start
            name_bytes = data[idx + 24: idx + 56]
            name = name_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            if name:
                result["client_hostname"] = name
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# NLA / CredSSP credential capture
# ---------------------------------------------------------------------------
#
# When a client negotiates NLA (PROTOCOL_HYBRID), credentials are sent inside
# a CredSSP (TSRequest) envelope over TLS.  The NTLM exchange within CredSSP
# is:
#   1. Client → Server  TSRequest{ negoTokens: [SPNEGO NTLM NEGOTIATE] }
#   2. Server → Client  TSRequest{ negoTokens: [SPNEGO NTLM CHALLENGE] }
#   3. Client → Server  TSRequest{ negoTokens: [SPNEGO NTLM AUTHENTICATE] }
#
# The NTLM AUTHENTICATE message (step 3) contains the username, domain, and
# NetNTLMv2 hash in plaintext inside the TLS tunnel.  We capture it by acting
# as the TLS endpoint and parsing the NTLM token.
#
# Output hash format (hashcat mode 5600 / john netntlmv2):
#   username::domain:ServerChallenge:NTProofStr:blob

# RDP Connection Confirm selecting PROTOCOL_HYBRID (NLA).
# Length = 19: 4-byte TPKT + 7-byte X.224 CC + 8-byte RDP_NEG_RSP.
RDP_CC_NLA = bytes([
    0x03, 0x00, 0x00, 0x13,   # TPKT: version=3, reserved=0, length=19
    0x0E,                       # X.224 LI=14
    0xD0,                       # CC TPDU
    0x00, 0x00,                 # DST-REF
    0x00, 0x00,                 # SRC-REF
    0x00,                       # Class 0
    0x02,                       # RDP_NEG_RSP type
    0x00,                       # flags
    0x08, 0x00,                 # length=8
    0x02, 0x00, 0x00, 0x00,     # selectedProtocol = PROTOCOL_HYBRID
])

# NTLM OID: 1.3.6.1.4.1.311.2.2.10
_NTLM_OID    = b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
_NTLM_SIG    = b"NTLMSSP\x00"


# --- Minimal ASN.1 helpers ---------------------------------------------------

def _asn1_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    return bytes([0x82, n >> 8, n & 0xFF])

def _asn1_tag(tag: int, data: bytes) -> bytes:
    return bytes([tag]) + _asn1_len(len(data)) + data

def _asn1_seq(data: bytes)        -> bytes: return _asn1_tag(0x30, data)
def _asn1_ctx(n: int, data: bytes)-> bytes: return _asn1_tag(0xA0 + n, data)
def _asn1_octet(data: bytes)      -> bytes: return _asn1_tag(0x04, data)
def _asn1_oid(oid: bytes)         -> bytes: return _asn1_tag(0x06, oid)
def _asn1_int(n: int)             -> bytes: return _asn1_tag(0x02, bytes([n]))
def _asn1_enum(n: int)            -> bytes: return _asn1_tag(0x0A, bytes([n]))


# --- NTLM message builder and parser -----------------------------------------

def _ntlm_av_pair(av_id: int, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def _ntlm_parse_negotiate_flags(data: bytes) -> int:
    """Extract NegotiateFlags from an NTLM NEGOTIATE (Type 1) message."""
    idx = data.find(_NTLM_SIG)
    if idx != -1 and idx + 16 <= len(data):
        return struct.unpack_from("<I", data, idx + 12)[0]
    return 0


def _ntlm_build_challenge(server_challenge: bytes, client_flags: int = 0,
                          target: str = "HONEYPOT") -> bytes:
    """Build a minimal NTLM Type 2 (CHALLENGE) message."""
    target_utf16 = target.encode("utf-16-le")
    av_pairs = (
        _ntlm_av_pair(0x0002, target.encode("utf-16-le"))   # MsvAvNbDomainName
        + _ntlm_av_pair(0x0001, target.encode("utf-16-le")) # MsvAvNbComputerName
        + _ntlm_av_pair(0x0000, b"")                        # MsvAvEOL
    )

    # Mandatory server flags
    flags = (
        0x00000001   # NTLMSSP_NEGOTIATE_UNICODE
        | 0x00000004 # NTLMSSP_REQUEST_TARGET
        | 0x00000200 # NTLMSSP_NEGOTIATE_NTLM
        | 0x00800000 # NTLMSSP_NEGOTIATE_TARGET_INFO
        | 0x02000000 # NTLMSSP_NEGOTIATE_VERSION
    )

    # Optional: only echo back flags the client also set
    optional = (
        0x00000010   # NTLMSSP_NEGOTIATE_SIGN
        | 0x00000020 # NTLMSSP_NEGOTIATE_SEAL
        | 0x00008000 # NTLMSSP_NEGOTIATE_ALWAYS_SIGN
        | 0x00020000 # NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        | 0x20000000 # NTLMSSP_NEGOTIATE_128
        | 0x40000000 # NTLMSSP_NEGOTIATE_KEY_EXCH
        | 0x80000000 # NTLMSSP_NEGOTIATE_56
    )
    flags |= (client_flags & optional)
    # Fixed header is 56 bytes (48 base + 8 version)
    target_offset   = 56
    av_pairs_offset = target_offset + len(target_utf16)
    return (
        _NTLM_SIG
        + struct.pack("<I",   2)                                          # MessageType
        + struct.pack("<HHI", len(target_utf16), len(target_utf16),
                              target_offset)                              # TargetNameFields
        + struct.pack("<I",   flags)                                      # NegotiateFlags
        + server_challenge                                                # ServerChallenge
        + b"\x00" * 8                                                     # Reserved
        + struct.pack("<HHI", len(av_pairs), len(av_pairs), av_pairs_offset) # TargetInfoFields
        + bytes([0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F])       # Version (Win7)
        + target_utf16
        + av_pairs
    )


def _ntlm_parse_authenticate(data: bytes) -> dict:
    """
    Parse NTLM Type 3 (AUTHENTICATE) message.
    Returns username, domain, and the NetNTLMv2 hash in hashcat 5600 format.
    """
    result = {"username": None, "domain": None, "netntlmv2_hash": None}
    try:
        if not data.startswith(_NTLM_SIG):
            return result
        if struct.unpack_from("<I", data, 8)[0] != 3:
            return result

        def _field(offset):
            length, _, off = struct.unpack_from("<HHI", data, offset)
            return data[off: off + length]

        nt_response = _field(20)
        domain      = _field(28).decode("utf-16-le", errors="replace")
        username    = _field(36).decode("utf-16-le", errors="replace")

        result["username"] = username
        result["domain"]   = domain

        if len(nt_response) > 16:
            result["netntlmv2_hash"] = (
                f"{username}::{domain}:"
                f"{{server_challenge}}:"  # filled in by caller
                f"{nt_response[:16].hex()}:"
                f"{nt_response[16:].hex()}"
            )
    except Exception:
        pass
    return result


# --- SPNEGO / CredSSP wrappers -----------------------------------------------

def _spnego_wrap_challenge(ntlm_challenge: bytes) -> bytes:
    """Wrap an NTLM CHALLENGE inside a SPNEGO negTokenResp."""
    inner = (
        _asn1_ctx(0, _asn1_enum(1))                    # negState: accept-incomplete
        + _asn1_ctx(1, _asn1_oid(_NTLM_OID))           # supportedMech: NTLM
        + _asn1_ctx(2, _asn1_octet(ntlm_challenge))    # responseToken
    )
    return _asn1_ctx(1, _asn1_seq(inner))              # [1] negTokenResp


def _credssp_wrap(spnego_token: bytes) -> bytes:
    """Wrap a SPNEGO token in a CredSSP TSRequest."""
    nego_item = _asn1_seq(_asn1_ctx(0, _asn1_octet(spnego_token)))
    return _asn1_seq(
        _asn1_ctx(0, _asn1_int(2))          # version = 2 (avoids EPA requirements in v5+)
        + _asn1_ctx(1, _asn1_seq(nego_item)) # negoTokens
    )


def _recv_tls_msg(sock) -> bytes:
    """Read one complete CredSSP/TSRequest (ASN.1 SEQUENCE) from a TLS socket."""
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        # Determine expected total length from ASN.1 header
        if len(buf) >= 4 and buf[0] == 0x30:
            if buf[1] < 0x80:
                if len(buf) >= 2 + buf[1]:
                    return buf
            elif buf[1] == 0x81 and len(buf) >= 3:
                if len(buf) >= 3 + buf[2]:
                    return buf
            elif buf[1] == 0x82 and len(buf) >= 4:
                total = 4 + (buf[2] << 8 | buf[3])
                if len(buf) >= total:
                    return buf
    return buf


# --- TLS certificate generation ----------------------------------------------

def _generate_self_signed_cert(cert_path: str, key_path: str):
    """Generate a self-signed RSA certificate with SANs for localhost and 127.0.0.1."""
    import ipaddress as _ipaddress
    key  = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now  = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(_ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    Path(cert_path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    Path(key_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
    log.info(f"Generated self-signed TLS certificate: {cert_path}")


def setup_rdp_tls(cert_path: str = "rdp_cert.pem",
                  key_path: str  = "rdp_key.pem") -> Optional[ssl.SSLContext]:
    """
    Return an SSLContext for the RDP honeypot, auto-generating a cert if needed.
    Returns None if TLS cannot be set up (cryptography library missing).
    """
    if not Path(cert_path).exists() or not Path(key_path).exists():
        if not CRYPTOGRAPHY_AVAILABLE:
            log.warning(
                "NLA credential capture disabled — 'cryptography' library not found.\n"
                "  Install it:  pip install cryptography\n"
                "  Or provide a cert/key with --rdp-cert / --rdp-key"
            )
            return None
        _generate_self_signed_cert(cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    return ctx


# --- NLA credential-capture flow ---------------------------------------------

def _nla_capture(conn: socket.socket, ssl_ctx: ssl.SSLContext) -> dict:
    """
    Perform the TLS + CredSSP/NTLM handshake and return any captured credentials.
    Raises on failure so handle_rdp can fall back gracefully.
    """
    tls = ssl_ctx.wrap_socket(conn, server_side=True)
    tls.settimeout(15)

    # Step 1: receive first TSRequest.
    # Modern CredSSP (v5+) may send a version-negotiation TSRequest before NTLM.
    msg = _recv_tls_msg(tls)
    log.debug(f"NLA msg1 ({len(msg)}b): {msg[:120].hex()}")

    if msg.find(_NTLM_SIG) == -1:
        # Version negotiation — respond with our version and read the real NEGOTIATE
        log.debug("NLA: version negotiation detected, responding")
        tls.sendall(_asn1_seq(_asn1_ctx(0, _asn1_int(2))))
        msg = _recv_tls_msg(tls)
        log.debug(f"NLA msg1b ({len(msg)}b): {msg[:120].hex()}")
        if msg.find(_NTLM_SIG) == -1:
            raise ValueError(f"NTLM NEGOTIATE not found after version exchange (hex: {msg[:60].hex()})")

    # Step 2: build and send NTLM CHALLENGE.
    # Mirror only flags the client offered — setting unsupported flags causes
    # strict NTLM implementations to drop the connection.
    client_flags  = _ntlm_parse_negotiate_flags(msg)
    server_challenge = secrets.token_bytes(8)
    ntlm_challenge   = _ntlm_build_challenge(server_challenge, client_flags=client_flags)
    challenge_ts     = _credssp_wrap(ntlm_challenge)
    log.debug(f"NLA sending challenge ({len(challenge_ts)}b): {challenge_ts[:80].hex()}")
    tls.sendall(challenge_ts)

    # Step 3: receive NTLM AUTHENTICATE (may arrive alongside pubKeyAuth in CredSSP v5+)
    msg3 = _recv_tls_msg(tls)
    log.debug(f"NLA msg3 ({len(msg3)}b): {msg3[:120].hex()}")

    ntlm_auth_pos = msg3.find(_NTLM_SIG)
    if ntlm_auth_pos == -1:
        raise ValueError(f"NTLM AUTHENTICATE not found in msg3 (hex: {msg3[:80].hex()})")

    result = _ntlm_parse_authenticate(msg3[ntlm_auth_pos:])

    if result.get("netntlmv2_hash"):
        result["netntlmv2_hash"] = result["netntlmv2_hash"].replace(
            "{server_challenge}", server_challenge.hex()
        )

    return result


def handle_rdp(conn: socket.socket, addr, geoip: GeoIP, iocs: IOCStore,
               ssl_ctx: Optional[ssl.SSLContext] = None):
    src_ip, src_port = addr
    geo      = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    parsed   = {}
    try:
        conn.settimeout(10)
        data = conn.recv(1024)
        if not data:
            return

        parsed = _parse_rdp_cr(data)
        wants_nla = (
            parsed.get("requested_protocols") and
            any("NLA" in p for p in parsed["requested_protocols"])
        )

        if wants_nla and ssl_ctx:
            # NLA path: negotiate NLA, do TLS, capture NetNTLMv2 hash
            conn.sendall(RDP_CC_NLA)
            try:
                nla_result = _nla_capture(conn, ssl_ctx)
                parsed.update(nla_result)
            except Exception as e:
                log.warning(f"NLA capture failed for {src_ip}: {type(e).__name__}: {e}")
        else:
            # Fallback: standard CC, read MCS for client hostname
            conn.sendall(RDP_CC)
            try:
                more = conn.recv(4096)
                if more:
                    parsed.update(_parse_rdp_mcs(more))
            except Exception:
                pass

        event = "credential_capture" if parsed.get("username") else "connection"
        log_event("RDP", src_ip, src_port, geo, ioc_match, event, parsed, force_alert=True)
    except Exception as e:
        log.warning(f"RDP handler error from {src_ip}: {type(e).__name__}: {e}")
        log_event("RDP", src_ip, src_port, geo, ioc_match, "connection", parsed, force_alert=True)
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Generic TCP server
# ---------------------------------------------------------------------------

def start_tcp_server(port: int, handler, geoip: GeoIP, iocs: IOCStore, label: str,
                     extra_kwargs: dict = None):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(50)
        log.info(f"{label} honeypot listening on port {port}")
        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handler,
                args=(conn, addr, geoip, iocs),
                kwargs=(extra_kwargs or {}),
                daemon=True
            ).start()
    except PermissionError:
        log.error(f"Permission denied on port {port} — use sudo for ports < 1024")
    except OSError as e:
        log.error(f"Bind failed on {label} port {port}: {e}")
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Honeypot — SSH, Telnet, FTP, HTTP, and RDP service emulation"
    )
    parser.add_argument("--ssh-port",    type=int, default=2222, help="SSH port    (default: 2222)")
    parser.add_argument("--telnet-port", type=int, default=2323, help="Telnet port (default: 2323)")
    parser.add_argument("--ftp-port",    type=int, default=2121, help="FTP port    (default: 2121)")
    parser.add_argument("--http-port",   type=int, default=8880, help="HTTP port   (default: 8880)")
    parser.add_argument("--rdp-port",    type=int, default=3389, help="RDP port    (default: 3389)")
    parser.add_argument("--no-ssh",    action="store_true", help="Disable SSH honeypot")
    parser.add_argument("--no-telnet", action="store_true", help="Disable Telnet honeypot")
    parser.add_argument("--no-ftp",    action="store_true", help="Disable FTP honeypot")
    parser.add_argument("--no-http",   action="store_true", help="Disable HTTP honeypot")
    parser.add_argument("--no-rdp",    action="store_true", help="Disable RDP honeypot")
    parser.add_argument("--rdp-cert",  default="rdp_cert.pem", help="TLS cert for RDP NLA (auto-generated if absent)")
    parser.add_argument("--rdp-key",   default="rdp_key.pem",  help="TLS key for RDP NLA (auto-generated if absent)")
    parser.add_argument("--ioc-file",  default="iocs.txt",           help="IOC file (default: iocs.txt)")
    parser.add_argument("--geoip-db",  default="GeoLite2-City.mmdb", help="GeoLite2 mmdb path (optional)")
    args = parser.parse_args()

    geoip    = GeoIP(mmdb_path=args.geoip_db)
    iocs     = IOCStore(ioc_file=args.ioc_file)
    ssl_ctx  = setup_rdp_tls(args.rdp_cert, args.rdp_key) if not args.no_rdp else None

    # Each entry: (port, handler, label, extra_kwargs)
    services = []
    if not args.no_ssh:
        services.append((args.ssh_port,    handle_ssh,    "SSH",    {}))
    if not args.no_telnet:
        services.append((args.telnet_port, handle_telnet, "Telnet", {}))
    if not args.no_ftp:
        services.append((args.ftp_port,    handle_ftp,    "FTP",    {}))
    if not args.no_http:
        services.append((args.http_port,   handle_http,   "HTTP",   {}))
    if not args.no_rdp:
        nla_status = "NLA capture enabled" if ssl_ctx else "NLA capture disabled (no TLS)"
        log.info(f"RDP: {nla_status}")
        services.append((args.rdp_port, handle_rdp, "RDP", {"ssl_ctx": ssl_ctx}))

    if not services:
        log.error("All services disabled — nothing to start.")
        return

    threads = []
    for port, handler, label, kwargs in services:
        t = threading.Thread(
            target=start_tcp_server,
            args=(port, handler, geoip, iocs, label),
            kwargs={"extra_kwargs": kwargs},
            daemon=True
        )
        t.start()
        threads.append(t)

    log.info("Logs -> honeypot.log | Alerts -> honeypot_alerts.log")
    log.info("Press Ctrl+C to stop.")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log.info("Honeypot stopped.")


if __name__ == "__main__":
    main()
