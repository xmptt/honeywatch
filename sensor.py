#!/usr/bin/env python3
"""
HoneyWatch Sensor Agent
Runs SSH / Telnet / FTP / HTTP honeypot services and streams all events
to a central HoneyWatch dashboard server in real time.

Requirements: Python 3.8+, stdlib only.

Usage:
    python3 sensor.py --server http://10.0.0.1:5000 --key <api-key> --name nyc-dc-01
    python3 sensor.py --help

Environment variable equivalents:
    HONEY_SERVER, HONEY_KEY, HONEY_NAME

Deploy on any Linux/macOS machine. The sensor runs all services in daemon
threads and flushes events to the server every 5 seconds. If the server is
unreachable, events buffer locally (up to --buffer-size, default 10 000)
and are retried with exponential back-off.
"""

import os, sys, json, re, time, socket, threading, logging, argparse
import hashlib, secrets, ipaddress, struct, collections
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from urllib.parse import parse_qs
from pathlib import Path

try:
    import requests as _requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import geoip2.database as _geoip2
    GEOIP2_AVAILABLE = True
except ImportError:
    GEOIP2_AVAILABLE = False

VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Globals (set in main())
# ---------------------------------------------------------------------------

SERVER_URL  = ""
API_KEY     = ""
SENSOR_NAME = ""
SENSOR_ID   = ""

_event_buffer: collections.deque = None
_buffer_lock  = threading.Lock()
_flush_backoff = 5          # seconds, doubles on failure, max 60
_events_sent   = 0
_start_time    = time.time()

log = logging.getLogger("sensor")

# ---------------------------------------------------------------------------
# GeoIP  (local DB preferred; falls back to ip-api.com; else None)
# ---------------------------------------------------------------------------

class GeoIP:
    _PRIVATE = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
    ]
    def __init__(self, mmdb_path="GeoLite2-City.mmdb"):
        self._reader = None
        self._cache  = {}
        self._lock   = threading.Lock()
        if GEOIP2_AVAILABLE and Path(mmdb_path).exists():
            self._reader = _geoip2.Reader(mmdb_path)
            log.info(f"GeoIP: local DB {mmdb_path}")
        elif REQUESTS_AVAILABLE:
            log.info("GeoIP: using ip-api.com (online)")
        else:
            log.info("GeoIP: unavailable")

    def _private(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in n for n in self._PRIVATE)
        except ValueError:
            return False

    def lookup(self, ip):
        if self._private(ip):
            return {"country":"Private","city":None,"org":None,"lat":None,"lon":None}
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]
        result = {"country":None,"city":None,"org":None,"lat":None,"lon":None}
        try:
            if self._reader:
                r = self._reader.city(ip)
                result = {"country":r.country.name,"city":r.city.name,
                          "org":None,"lat":r.location.latitude,"lon":r.location.longitude}
            elif REQUESTS_AVAILABLE:
                r = _requests.get(
                    f"http://ip-api.com/json/{ip}?fields=country,city,org,lat,lon,status",
                    timeout=3)
                d = r.json()
                if d.get("status") == "success":
                    result = {"country":d.get("country"),"city":d.get("city"),
                              "org":d.get("org"),"lat":d.get("lat"),"lon":d.get("lon")}
        except Exception as e:
            log.debug(f"GeoIP {ip}: {e}")
        with self._lock:
            self._cache[ip] = result
        return result

_geoip = None  # set in main()

# ---------------------------------------------------------------------------
# IOC store
# ---------------------------------------------------------------------------

class IOCStore:
    def __init__(self, path=None):
        self.bad_ips   = set()
        self.bad_cidrs = []
        if path and Path(path).exists():
            self._load(path)

    def _load(self, path):
        count = 0
        with open(path) as f:
            for line in f:
                entry = line.strip()
                if not entry or entry.startswith("#"): continue
                try:
                    if "/" in entry:
                        self.bad_cidrs.append(ipaddress.ip_network(entry, strict=False))
                    else:
                        self.bad_ips.add(entry)
                    count += 1
                except ValueError:
                    pass
        log.info(f"Loaded {count} IOCs from {path}")

    def is_malicious(self, ip):
        if ip in self.bad_ips: return True
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in n for n in self.bad_cidrs)
        except ValueError:
            return False

_iocs = None  # set in main()

# ---------------------------------------------------------------------------
# Event buffering
# ---------------------------------------------------------------------------

def buffer_event(service, src_ip, src_port, event_type, details=None):
    global _geoip, _iocs
    geo = _geoip.lookup(src_ip) if _geoip else {}
    ioc = _iocs.is_malicious(src_ip) if _iocs else False
    ev  = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service":   service,
        "src_ip":    src_ip,
        "src_port":  src_port,
        "geo":       geo,
        "ioc_match": ioc,
        "event":     event_type,
        **(details or {}),
    }
    log.info(json.dumps(ev))
    if ioc or event_type == "credential_capture":
        log.warning(f"*** {event_type.upper()} — {src_ip} [{geo.get('country','?')}] on {service} ***")
    with _buffer_lock:
        _event_buffer.append(ev)

# ---------------------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------------------

def _post(path, body):
    url  = SERVER_URL.rstrip("/") + path
    data = json.dumps(body).encode()
    req  = Request(url, data=data,
                   headers={"Content-Type": "application/json",
                             "Authorization": f"Bearer {API_KEY}"})
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read())

def _get(path):
    url = SERVER_URL.rstrip("/") + path
    req = Request(url, headers={"Authorization": f"Bearer {API_KEY}"})
    with urlopen(req, timeout=10) as r:
        return json.loads(r.read())

# ---------------------------------------------------------------------------
# Flush thread  (sends event batches to server every N seconds)
# ---------------------------------------------------------------------------

def _flush_worker():
    global _flush_backoff, _events_sent
    while True:
        time.sleep(_flush_backoff)
        with _buffer_lock:
            if not _event_buffer:
                _flush_backoff = 5
                continue
            batch = list(_event_buffer)
            _event_buffer.clear()
        try:
            resp = _post("/api/sensor/events", {"sensor_id": SENSOR_ID, "batch": batch})
            _events_sent += resp.get("accepted", len(batch))
            _flush_backoff = 5
        except Exception as e:
            # Restore events to buffer (prepend to keep order)
            with _buffer_lock:
                for ev in reversed(batch):
                    _event_buffer.appendleft(ev)
            _flush_backoff = min(_flush_backoff * 2, 60)
            log.warning(f"Flush failed: {e}  — retry in {_flush_backoff}s  buffer={len(_event_buffer)}")

# ---------------------------------------------------------------------------
# Heartbeat thread
# ---------------------------------------------------------------------------

def _heartbeat_worker():
    while True:
        time.sleep(30)
        try:
            _post("/api/sensor/heartbeat", {
                "sensor_id":      SENSOR_ID,
                "uptime_seconds": int(time.time() - _start_time),
                "buffer_depth":   len(_event_buffer),
                "events_sent_total": _events_sent,
            })
        except Exception as e:
            log.debug(f"Heartbeat failed: {e}")

# ---------------------------------------------------------------------------
# Config poller — picks up name / label changes made in the dashboard
# ---------------------------------------------------------------------------

def _config_poller():
    global SENSOR_NAME
    while True:
        time.sleep(60)
        try:
            cfg = _get("/api/sensor/config")
            new_name = cfg.get("name", "")
            if new_name and new_name != SENSOR_NAME:
                log.info(f"Sensor name updated by dashboard: '{SENSOR_NAME}' → '{new_name}'")
                SENSOR_NAME = new_name
        except Exception as e:
            log.debug(f"Config poll failed: {e}")

# ---------------------------------------------------------------------------
# Registration  (blocking retry on startup)
# ---------------------------------------------------------------------------

def register():
    import subprocess
    services_running = []
    log.info(f"Registering sensor '{SENSOR_ID}' with {SERVER_URL} …")
    backoff = 5
    while True:
        try:
            resp = _post("/api/sensor/register", {
                "sensor_id": SENSOR_ID,
                "name":      SENSOR_NAME,
                "version":   VERSION,
                "services":  ["SSH","HTTP","FTP","TELNET"],
            })
            log.info(f"Registered: {resp}")
            return
        except Exception as e:
            log.warning(f"Registration failed: {e}  — retry in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

# ---------------------------------------------------------------------------
# Generic TCP server (spawns a handler thread per connection)
# ---------------------------------------------------------------------------

def start_tcp_server(port, handler, name):
    def serve():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", port))
        except OSError as e:
            log.error(f"{name} bind on port {port} failed: {e}")
            return
        srv.listen(50)
        log.info(f"{name} honeypot listening on port {port}")
        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(target=_safe_handle,
                                     args=(handler, conn, addr), daemon=True)
                t.start()
            except Exception as e:
                log.debug(f"{name} accept error: {e}")

    threading.Thread(target=serve, daemon=True).start()

def _safe_handle(handler, conn, addr):
    try:
        handler(conn, addr)
    except Exception as e:
        log.debug(f"Handler error: {e}")
    finally:
        try: conn.close()
        except: pass

# ---------------------------------------------------------------------------
# SSH honeypot
# ---------------------------------------------------------------------------

SSH_BANNER = b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-2ubuntu0.3\r\n"

def handle_ssh(conn, addr):
    src_ip, src_port = addr[0], addr[1]
    try:
        conn.sendall(SSH_BANNER)
        conn.settimeout(12)
        raw = conn.recv(256)
        client_banner = raw.split(b"\n")[0].decode(errors="replace").strip()
        buffer_event("SSH", src_ip, src_port, "connection",
                     {"client_banner": client_banner[:120]})
        # Send fake key exchange init  (MSG_KEXINIT = 20)
        # Cookie (16 bytes) + padding to look realistic
        kex_payload = bytes([20]) + secrets.token_bytes(16) + b"\x00" * 140
        length = len(kex_payload) + 1  # +1 for padding_length byte
        padding = 8 - ((5 + length) % 8)
        if padding < 4: padding += 8
        packet = struct.pack(">IB", length + padding, padding) + kex_payload + secrets.token_bytes(padding)
        conn.sendall(packet)
        # Try to read auth request and extract username/password
        for _ in range(8):
            try:
                hdr = conn.recv(5)
                if len(hdr) < 5: break
                plen, padlen = struct.unpack(">IB", hdr)
                body = conn.recv(min(plen - 1, 4096))
                if not body: break
                # SSH_MSG_USERAUTH_REQUEST = 50
                if body[0:1] == b"\x32":
                    try:
                        pos = 1
                        ulen = struct.unpack(">I", body[pos:pos+4])[0]; pos += 4
                        username = body[pos:pos+ulen].decode(errors="replace"); pos += ulen
                        # skip service name
                        slen = struct.unpack(">I", body[pos:pos+4])[0]; pos += 4
                        pos += slen
                        # method
                        mlen = struct.unpack(">I", body[pos:pos+4])[0]; pos += 4
                        method = body[pos:pos+mlen].decode(errors="replace"); pos += mlen
                        if method == "password":
                            pos += 1  # boolean
                            plen2 = struct.unpack(">I", body[pos:pos+4])[0]; pos += 4
                            password = body[pos:pos+plen2].decode(errors="replace")
                            buffer_event("SSH", src_ip, src_port, "credential_capture",
                                         {"username": username, "password": password})
                        else:
                            buffer_event("SSH", src_ip, src_port, "auth_attempt",
                                         {"username": username, "auth_method": method})
                        # Send SSH_MSG_USERAUTH_FAILURE
                        fail = b"\x33\x00\x00\x00\x08password\x00"
                        conn.sendall(fail)
                    except Exception:
                        pass
            except socket.timeout:
                break
    except Exception as e:
        log.debug(f"SSH handler {src_ip}: {e}")

# ---------------------------------------------------------------------------
# Telnet honeypot
# ---------------------------------------------------------------------------

TELNET_BANNER = b"\r\nUbuntu 22.04.3 LTS\r\n\r\nlogin: "
TELNET_PASS   = b"Password: "
TELNET_FAIL   = b"\r\nLogin incorrect\r\n\r\nlogin: "

def _recv_line(conn, max_bytes=256):
    buf = b""
    while len(buf) < max_bytes:
        try:
            ch = conn.recv(1)
        except: break
        if not ch or ch in (b"\n", b"\r"): break
        if ch == b"\xff":  # IAC — skip 2 more bytes
            conn.recv(2)
            continue
        buf += ch
    return buf.decode(errors="replace")

def handle_telnet(conn, addr):
    src_ip, src_port = addr[0], addr[1]
    try:
        conn.sendall(TELNET_BANNER)
        conn.settimeout(15)
        username = _recv_line(conn, 64).strip()
        if not username: return
        conn.sendall(TELNET_PASS)
        password = _recv_line(conn, 64).strip()
        buffer_event("Telnet", src_ip, src_port, "credential_capture",
                     {"username": username, "password": password})
        conn.sendall(TELNET_FAIL)
        time.sleep(0.5)
    except Exception as e:
        log.debug(f"Telnet {src_ip}: {e}")
        buffer_event("Telnet", src_ip, src_port, "connection", {})

# ---------------------------------------------------------------------------
# FTP honeypot
# ---------------------------------------------------------------------------

FTP_BANNER  = b"220 FTP server ready.\r\n"
FTP_PASS_OK = b"331 Password required.\r\n"
FTP_FAIL    = b"530 Login incorrect.\r\n"
FTP_UNKNOWN = b"500 Unknown command.\r\n"
FTP_BYE     = b"221 Goodbye.\r\n"

def handle_ftp(conn, addr):
    src_ip, src_port = addr[0], addr[1]
    username = None
    try:
        conn.sendall(FTP_BANNER)
        conn.settimeout(15)
        buffer_event("FTP", src_ip, src_port, "connection", {})
        for _ in range(10):
            line = _recv_line(conn, 256).strip()
            if not line: break
            cmd, _, arg = line.partition(" ")
            cmd = cmd.upper()
            if cmd == "USER":
                username = arg; conn.sendall(FTP_PASS_OK)
            elif cmd == "PASS":
                buffer_event("FTP", src_ip, src_port, "credential_capture",
                             {"username": username, "password": arg})
                conn.sendall(FTP_FAIL); break
            elif cmd == "QUIT":
                conn.sendall(FTP_BYE); break
            else:
                conn.sendall(FTP_UNKNOWN)
    except Exception as e:
        log.debug(f"FTP {src_ip}: {e}")

# ---------------------------------------------------------------------------
# HTTP honeypot
# ---------------------------------------------------------------------------

_LOGIN_HTML = b"""<!DOCTYPE html><html><head><title>Admin Login</title>
<style>body{font-family:Arial,sans-serif;background:#1a1a2e;display:flex;
justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#fff;padding:40px;border-radius:8px;width:320px;box-shadow:0 4px 20px rgba(0,0,0,.4)}
h2{text-align:center;margin-bottom:24px;color:#333}
input{width:100%;padding:10px;margin:8px 0 16px;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:12px;background:#4a90d9;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:15px}
</style></head><body><div class="box"><h2>Admin Panel</h2>
<form method="POST" action="/login">
<label>Username</label><input type="text" name="username"/>
<label>Password</label><input type="password" name="password"/>
<button type="submit">Login</button></form></div></body></html>"""

_HTTP_200 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
             b"Connection: close\r\nContent-Length: " +
             str(len(_LOGIN_HTML)).encode() + b"\r\n\r\n" + _LOGIN_HTML)
_HTTP_404 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
_HTTP_FAIL = _HTTP_200  # same page, always "fail"

LOGIN_PATHS = {"/","/login","/admin","/wp-login.php","/administrator",
               "/panel","/manage","/console","/phpmyadmin"}

def handle_http(conn, addr):
    src_ip, src_port = addr[0], addr[1]
    try:
        conn.settimeout(10)
        raw = b""
        while b"\r\n\r\n" not in raw and len(raw) < 8192:
            chunk = conn.recv(1024)
            if not chunk: break
            raw += chunk
        # Read body
        cl_m = re.search(rb"[Cc]ontent-[Ll]ength:\s*(\d+)", raw)
        if cl_m:
            cl = int(cl_m.group(1))
            body_so_far = raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""
            while len(body_so_far) < cl:
                chunk = conn.recv(1024)
                if not chunk: break
                raw += chunk
                body_so_far = raw.split(b"\r\n\r\n", 1)[1]

        try:
            hdr, _, body = raw.partition(b"\r\n\r\n")
            lines  = hdr.decode(errors="replace").split("\r\n")
            parts  = lines[0].split(" ")
            method = parts[0] if parts else "?"
            path   = parts[1] if len(parts) > 1 else "/"
            hdrs   = {}
            for line in lines[1:]:
                if ": " in line:
                    k,_,v = line.partition(": ")
                    hdrs[k.lower()] = v
            ua = hdrs.get("user-agent","")
        except Exception:
            method, path, ua, body = "?","/","",b""

        buffer_event("HTTP", src_ip, src_port, "request",
                     {"method":method,"path":path,"user_agent":ua[:200]})

        if method == "POST" and path in LOGIN_PATHS:
            fields = {k: v[0] if v else ""
                      for k, v in parse_qs(body.decode(errors="replace")).items()}
            uname = fields.get("username") or fields.get("user") or fields.get("log","")
            pwd   = fields.get("password") or fields.get("pass") or fields.get("pwd","")
            if uname or pwd:
                buffer_event("HTTP", src_ip, src_port, "credential_capture",
                             {"username":uname,"password":pwd,"path":path})
            conn.sendall(_HTTP_FAIL)
        elif method in ("GET","HEAD"):
            conn.sendall(_HTTP_200)
        else:
            conn.sendall(_HTTP_404)
    except Exception as e:
        log.debug(f"HTTP {src_ip}: {e}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global SERVER_URL, API_KEY, SENSOR_NAME, SENSOR_ID
    global _event_buffer, _geoip, _iocs

    parser = argparse.ArgumentParser(description="HoneyWatch Sensor Agent")
    parser.add_argument("--server",      default=os.environ.get("HONEY_SERVER",""),
                        help="Central server URL, e.g. http://10.0.0.1:5000")
    parser.add_argument("--key",         default=os.environ.get("HONEY_KEY",""),
                        help="Sensor API key (from dashboard)")
    parser.add_argument("--name",        default=os.environ.get("HONEY_NAME","sensor-01"),
                        help="Sensor name / ID")
    parser.add_argument("--ssh-port",    type=int, default=2222)
    parser.add_argument("--http-port",   type=int, default=8880)
    parser.add_argument("--ftp-port",    type=int, default=2121)
    parser.add_argument("--telnet-port", type=int, default=2323)
    parser.add_argument("--no-ssh",      action="store_true")
    parser.add_argument("--no-http",     action="store_true")
    parser.add_argument("--no-ftp",      action="store_true")
    parser.add_argument("--no-telnet",   action="store_true")
    parser.add_argument("--ioc-file",    default="iocs.txt")
    parser.add_argument("--geoip-db",    default="GeoLite2-City.mmdb")
    parser.add_argument("--buffer-size", type=int, default=10_000)
    parser.add_argument("--log-file",    default="sensor.log")
    args = parser.parse_args()

    if not args.server or not args.key:
        parser.error("--server and --key are required (or set HONEY_SERVER / HONEY_KEY env vars)")

    # Clean up name to make a valid sensor ID
    SERVER_URL  = args.server.rstrip("/")
    API_KEY     = args.key
    SENSOR_NAME = args.name
    SENSOR_ID   = re.sub(r"[^a-z0-9_-]", "-", args.name.lower())

    # Logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(args.log_file),
            logging.StreamHandler(),
        ]
    )

    log.info(f"HoneyWatch Sensor Agent v{VERSION}")
    log.info(f"Sensor ID: {SENSOR_ID}  Server: {SERVER_URL}")

    _event_buffer = collections.deque(maxlen=args.buffer_size)
    _geoip        = GeoIP(args.geoip_db)
    _iocs         = IOCStore(args.ioc_file)

    # Register (blocks until server responds)
    register()

    # Start background workers
    threading.Thread(target=_flush_worker,     daemon=True, name="flusher").start()
    threading.Thread(target=_heartbeat_worker, daemon=True, name="heartbeat").start()
    threading.Thread(target=_config_poller,   daemon=True, name="config-poll").start()

    # Start honeypot services
    if not args.no_ssh:    start_tcp_server(args.ssh_port,    handle_ssh,    "SSH")
    if not args.no_http:   start_tcp_server(args.http_port,   handle_http,   "HTTP")
    if not args.no_ftp:    start_tcp_server(args.ftp_port,    handle_ftp,    "FTP")
    if not args.no_telnet: start_tcp_server(args.telnet_port, handle_telnet, "Telnet")

    log.info("All services running. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(60)
            log.info(f"Status — buffered: {len(_event_buffer)}  sent: {_events_sent}")
    except KeyboardInterrupt:
        log.info("Sensor stopped.")

if __name__ == "__main__":
    main()
