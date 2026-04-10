#!/usr/bin/env python3
"""
Network Listener - Incident Response Tool
Logs incoming TCP/UDP connections with GeoIP, IOC matching, and repeat-connection alerting.
Use only on systems you own or are authorized to monitor.

Dependencies:
    pip install requests

Optional GeoIP (offline, faster):
    pip install geoip2
    Download GeoLite2-City.mmdb from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"""

import socket
import threading
import logging
import argparse
import json
import ipaddress
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

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

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("network_listener.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

ALERT_LOG = logging.getLogger("alerts")
alert_handler = logging.FileHandler("network_listener_alerts.log")
alert_handler.setFormatter(logging.Formatter("%(asctime)s [ALERT] %(message)s"))
ALERT_LOG.addHandler(alert_handler)
ALERT_LOG.setLevel(logging.WARNING)

# ---------------------------------------------------------------------------
# IOC Store
# ---------------------------------------------------------------------------

class IOCStore:
    """Loads and matches IPs against known-bad indicators."""

    def __init__(self, ioc_file: str = None):
        self.bad_ips: set[str] = set()
        self.bad_cidrs: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        if ioc_file and Path(ioc_file).exists():
            self._load(ioc_file)
        else:
            log.info("No IOC file loaded. Create iocs.txt (one IP or CIDR per line) to enable matching.")

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
    """Resolves IP geolocation via local mmdb (preferred) or ip-api.com fallback."""

    PRIVATE_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]

    def __init__(self, mmdb_path: str = "GeoLite2-City.mmdb"):
        self._reader = None
        self._cache: dict[str, dict] = {}
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
                result = {
                    "country": r.country.name,
                    "city": r.city.name,
                    "org": None
                }
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
# Repeat-connection alerting
# ---------------------------------------------------------------------------

class ConnectionTracker:
    """Tracks connection frequency per IP and fires alerts on threshold breach."""

    def __init__(self, threshold: int = 10, window_seconds: int = 60):
        self.threshold = threshold
        self.window = window_seconds
        self._history: dict[str, list[float]] = defaultdict(list)
        self._alerted: set[str] = set()
        self._lock = threading.Lock()

    def record(self, ip: str) -> bool:
        """Returns True if this connection triggers a repeat-connection alert."""
        now = time.monotonic()
        with self._lock:
            timestamps = self._history[ip]
            # Prune old entries outside the window
            self._history[ip] = [t for t in timestamps if now - t < self.window]
            self._history[ip].append(now)
            count = len(self._history[ip])

            if count >= self.threshold and ip not in self._alerted:
                self._alerted.add(ip)
                return True
            # Reset alert state if activity drops back below threshold
            if count < self.threshold and ip in self._alerted:
                self._alerted.discard(ip)
        return False

    def get_count(self, ip: str) -> int:
        now = time.monotonic()
        with self._lock:
            return len([t for t in self._history[ip] if now - t < self.window])


# ---------------------------------------------------------------------------
# Core listener logic
# ---------------------------------------------------------------------------

def build_entry(proto, src_ip, src_port, dst_port, data, geo, ioc_match, conn_count):
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "protocol": proto,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "data_preview": data[:200].hex() if data else None,
        "geo": geo,
        "ioc_match": ioc_match,
        "connections_in_window": conn_count
    }


def process_connection(proto, src_ip, src_port, dst_port, data, geoip, iocs, tracker):
    geo = geoip.lookup(src_ip)
    ioc_match = iocs.is_malicious(src_ip)
    repeat_alert = tracker.record(src_ip)
    conn_count = tracker.get_count(src_ip)

    entry = build_entry(proto, src_ip, src_port, dst_port, data, geo, ioc_match, conn_count)
    log.info(json.dumps(entry))

    if ioc_match:
        msg = f"IOC MATCH — {src_ip} ({geo.get('country')}) hit port {dst_port} [{proto}]"
        ALERT_LOG.warning(msg)
        print(f"\n  *** ALERT: {msg} ***\n")

    if repeat_alert:
        msg = (
            f"REPEAT CONNECTION — {src_ip} ({geo.get('country')}) "
            f"reached {conn_count} connections on port {dst_port} [{proto}]"
        )
        ALERT_LOG.warning(msg)
        print(f"\n  *** ALERT: {msg} ***\n")


def handle_tcp_client(conn, addr, port, geoip, iocs, tracker):
    src_ip, src_port = addr
    try:
        data = conn.recv(1024)
        process_connection("TCP", src_ip, src_port, port, data, geoip, iocs, tracker)
    except Exception as e:
        log.debug(f"TCP recv error from {src_ip}: {e}")
    finally:
        conn.close()


def tcp_listener(port, geoip, iocs, tracker):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.listen(50)
        log.info(f"TCP listener active on port {port}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(
                target=handle_tcp_client,
                args=(conn, addr, port, geoip, iocs, tracker),
                daemon=True
            )
            t.start()
    except PermissionError:
        log.error(f"Permission denied on port {port} — use sudo for ports < 1024")
    except OSError as e:
        log.error(f"TCP bind failed on port {port}: {e}")
    finally:
        s.close()


def udp_listener(port, geoip, iocs, tracker):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        log.info(f"UDP listener active on port {port}")
        while True:
            data, addr = s.recvfrom(1024)
            src_ip, src_port = addr
            process_connection("UDP", src_ip, src_port, port, data, geoip, iocs, tracker)
    except PermissionError:
        log.error(f"Permission denied on port {port} — use sudo for ports < 1024")
    except OSError as e:
        log.error(f"UDP bind failed on port {port}: {e}")
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Network listener with GeoIP, IOC matching, and alerting")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[4444, 8080, 9999],
                        help="Ports to listen on (default: 4444 8080 9999)")
    parser.add_argument("--tcp-only", action="store_true", help="TCP only")
    parser.add_argument("--udp-only", action="store_true", help="UDP only")
    parser.add_argument("--ioc-file", default="iocs.txt",
                        help="Path to IOC file — one IP or CIDR per line (default: iocs.txt)")
    parser.add_argument("--geoip-db", default="GeoLite2-City.mmdb",
                        help="Path to GeoLite2-City.mmdb for offline GeoIP (optional)")
    parser.add_argument("--alert-threshold", type=int, default=10,
                        help="Connections from same IP within window to trigger alert (default: 10)")
    parser.add_argument("--alert-window", type=int, default=60,
                        help="Time window in seconds for repeat-connection alerting (default: 60)")
    args = parser.parse_args()

    geoip = GeoIP(mmdb_path=args.geoip_db)
    iocs = IOCStore(ioc_file=args.ioc_file)
    tracker = ConnectionTracker(threshold=args.alert_threshold, window_seconds=args.alert_window)

    threads = []
    for port in args.ports:
        if not args.udp_only:
            t = threading.Thread(target=tcp_listener, args=(port, geoip, iocs, tracker), daemon=True)
            t.start()
            threads.append(t)
        if not args.tcp_only:
            t = threading.Thread(target=udp_listener, args=(port, geoip, iocs, tracker), daemon=True)
            t.start()
            threads.append(t)

    log.info(f"Listening on ports {args.ports} | alert threshold: {args.alert_threshold} conns/{args.alert_window}s")
    log.info("Logs -> network_listener.log | Alerts -> network_listener_alerts.log")
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        log.info("Listener stopped.")


if __name__ == "__main__":
    main()
