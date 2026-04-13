#!/usr/bin/env python3
"""
HoneyWatch — Central Server & Admin Dashboard
Receives events from remote sensor agents, stores in SQLite, serves fleet dashboard.

Usage:
    pip install flask
    python dashboard.py [--host 0.0.0.0] [--port 5000]

Default login: admin / admin  —  change on first login!
"""

import os, sys, json, re, csv, io, socket, hashlib, hmac, secrets
import logging, threading, time, sqlite3, ipaddress
from datetime import datetime, timezone, timedelta
from pathlib import Path
from functools import wraps
from collections import defaultdict
from urllib.request import urlopen, Request

try:
    from flask import (Flask, request, jsonify, session, redirect,
                       render_template, Response)
except ImportError:
    print("Flask not installed. Run: pip install flask"); sys.exit(1)

# ---------------------------------------------------------------------------
# Paths / config
# ---------------------------------------------------------------------------

BASE_DIR     = Path(__file__).parent
TEMPLATE_DIR = BASE_DIR / "templates"
CONFIG_FILE  = BASE_DIR / "dashboard_config.json"
DB_FILE      = BASE_DIR / "honeywatch.db"

LOG_FILES = [
    "honeypot.log", "honeypot_alerts.log",
    "network_listener.log", "network_listener_alerts.log",
]

DEFAULT_CONFIG = {
    "username": "admin",
    "password_hash": hashlib.sha256(b"admin").hexdigest(),
    "secret_key": secrets.token_hex(32),
    "siem": {
        "webhook_url": "", "webhook_token": "", "webhook_type": "generic",
        "webhook_enabled": False,
        "syslog_host": "", "syslog_port": 514, "syslog_proto": "udp",
        "syslog_enabled": False, "realtime_forward": False,
    },
    "event_retention_days": 90,
}

# ---------------------------------------------------------------------------
# SQLite database
# ---------------------------------------------------------------------------

_db: sqlite3.Connection = None
_db_lock = threading.Lock()

def init_db():
    global _db
    _db = sqlite3.connect(str(DB_FILE), check_same_thread=False)
    _db.row_factory = sqlite3.Row
    _db.execute("PRAGMA journal_mode=WAL")
    _db.execute("PRAGMA synchronous=NORMAL")
    _db.executescript("""
        CREATE TABLE IF NOT EXISTS sensors (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            api_key       TEXT NOT NULL UNIQUE,
            description   TEXT DEFAULT '',
            registered_at TEXT NOT NULL,
            last_seen     TEXT,
            last_ip       TEXT,
            status        TEXT NOT NULL DEFAULT 'offline',
            location_lat  REAL,
            location_lon  REAL,
            location_label TEXT DEFAULT '',
            services      TEXT DEFAULT '[]',
            version       TEXT DEFAULT '',
            notes         TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id   TEXT NOT NULL,
            timestamp   TEXT NOT NULL,
            received_at TEXT NOT NULL,
            service     TEXT,
            src_ip      TEXT,
            src_port    INTEGER,
            event_type  TEXT,
            username    TEXT,
            password    TEXT,
            path        TEXT,
            method      TEXT,
            user_agent  TEXT,
            ioc_match   INTEGER DEFAULT 0,
            geo_country TEXT,
            geo_city    TEXT,
            geo_lat     REAL,
            geo_lon     REAL,
            geo_org     TEXT,
            raw         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ev_ts     ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_ev_sensor ON events(sensor_id);
        CREATE INDEX IF NOT EXISTS idx_ev_ip     ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_ev_type   ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_ev_svc    ON events(service);
    """)
    _db.commit()

def db_query(sql, params=()):
    return _db.execute(sql, params).fetchall()

def db_one(sql, params=()):
    return _db.execute(sql, params).fetchone()

def db_write(sql, params=()):
    with _db_lock:
        _db.execute(sql, params)
        _db.commit()

def db_write_many(sql, rows):
    with _db_lock:
        _db.executemany(sql, rows)
        _db.commit()

# ---------------------------------------------------------------------------
# Local log import (one-time, on startup)
# ---------------------------------------------------------------------------

_JSON_RE = re.compile(r'\[(?:INFO|WARNING|ERROR|CRITICAL)\]\s+(\{.+\})\s*$')

def _parse_log_line(line):
    m = _JSON_RE.search(line)
    if m:
        try: return json.loads(m.group(1))
        except: pass
    return None

def import_local_logs():
    """Import local honeypot log files into SQLite as a built-in 'local' sensor."""
    # Only run once
    existing = db_one("SELECT COUNT(*) FROM events WHERE sensor_id='local'")[0]
    if existing > 0:
        return

    now = datetime.now(timezone.utc).isoformat()
    db_write("""
        INSERT OR IGNORE INTO sensors
            (id, name, api_key, registered_at, last_seen, status, description)
        VALUES ('local','Local Node','',?,?,'offline','Events imported from local log files')
    """, (now, now))

    rows = []
    for name in LOG_FILES:
        path = BASE_DIR / name
        if not path.exists(): continue
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    ev = _parse_log_line(line.rstrip())
                    if ev:
                        rows.append(_event_to_row("local", ev))
        except Exception as e:
            logging.warning(f"Log import error {name}: {e}")

    if rows:
        db_write_many(_INSERT_SQL, rows)
        logging.info(f"Imported {len(rows)} events from local log files")

_INSERT_SQL = """
    INSERT INTO events
        (sensor_id, timestamp, received_at, service, src_ip, src_port,
         event_type, username, password, path, method, user_agent,
         ioc_match, geo_country, geo_city, geo_lat, geo_lon, geo_org, raw)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""

def _event_to_row(sensor_id, ev):
    geo = ev.get("geo") or {}
    now = datetime.now(timezone.utc).isoformat()
    return (
        sensor_id,
        ev.get("timestamp", now),
        now,
        ev.get("service", ""),
        ev.get("src_ip", ""),
        ev.get("src_port"),
        ev.get("event", ""),
        ev.get("username"),
        ev.get("password"),
        ev.get("path"),
        ev.get("method"),
        ev.get("user_agent"),
        1 if ev.get("ioc_match") else 0,
        geo.get("country"),
        geo.get("city"),
        geo.get("lat"),
        geo.get("lon"),
        geo.get("org"),
        json.dumps(ev),
    )

# ---------------------------------------------------------------------------
# Watchdog — marks sensors offline after missed heartbeats
# ---------------------------------------------------------------------------

def _sensor_watchdog():
    while True:
        try:
            cutoff = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
            db_write(
                "UPDATE sensors SET status='offline' "
                "WHERE last_seen < ? AND status='online' AND id != 'local'",
                (cutoff,)
            )
        except Exception as e:
            logging.warning(f"Watchdog error: {e}")
        time.sleep(30)

# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_cfg():
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text())
        except: pass
    return DEFAULT_CONFIG.copy()

def _save_cfg(cfg):
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__, template_folder=str(TEMPLATE_DIR))
cfg = _load_cfg()
if "secret_key" not in cfg:
    cfg["secret_key"] = secrets.token_hex(32); _save_cfg(cfg)
app.secret_key = cfg["secret_key"]

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def dec(*a, **kw):
        if not session.get("auth"): return redirect("/login")
        return f(*a, **kw)
    return dec

def api_auth(f):
    @wraps(f)
    def dec(*a, **kw):
        if not session.get("auth"): return jsonify({"error": "Unauthorized"}), 401
        return f(*a, **kw)
    return dec

def _verify_sensor(req):
    """Verify sensor API key from Authorization: Bearer <key> header."""
    auth = req.headers.get("Authorization", "")
    if not auth.startswith("Bearer "): return None
    raw_key = auth[7:].strip()
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    row = db_one("SELECT * FROM sensors WHERE api_key=?", (key_hash,))
    return dict(row) if row else None

def sensor_auth(f):
    @wraps(f)
    def dec(*a, **kw):
        sensor = _verify_sensor(request)
        if not sensor: return jsonify({"error": "Invalid API key"}), 401
        return f(sensor, *a, **kw)
    return dec

# ---------------------------------------------------------------------------
# GeoIP cache (for enriching events that lack geo data)
# ---------------------------------------------------------------------------

_geo_cache: dict = {}

def _is_private(ip):
    try:
        parts = [int(x) for x in ip.split(".")]
        if parts[0] in (10, 127): return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
    except: pass
    return False

def enrich_geo(ips):
    to_lookup = [ip for ip in set(ips) if ip and not _is_private(ip) and ip not in _geo_cache]
    if not to_lookup: return
    for ip in to_lookup[:100]:
        try:
            req = Request(f"http://ip-api.com/json/{ip}?fields=country,city,lat,lon,org",
                          headers={"Accept": "application/json"})
            with urlopen(req, timeout=8) as r:
                d = json.loads(r.read())
            _geo_cache[ip] = {"lat": d.get("lat"), "lon": d.get("lon"),
                              "country": d.get("country"), "city": d.get("city"),
                              "org": d.get("org")}
        except: pass

# ---------------------------------------------------------------------------
# SIEM forwarding
# ---------------------------------------------------------------------------

def _send_webhook(event, siem):
    url = siem.get("webhook_url", "")
    if not url: return False
    try:
        wtype = siem.get("webhook_type", "generic")
        body  = json.dumps({"event": event, "sourcetype": "honeypot"} if wtype == "splunk" else event).encode()
        token = siem.get("webhook_token", "")
        hdrs  = {"Content-Type": "application/json"}
        if wtype == "splunk" and token: hdrs["Authorization"] = f"Splunk {token}"
        elif token: hdrs["Authorization"] = f"Bearer {token}"
        req = Request(url, data=body, headers=hdrs, method="POST")
        urlopen(req, timeout=5)
        return True
    except Exception as e:
        logging.warning(f"Webhook error: {e}"); return False

def _send_syslog(event, siem):
    host = siem.get("syslog_host", "")
    port = int(siem.get("syslog_port", 514))
    if not host: return False
    try:
        msg = (f"<134>1 {event.get('timestamp','')} honeypot honeypot - - - "
               f"sensor={event.get('sensor_id','?')} service={event.get('service','?')} "
               f"src_ip={event.get('src_ip','?')} event={event.get('event','?')} "
               f"raw={json.dumps(event)}").encode()
        if siem.get("syslog_proto") == "tcp":
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5); s.connect((host, port)); s.sendall(msg); s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(msg, (host, port)); s.close()
        return True
    except Exception as e:
        logging.warning(f"Syslog error: {e}"); return False

# ---------------------------------------------------------------------------
# Stats queries (SQL aggregation — much faster than Python loops)
# ---------------------------------------------------------------------------

def _where(sensor_id):
    return ("WHERE sensor_id=?", (sensor_id,)) if sensor_id else ("", ())

def get_stats(sensor_id=None):
    w, p = _where(sensor_id)
    totals = db_one(f"""
        SELECT COUNT(*) total,
               COUNT(DISTINCT src_ip) unique_ips,
               SUM(CASE WHEN event_type='credential_capture' THEN 1 ELSE 0 END) creds,
               SUM(ioc_match) iocs
        FROM events {w}
    """, p)

    services   = db_query(f"SELECT service, COUNT(*) n FROM events {w} GROUP BY service ORDER BY n DESC", p)
    evt_types  = db_query(f"SELECT event_type, COUNT(*) n FROM events {w} GROUP BY event_type ORDER BY n DESC", p)
    countries  = db_query(f"SELECT geo_country, COUNT(*) n FROM events {w} WHERE geo_country IS NOT NULL AND geo_country NOT IN ('Private','') GROUP BY geo_country ORDER BY n DESC LIMIT 15", p)
    top_ips    = db_query(f"SELECT src_ip, COUNT(*) n FROM events {w} WHERE src_ip IS NOT NULL GROUP BY src_ip ORDER BY n DESC LIMIT 20", p)
    top_users  = db_query(f"SELECT username, COUNT(*) n FROM events {w} WHERE username IS NOT NULL AND username!='' GROUP BY username ORDER BY n DESC LIMIT 20", p)
    top_pwds   = db_query(f"SELECT password, COUNT(*) n FROM events {w} WHERE password IS NOT NULL AND password!='' GROUP BY password ORDER BY n DESC LIMIT 20", p)
    timeline   = db_query(f"SELECT strftime('%Y-%m-%dT%H:00', timestamp) hr, COUNT(*) n FROM events {w} WHERE timestamp IS NOT NULL GROUP BY hr ORDER BY hr", p)

    return {
        "total_events":        totals["total"] or 0,
        "unique_ips":          totals["unique_ips"] or 0,
        "credentials_captured":totals["creds"] or 0,
        "ioc_matches":         totals["iocs"] or 0,
        "services":    {r["service"]: r["n"] for r in services if r["service"]},
        "event_types": {r["event_type"]: r["n"] for r in evt_types if r["event_type"]},
        "countries":   [[r["geo_country"], r["n"]] for r in countries],
        "top_ips":     [[r["src_ip"], r["n"]] for r in top_ips],
        "top_usernames":[[r["username"], r["n"]] for r in top_users],
        "top_passwords":[[r["password"], r["n"]] for r in top_pwds],
        "timeline":    [[r["hr"], r["n"]] for r in timeline],
    }

# ---------------------------------------------------------------------------
# Routes — pages
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        c = _load_cfg()
        u, p = request.form.get("username",""), request.form.get("password","")
        if u == c["username"] and hashlib.sha256(p.encode()).hexdigest() == c["password_hash"]:
            session["auth"] = True; return redirect("/")
        error = "Invalid credentials"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear(); return redirect("/login")

@app.route("/")
@login_required
def index():
    return render_template("dashboard.html")

# ---------------------------------------------------------------------------
# Routes — sensor API (Bearer token auth)
# ---------------------------------------------------------------------------

@app.route("/api/sensor/register", methods=["POST"])
@sensor_auth
def sensor_register(sensor):
    data = request.get_json(force=True) or {}
    now  = datetime.now(timezone.utc).isoformat()
    db_write("""
        UPDATE sensors SET status='online', last_seen=?, last_ip=?,
            services=?, version=?, name=COALESCE(NULLIF(?,''), name)
        WHERE id=?
    """, (now, request.remote_addr,
          json.dumps(data.get("services", [])),
          data.get("version",""),
          data.get("name",""),
          sensor["id"]))
    return jsonify({"status":"registered","sensor_id":sensor["id"],
                    "flush_interval":5,"heartbeat_interval":30})

@app.route("/api/sensor/heartbeat", methods=["POST"])
@sensor_auth
def sensor_heartbeat(sensor):
    now = datetime.now(timezone.utc).isoformat()
    db_write("UPDATE sensors SET status='online', last_seen=?, last_ip=? WHERE id=?",
             (now, request.remote_addr, sensor["id"]))
    return jsonify({"status":"ok","server_time":now})

@app.route("/api/sensor/events", methods=["POST"])
@sensor_auth
def sensor_events(sensor):
    data  = request.get_json(force=True) or {}
    batch = data.get("batch", [])
    if len(batch) > 500:
        return jsonify({"error":"batch_too_large"}), 400

    rows = []; rejected = 0
    for ev in batch:
        try:
            rows.append(_event_to_row(sensor["id"], ev))
        except Exception:
            rejected += 1

    if rows:
        db_write_many(_INSERT_SQL, rows)
        now = datetime.now(timezone.utc).isoformat()
        db_write("UPDATE sensors SET last_seen=? WHERE id=?", (now, sensor["id"]))

    # Forward to SIEM if real-time enabled
    c = _load_cfg()
    siem = c.get("siem", {})
    if siem.get("realtime_forward"):
        for ev in batch:
            ev["sensor_id"] = sensor["id"]
            if siem.get("webhook_enabled"): _send_webhook(ev, siem)
            if siem.get("syslog_enabled"):  _send_syslog(ev, siem)

    return jsonify({"accepted": len(rows), "rejected": rejected})

# ---------------------------------------------------------------------------
# Routes — sensor management (admin)
# ---------------------------------------------------------------------------

@app.route("/api/sensors", methods=["GET"])
@api_auth
def api_sensors_list():
    sensors = db_query("SELECT * FROM sensors ORDER BY registered_at DESC")
    result  = []
    for s in sensors:
        s = dict(s)
        cnt = db_one("SELECT COUNT(*) n FROM events WHERE sensor_id=?", (s["id"],))
        s["event_count"] = cnt["n"] if cnt else 0
        s["api_key"]     = ""  # never expose hash
        result.append(s)
    return jsonify(result)

@app.route("/api/sensors", methods=["POST"])
@api_auth
def api_sensors_create():
    data   = request.get_json(force=True) or {}
    sid    = re.sub(r"[^a-z0-9_-]", "-", data.get("id","").lower().strip())
    name   = data.get("name", sid)
    if not sid:
        return jsonify({"error":"id required"}), 400
    if db_one("SELECT id FROM sensors WHERE id=?", (sid,)):
        return jsonify({"error":"sensor id already exists"}), 409

    raw_key  = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now      = datetime.now(timezone.utc).isoformat()
    db_write("""
        INSERT INTO sensors (id, name, api_key, description, registered_at, status, notes)
        VALUES (?,?,?,?,?,?,?)
    """, (sid, name, key_hash, data.get("description",""), now, "offline", data.get("notes","")))

    return jsonify({"sensor_id": sid, "api_key": raw_key,
                    "deploy_cmd": f"python3 sensor.py --server http://YOUR_SERVER:5000 --key {raw_key} --name {sid}"})

@app.route("/api/sensors/<sensor_id>", methods=["PATCH"])
@api_auth
def api_sensors_update(sensor_id):
    if not db_one("SELECT id FROM sensors WHERE id=?", (sensor_id,)):
        return jsonify({"error":"not found"}), 404
    data = request.get_json(force=True) or {}
    allowed = {"name","description","notes","location_lat","location_lon","location_label"}
    for k, v in data.items():
        if k in allowed:
            # Guard against NaN / non-finite floats which break JSON
            if isinstance(v, float):
                import math
                if not math.isfinite(v):
                    continue
            db_write(f"UPDATE sensors SET {k}=? WHERE id=?", (v, sensor_id))
    return jsonify({"status":"updated"})

# Sensor polls this to pick up config changes (name rename, notes, etc.)
@app.route("/api/sensor/config", methods=["GET"])
@sensor_auth
def sensor_config(sensor):
    row = db_one("SELECT name, notes, location_label FROM sensors WHERE id=?", (sensor["id"],))
    if not row:
        return jsonify({"error":"not found"}), 404
    return jsonify({
        "sensor_id":      sensor["id"],
        "name":           row["name"],
        "notes":          row["notes"] or "",
        "location_label": row["location_label"] or "",
    })

@app.route("/api/sensors/<sensor_id>", methods=["DELETE"])
@api_auth
def api_sensors_delete(sensor_id):
    if sensor_id == "local":
        return jsonify({"error":"cannot delete built-in local sensor"}), 400
    db_write("DELETE FROM sensors WHERE id=?", (sensor_id,))
    return jsonify({"status":"deleted"})

@app.route("/api/sensors/<sensor_id>/rotate-key", methods=["POST"])
@api_auth
def api_rotate_key(sensor_id):
    if sensor_id == "local":
        return jsonify({"error":"no key for local sensor"}), 400
    if not db_one("SELECT id FROM sensors WHERE id=?", (sensor_id,)):
        return jsonify({"error":"not found"}), 404
    raw_key  = secrets.token_hex(32)
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    db_write("UPDATE sensors SET api_key=?, status='offline' WHERE id=?", (key_hash, sensor_id))
    return jsonify({"api_key": raw_key,
                    "deploy_cmd": f"python3 sensor.py --server http://YOUR_SERVER:5000 --key {raw_key} --name {sensor_id}"})

# ---------------------------------------------------------------------------
# Routes — dashboard API (admin)
# ---------------------------------------------------------------------------

@app.route("/api/events")
@api_auth
def api_events():
    page      = int(request.args.get("page", 1))
    per_page  = min(int(request.args.get("per_page", 50)), 200)
    svc_f     = request.args.get("service","").upper()
    evt_f     = request.args.get("event","")
    ip_f      = request.args.get("ip","")
    sensor_f  = request.args.get("sensor_id","")

    clauses, params = [], []
    if svc_f:    clauses.append("service=?");    params.append(svc_f)
    if evt_f:    clauses.append("event_type=?"); params.append(evt_f)
    if ip_f:     clauses.append("src_ip LIKE ?");params.append(f"%{ip_f}%")
    if sensor_f: clauses.append("sensor_id=?");  params.append(sensor_f)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    total = db_one(f"SELECT COUNT(*) n FROM events {where}", params)["n"]
    rows  = db_query(
        f"SELECT e.*, s.name sensor_name FROM events e "
        f"LEFT JOIN sensors s ON e.sensor_id=s.id {where} "
        f"ORDER BY e.timestamp DESC LIMIT ? OFFSET ?",
        params + [per_page, (page-1)*per_page]
    )
    return jsonify({
        "events": [_row_to_event(r) for r in rows],
        "total": total, "page": page,
        "pages": max(1,(total+per_page-1)//per_page),
    })

def _row_to_event(r):
    d = dict(r)
    # Rebuild compact dict for frontend
    return {
        "timestamp":   d.get("timestamp"),
        "service":     d.get("service"),
        "src_ip":      d.get("src_ip"),
        "src_port":    d.get("src_port"),
        "event":       d.get("event_type"),
        "username":    d.get("username"),
        "password":    d.get("password"),
        "path":        d.get("path"),
        "method":      d.get("method"),
        "user_agent":  d.get("user_agent"),
        "ioc_match":   bool(d.get("ioc_match")),
        "geo_country": d.get("geo_country"),
        "sensor_id":   d.get("sensor_id"),
        "sensor_name": d.get("sensor_name",""),
    }

@app.route("/api/stats")
@api_auth
def api_stats():
    sensor_id = request.args.get("sensor_id")
    return jsonify(get_stats(sensor_id or None))

@app.route("/api/geo")
@api_auth
def api_geo():
    # Attacker markers
    rows = db_query("""
        SELECT src_ip, geo_country, geo_city, geo_lat, geo_lon, geo_org, COUNT(*) cnt
        FROM events
        WHERE geo_lat IS NOT NULL AND geo_lon IS NOT NULL
        GROUP BY src_ip
        ORDER BY cnt DESC
        LIMIT 2000
    """)
    attackers = [{"ip":r["src_ip"],"lat":r["geo_lat"],"lon":r["geo_lon"],
                  "country":r["geo_country"],"city":r["geo_city"],
                  "org":r["geo_org"],"count":r["cnt"]} for r in rows]

    # Sensor deployment markers
    sensors = db_query("""
        SELECT id, name, location_lat, location_lon, location_label, status
        FROM sensors WHERE location_lat IS NOT NULL AND id!='local'
    """)
    sensor_markers = [{"id":s["id"],"lat":s["location_lat"],"lon":s["location_lon"],
                       "label":s["location_label"] or s["name"],"status":s["status"]} for s in sensors]

    return jsonify({"attackers": attackers, "sensors": sensor_markers})

@app.route("/api/credentials")
@api_auth
def api_credentials():
    sensor_id = request.args.get("sensor_id","")
    w = "WHERE event_type='credential_capture'" + (" AND sensor_id=?" if sensor_id else "")
    p = (sensor_id,) if sensor_id else ()
    rows = db_query(f"SELECT * FROM events {w} ORDER BY timestamp DESC LIMIT 1000", p)
    return jsonify([_row_to_event(r) for r in rows])

@app.route("/api/siem", methods=["GET","POST"])
@api_auth
def api_siem():
    c = _load_cfg()
    if request.method == "POST":
        data = request.get_json(force=True) or {}
        c["siem"].update(data); _save_cfg(c)
        return jsonify({"status":"saved"})
    siem = dict(c.get("siem",{}))
    if siem.get("webhook_token"): siem["webhook_token_set"]=True; siem["webhook_token"]=""
    return jsonify(siem)

@app.route("/api/siem/test", methods=["POST"])
@api_auth
def api_siem_test():
    c = _load_cfg(); siem = c.get("siem",{})
    ev = {"timestamp":datetime.now(timezone.utc).isoformat(),"service":"DASHBOARD",
          "src_ip":"0.0.0.0","event":"siem_test","sensor_id":"dashboard"}
    results = {}
    if siem.get("webhook_enabled") and siem.get("webhook_url"):
        results["webhook"] = _send_webhook(ev, siem)
    if siem.get("syslog_enabled") and siem.get("syslog_host"):
        results["syslog"]  = _send_syslog(ev, siem)
    return jsonify(results)

@app.route("/api/export")
@api_auth
def api_export():
    fmt       = request.args.get("format","json")
    sensor_id = request.args.get("sensor_id","")
    w = ("WHERE sensor_id=?" if sensor_id else "")
    p = (sensor_id,) if sensor_id else ()
    rows = db_query(f"SELECT * FROM events {w} ORDER BY timestamp DESC LIMIT 50000", p)
    events = [_row_to_event(r) for r in rows]

    if fmt == "csv":
        out  = io.StringIO()
        keys = ["timestamp","sensor_id","sensor_name","service","src_ip","src_port",
                "event","username","password","path","method","user_agent","ioc_match","geo_country"]
        w2 = csv.DictWriter(out, fieldnames=keys, extrasaction="ignore")
        w2.writeheader(); w2.writerows(events)
        return Response(out.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition":"attachment; filename=honeywatch_events.csv"})
    return Response(json.dumps(events,indent=2), mimetype="application/json",
                    headers={"Content-Disposition":"attachment; filename=honeywatch_events.json"})

@app.route("/api/change-password", methods=["POST"])
@api_auth
def api_change_password():
    c = _load_cfg()
    pw = (request.get_json(force=True) or {}).get("password","")
    if len(pw) < 8: return jsonify({"error":"Minimum 8 characters"}), 400
    c["password_hash"] = hashlib.sha256(pw.encode()).hexdigest()
    _save_cfg(c)
    return jsonify({"status":"updated"})

@app.route("/api/forward-batch", methods=["POST"])
@api_auth
def api_forward_batch():
    c    = _load_cfg(); siem = c.get("siem",{})
    n    = min(int((request.get_json(force=True) or {}).get("count",100)), 1000)
    rows = db_query("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (n,))
    ok = err = 0
    for r in rows:
        ev = _row_to_event(r); success = True
        if siem.get("webhook_enabled") and siem.get("webhook_url"):
            success = success and _send_webhook(ev, siem)
        if siem.get("syslog_enabled") and siem.get("syslog_host"):
            success = success and _send_syslog(ev, siem)
        if success: ok += 1
        else: err += 1
    return jsonify({"forwarded":ok,"errors":err})

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HoneyWatch Central Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    if not CONFIG_FILE.exists():
        _save_cfg(DEFAULT_CONFIG.copy())
        print("Created dashboard_config.json  —  default login: admin / admin")
        print("CHANGE THE PASSWORD after first login!\n")

    init_db()
    import_local_logs()

    threading.Thread(target=_sensor_watchdog, daemon=True).start()

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")
    print(f"HoneyWatch Central Server  →  http://{args.host}:{args.port}")
    print("Sensor endpoint: POST /api/sensor/events  (Bearer token auth)")
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
