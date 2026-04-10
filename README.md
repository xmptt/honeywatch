# HoneyWatch 🎯

A lightweight, self-hosted honeypot platform with a real-time fleet management dashboard. Deploy sensor agents across multiple machines to lure attackers, capture credentials, and visualise threat activity on a live world map — all feeding back to a central web UI.

---

## How it works

```
[Sensor A]  ──┐
[Sensor B]  ──┤──▶  Central Dashboard (Flask + SQLite)  ◀──  Admin Browser
[Sensor N]  ──┘
```

**Sensors** emulate common network services (SSH, HTTP, FTP, Telnet) to attract bots and scanners. Every connection attempt, credential submission, and HTTP request is logged as a structured JSON event and streamed to the central dashboard in real time over a simple authenticated HTTP API.

**The dashboard** stores all events in SQLite, presents them through a dark SOC-style web UI, and can forward events onward to a SIEM (Splunk, Elastic, syslog, or any webhook).

---

## Components

| File | Role |
|---|---|
| `sensor.py` | Deployable sensor agent — runs honeypot services and streams events |
| `dashboard.py` | Central server — receives events, stores them, serves the web UI |
| `honeypot.py` | Standalone honeypot (original single-node version, no dashboard) |
| `network_listener_v2.py` | Low-level raw network listener |
| `templates/login.html` | Dashboard login page |
| `templates/dashboard.html` | Main dashboard single-page app |

---

## Requirements

- Python 3.8+
- Flask (`pip install flask`)
- Optional: `requests` for online GeoIP lookups
- Optional: `geoip2` + MaxMind GeoLite2-City.mmdb for offline GeoIP

---

## Quick Start

### 1. Start the central dashboard

```bash
pip install flask
python3 dashboard.py --host 0.0.0.0 --port 5000
```

Open `http://localhost:5000` in your browser.  
Default login: **admin / admin** — change this immediately in the Settings tab.

### 2. Register a sensor

In the dashboard, go to **Sensors → Add Sensor**, fill in a name and ID, and click **Create Sensor**. You'll get a ready-to-run deploy command with an API key:

```
python3 sensor.py --server http://YOUR_SERVER:5000 --key <api-key> --name nyc-dc-01
```

The API key is shown only once. Use **Rotate Key** on the sensor card if you lose it.

### 3. Deploy the sensor

Copy `sensor.py` to any machine you want to monitor and run the deploy command:

```bash
python3 sensor.py \
  --server http://YOUR_SERVER:5000 \
  --key <api-key> \
  --name nyc-dc-01
```

The sensor registers with the dashboard, starts all honeypot services, and begins streaming events. Repeat for as many machines as you like.

---

## Sensor options

```
--server        Central dashboard URL (required)
--key           API key from dashboard (required)
--name          Sensor name / ID (required)
--ssh-port      SSH honeypot port (default: 2222)
--http-port     HTTP honeypot port (default: 8880)
--ftp-port      FTP honeypot port (default: 2121)
--telnet-port   Telnet honeypot port (default: 2323)
--no-ssh        Disable SSH service
--no-http       Disable HTTP service
--no-ftp        Disable FTP service
--no-telnet     Disable Telnet service
--ioc-file      Path to IOC list (one IP/CIDR per line)
--geoip-db      Path to GeoLite2-City.mmdb for offline GeoIP
--buffer-size   Max events to buffer locally if server unreachable (default: 10000)
--log-file      Local log file path (default: sensor.log)
```

You can also set `HONEY_SERVER`, `HONEY_KEY`, and `HONEY_NAME` as environment variables instead of passing flags.

---

## Dashboard features

| Section | What it shows |
|---|---|
| **Overview** | Live stat cards, attack timeline chart, service breakdown, top countries/IPs/credentials |
| **Sensors** | Fleet status — online/offline, last seen, event counts, location, key rotation |
| **Attack Map** | World map with clustered attacker IP markers (red) and sensor locations (cyan) |
| **Events** | Paginated event log, filterable by sensor, service, event type, and IP |
| **Credentials** | All captured username/password pairs in a searchable table |
| **SIEM** | Forward events to Splunk HEC, Elastic/Logstash, generic webhook, or syslog (UDP/TCP) |
| **Export** | Download all events as JSON or CSV, optionally filtered by sensor |
| **Settings** | Change admin password |

---

## SIEM integration

Go to the **SIEM** tab in the dashboard and configure one or both of:

**Webhook** — works with Splunk HEC, Elastic HTTP input, or any REST endpoint:
- Set the destination type, URL, and optional token
- Enable **Real-time forwarding** to stream events as they arrive from sensors

**Syslog** — RFC 5424 formatted messages over UDP or TCP:
- Set the host, port, and protocol

Use **Send Test Event** to verify connectivity before going live.

---

## GeoIP setup (optional but recommended)

For the attack map to show attacker locations, you need GeoIP data. Two options:

**Online (automatic, no setup):**  
Install `requests` and the sensor/dashboard will query ip-api.com automatically. Results are cached locally.

```bash
pip install requests
```

**Offline (faster, no rate limits):**  
Download the free MaxMind GeoLite2-City database and pass it to the sensor:

```bash
pip install geoip2
python3 sensor.py ... --geoip-db /path/to/GeoLite2-City.mmdb
```

---

## IOC matching

Create a file `iocs.txt` with one IP or CIDR per line to flag known-bad addresses:

```
185.220.101.0/24
1.2.3.4
# Comments supported
```

Pass it to the sensor with `--ioc-file iocs.txt`. Matching events are flagged with a red IOC badge in the dashboard.

---

## Architecture notes

- **Authentication**: Each sensor has a unique API key (SHA-256 hashed server-side). Sensors authenticate with `Authorization: Bearer <key>` on all API calls.
- **Buffering**: If the central server is unreachable, the sensor buffers up to 10,000 events locally and retries with exponential back-off (5s → 60s max). Events are never silently dropped unless the buffer overflows.
- **Heartbeat**: Sensors send a heartbeat every 30 seconds. The dashboard marks a sensor offline if no heartbeat is received within 90 seconds.
- **Database**: SQLite with WAL mode for concurrent reads. All events, sensor metadata, and stats are stored in `honeywatch.db`.
- **Local logs**: On first startup, the dashboard imports any existing `honeypot.log` / `honeypot_alerts.log` files into SQLite as a built-in `local` sensor.

---

## Security notes

- Run the dashboard behind a reverse proxy (nginx/Caddy) with TLS in production
- Bind the dashboard to `0.0.0.0` only if sensors need to reach it over the network
- The default `admin/admin` credentials **must** be changed before any real deployment
- Sensor API keys are never stored in plaintext — only SHA-256 hashes are kept
- Do not expose honeypot ports on a machine that has sensitive data or production services

---

## Standalone honeypot (no dashboard)

If you just want a single-node honeypot without the fleet management, use `honeypot.py` directly:

```bash
pip install requests  # optional, for GeoIP
python3 honeypot.py
```

Logs are written to `honeypot.log` and `honeypot_alerts.log` in JSON format.

---

## License

For defensive and educational use only. Only deploy on systems you own or are authorised to monitor.
