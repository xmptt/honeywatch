#!/bin/bash
# HoneyWatch — start dashboard and honeypot safely

cd "$(dirname "$0")"

# ---------- Dashboard ----------
if lsof -i :5000 -t &>/dev/null; then
    echo "✓ Dashboard already running on port 5000"
else
    nohup python3 dashboard.py --host 127.0.0.1 --port 5000 \
        > dashboard_server.log 2>&1 &
    echo $! > dashboard.pid
    echo "✓ Dashboard started  →  http://127.0.0.1:5000  (pid $(cat dashboard.pid))"
fi

# ---------- Honeypot ----------
if lsof -i :2222 -t &>/dev/null; then
    echo "✓ Honeypot already running"
else
    nohup python3 honeypot.py \
        > honeypot_server.log 2>&1 &
    echo $! > honeypot.pid
    echo "✓ Honeypot started (SSH:2222 HTTP:8880 FTP:2121 Telnet:2323)  (pid $(cat honeypot.pid))"
fi

echo ""
echo "Logs:  tail -f dashboard_server.log"
echo "       tail -f honeypot_server.log"
echo "Stop:  ./stop.sh"
