#!/bin/bash
# HoneyWatch — stop dashboard and honeypot

cd "$(dirname "$0")"

for pidfile in dashboard.pid honeypot.pid; do
    if [ -f "$pidfile" ]; then
        pid=$(cat "$pidfile")
        if kill "$pid" 2>/dev/null; then
            echo "✓ Stopped $(basename $pidfile .pid) (pid $pid)"
        else
            echo "⚠ $(basename $pidfile .pid) was not running"
        fi
        rm -f "$pidfile"
    fi
done
