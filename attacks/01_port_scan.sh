#!/bin/bash
# Attack 1: Port Scan (Lateral Movement)
# Suricata rule: "Possible TCP SYN Scan Detected" (SID 1000002)
# Expected scenario: port_scan_lateral_movement

set -euo pipefail

echo "=== ATTACK 1: TCP SYN Port Scan ==="
echo "Attacker: web -> Target: api"
echo ""

# Install nmap in web container
docker exec web sh -c 'command -v nmap >/dev/null 2>&1 || apk add --no-cache nmap'

# Get API container IP
API_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api)
if [ -z "$API_IP" ]; then
    echo "❌ Could not determine the API container IP."
    exit 1
fi
echo "API IP: $API_IP"

echo "Starting SYN scan (skip host discovery)..."
docker exec web nmap -Pn -sS "$API_IP" -p 1-100 --min-rate 100

echo ""
echo "✅ Port scan complete. Check detection_agent terminal for alerts."
echo "   Expected: port_scan_lateral_movement with threshold_met=true"
