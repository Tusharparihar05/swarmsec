#!/bin/bash
# Attack 1: Port Scan (Lateral Movement)
# Suricata rule: "Possible TCP SYN Scan Detected" (SID 1000002)
# Expected scenario: port_scan_lateral_movement

echo "=== ATTACK 1: TCP SYN Port Scan ==="
echo "Attacker: web -> Target: api"
echo ""

# Install nmap in web container
docker exec web sh -c "apk add --no-cache nmap 2>/dev/null || apt-get update && apt-get install -y nmap 2>/dev/null" 2>/dev/null

# Get API container IP
API_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api)
echo "API IP: $API_IP"

echo "Starting SYN scan..."
docker exec web nmap -sS "$API_IP" -p 1-100 --min-rate 100

echo ""
echo "✅ Port scan complete. Check detection_agent terminal for alerts."
echo "   Expected: port_scan_lateral_movement with threshold_met=true"
