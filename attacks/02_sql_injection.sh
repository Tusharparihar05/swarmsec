#!/bin/bash
# Attack 2: SQL Injection
# Suricata rule: "SQL Injection Attempt Detected" (SID 1000003)
# Requires HTTP traffic containing "SELECT" and "FROM" through Suricata
# Expected scenario: api_abuse

echo "=== ATTACK 2: SQL Injection ==="
echo "Attacker: web -> Target: api (via HTTP)"
echo ""

# Get API container IP
API_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api)
echo "API IP: $API_IP"

# Start a simple HTTP server in the API container first
echo "Starting temp HTTP server on api container..."
docker exec -d api sh -c "python3 -m http.server 8080 2>/dev/null &"
sleep 2

# Send SQL injection payloads through web container (Suricata monitors web's network)
echo "Sending SQL injection payloads..."
for i in $(seq 1 25); do
    docker exec web sh -c "wget -q -O /dev/null 'http://$API_IP:8080/?q=SELECT+username+FROM+users+WHERE+1=1' 2>/dev/null || curl -s 'http://$API_IP:8080/?q=SELECT+username+FROM+users+WHERE+1=1' >/dev/null 2>&1"
    docker exec web sh -c "wget -q -O /dev/null 'http://$API_IP:8080/?id=1+UNION+SELECT+password+FROM+credentials' 2>/dev/null || curl -s 'http://$API_IP:8080/?id=1+UNION+SELECT+password+FROM+credentials' >/dev/null 2>&1"
done

echo ""
echo "✅ SQL Injection attack complete. Check detection_agent terminal."
echo "   Expected: api_abuse scenario (threshold: 20 in 60s)"
