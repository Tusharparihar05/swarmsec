#!/bin/bash
# Attack 4: Reverse Shell Simulation
# Suricata rule: "Possible Reverse Shell Detected" (SID 1000005)
# Sends TCP traffic containing "/bin/sh" through the network
# Expected scenario: reverse_shell

echo "=== ATTACK 4: Reverse Shell Simulation ==="
echo "Attacker: web -> Target: api"
echo ""

API_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' api)
echo "API IP: $API_IP"

# Start a netcat listener on the api container
echo "Setting up listener on api:9999..."
docker exec -d api sh -c "apt-get update -qq && apt-get install -y -qq netcat-openbsd 2>/dev/null; nc -l -p 9999 &"
sleep 3

# Simulate reverse shell connection from web (sends /bin/sh in payload)
echo "Simulating reverse shell connection from web..."
docker exec web sh -c "echo '/bin/sh -i' | nc -w 2 $API_IP 9999" 2>/dev/null || true
docker exec web sh -c "echo 'exec /bin/sh' | nc -w 2 $API_IP 9999" 2>/dev/null || true
docker exec web sh -c "echo '/bin/sh 0<&1 2>&1' | nc -w 2 $API_IP 9999" 2>/dev/null || true

# Also try with ncat if available
docker exec web sh -c "printf '/bin/sh\\n' | nc $API_IP 9999 &" 2>/dev/null || true

echo ""
echo "✅ Reverse shell simulation complete. Check detection_agent terminal."
echo "   Expected: reverse_shell scenario (threshold: 1 occurrence = instant)"
