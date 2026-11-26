#!/bin/bash
# SwarmSec - Launch All 6 Agents
# Run this from the swarmsec/ directory with virtualenv activated

echo "╔══════════════════════════════════════════╗"
echo "║         SwarmSec Agent Launcher          ║"
echo "╚══════════════════════════════════════════╝"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# Check Docker containers are running
echo "[1/7] Checking Docker containers..."
RUNNING=$(docker ps --format '{{.Names}}' | sort | tr '\n' ' ')
echo "  Running: $RUNNING"

REQUIRED="web api db redis mongodb neo4j suricata"
for c in $REQUIRED; do
    if ! docker ps --format '{{.Names}}' | grep -q "^${c}$"; then
        echo "  ⚠️  Container '$c' is NOT running!"
        echo "  Start Docker lab first: cd docker && docker compose up -d"
        exit 1
    fi
done
echo "  ✅ All containers running"

# Suricata shares web's network namespace. The attacker and target must also
# share a Docker network, or attack traffic never reaches the monitored link.
WEB_NETWORKS=$(docker inspect -f '{{range $name, $network := .NetworkSettings.Networks}}{{$name}} {{end}}' web)
API_NETWORKS=$(docker inspect -f '{{range $name, $network := .NetworkSettings.Networks}}{{$name}} {{end}}' api)
SHARED_NETWORK=""
for network in $WEB_NETWORKS; do
    case " $API_NETWORKS " in
        *" $network "*) SHARED_NETWORK=$network; break ;;
    esac
done

if [ -z "$SHARED_NETWORK" ]; then
    echo "  ❌ Containers 'web' and 'api' are not on a shared Docker network."
    echo "  Recreate them from this project with:"
    echo "    docker compose -f docker/docker-compose.yml up -d --force-recreate web suricata"
    exit 1
fi
echo "  ✅ web and api share network: $SHARED_NETWORK"

# Load Neo4j topology
echo ""
echo "[2/7] Loading Neo4j topology..."
source .venv/bin/activate 2>/dev/null
python agents/load_topology.py
echo "  ✅ Topology loaded"

# Launch agents in background with colored output
echo ""
echo "[3/7] Starting Detection Agent..."
python agents/detection_agent.py &
PID_DETECT=$!

echo "[4/7] Starting Graph Context Agent..."
python agents/graph_context_agent.py &
PID_GRAPH=$!

echo "[5/7] Starting Remediation Agent..."
python agents/remediation_agent.py &
PID_REMED=$!

echo "[6/7] Starting Sandbox Agent..."
python agents/sandbox_agent.py &
PID_SANDBOX=$!

echo "[7/7] Starting Deployment Agent..."
python agents/deployment_agent.py &
PID_DEPLOY=$!

# Also start mongo logger
python agents/mongo_logger.py &
PID_MONGO=$!

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  All 6 agents + logger started!          ║"
echo "║                                          ║"
echo "║  PIDs:                                   ║"
echo "║    Detection:  $PID_DETECT"
echo "║    Graph:      $PID_GRAPH"
echo "║    Remediation:$PID_REMED"
echo "║    Sandbox:    $PID_SANDBOX"
echo "║    Deployment: $PID_DEPLOY"
echo "║    MongoLogger:$PID_MONGO"
echo "║                                          ║"
echo "║  Press Ctrl+C to stop all agents         ║"
echo "╚══════════════════════════════════════════╝"

# Wait and cleanup on Ctrl+C
trap "echo 'Stopping all agents...'; kill $PID_DETECT $PID_GRAPH $PID_REMED $PID_SANDBOX $PID_DEPLOY $PID_MONGO 2>/dev/null; exit" SIGINT SIGTERM
wait
