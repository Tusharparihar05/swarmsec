#!/bin/bash
# Run ALL attacks sequentially for demo purposes
echo "╔══════════════════════════════════════════╗"
echo "║     SwarmSec Attack Demo Suite           ║"
echo "║     Make sure all 6 agents are running!  ║"
echo "╚══════════════════════════════════════════╝"
echo ""

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Press Enter to start Attack 1 (Port Scan)..."
read
bash "$SCRIPT_DIR/01_port_scan.sh"

echo ""
echo "================================"
echo "Press Enter to start Attack 2 (SQL Injection)..."
read
bash "$SCRIPT_DIR/02_sql_injection.sh"

echo ""
echo "================================"
echo "Press Enter to start Attack 3 (XSS)..."
read
bash "$SCRIPT_DIR/03_xss_attack.sh"

echo ""
echo "================================"
echo "Press Enter to start Attack 4 (Reverse Shell)..."
read
bash "$SCRIPT_DIR/04_reverse_shell.sh"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║     All attacks complete!                ║"
echo "║     Check agent terminals for results    ║"
echo "║     Open dashboard: streamlit run        ║"
echo "║        dashboard.py                      ║"
echo "╚══════════════════════════════════════════╝"
