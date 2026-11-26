# SwarmSec Attack Test Scripts

Run each attack in a **separate terminal** while all 6 agents are running.

## Quick Start
```bash
# Terminal 1: Start all agents (from swarmsec/ directory)
bash run_all_agents.sh

# Terminal 2: Run attacks one by one
bash attacks/01_port_scan.sh
bash attacks/02_sql_injection.sh
bash attacks/03_xss_attack.sh
bash attacks/04_reverse_shell.sh
```

The agent launcher checks that `web` and `api` share a Docker network. If it
reports a network mismatch, run this from the repository root and start the
agents again:

```bash
docker compose -f docker/docker-compose.yml up -d --force-recreate web suricata
```
