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
