<div align="center">

# 🛡️ SwarmSec

### Multi-Agent AI-Powered Cybersecurity System for Docker Containers

[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue.svg)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docker.com)
[![Suricata](https://img.shields.io/badge/IDS-Suricata-EF3B2D.svg)](https://suricata.io)
[![Groq](https://img.shields.io/badge/LLM-Groq_Free-F55036.svg)](https://groq.com)
[![Neo4j](https://img.shields.io/badge/Graph-Neo4j-008CC1.svg)](https://neo4j.com)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io)

**SwarmSec** detects, analyzes, and auto-remediates cyberattacks in containerized networks using a swarm of 6 AI agents working together in real-time.

[Features](#-features) • [Architecture](#-architecture) • [Quick Start](#-quick-start) • [Dashboard](#-dashboard) • [Evaluation](#-comparative-evaluation)

</div>

---

## 🎯 Features

- **🔍 Two-Layer Detection** — Suricata signature rules + LLM reasoning (Groq, free tier)
- **🕸️ Blast Radius Analysis** — Neo4j graph DB maps attack spread across containers
- **🤖 Auto-Remediation** — LLM generates Docker isolation commands automatically
- **🧪 Sandbox Verification** — Tests every fix in an isolated container before deploying
- **🚀 Auto-Deployment** — Applies verified fixes to production in < 5 seconds
- **📊 Real-Time Dashboard** — 6-page Streamlit dashboard with live metrics
- **📋 Full Audit Trail** — Every detection, fix, and deployment logged to MongoDB

---

## 🏗️ Architecture

```
                        ┌──────────────────────────────────────────┐
                        │          DOCKER CONTAINER LAB            │
                        │  ┌─────┐ ┌─────┐ ┌────┐ ┌───────┐      │
                        │  │ web │→│ api │→│ db │ │ admin │      │
                        │  └──┬──┘ └─────┘ └────┘ └───────┘      │
                        │     │    ┌───────┐ ┌─────────┐ ┌─────┐ │
                        │     │    │ redis │ │ mongodb │ │neo4j│ │
                        │     │    └───────┘ └─────────┘ └─────┘ │
                        └─────┼───────────────────────────────────┘
                              │ monitors
                        ┌─────▼─────┐
                        │ Suricata  │  ← Network IDS
                        │ eve.json  │
                        └─────┬─────┘
                              │ new alerts
            ┌─────────────────▼──────────────────┐
            │      AGENT 1: Detection Agent      │
            │  Layer 1: Regex + Threshold Rules   │
            │  Layer 2: Groq LLM Reasoning        │
            │  Dedup: 30s cooldown per scenario   │
            └─────────────────┬──────────────────┘
                              │ Redis: swarmsec:detections
            ┌─────────────────▼──────────────────┐
            │   AGENT 2: Graph Context Agent     │
            │  IP → Container mapping (Docker)    │
            │  Blast radius query (Neo4j)         │
            │  Output: affected containers        │
            └─────────────────┬──────────────────┘
                              │ Redis: swarmsec:context
            ┌─────────────────▼──────────────────┐
            │    AGENT 3: Remediation Agent      │
            │  Primary: Groq LLM generates fix    │
            │  Fallback: Template per scenario    │
            │  Output: docker/iptables commands   │
            └─────────────────┬──────────────────┘
                              │ Redis: swarmsec:remediation
            ┌─────────────────▼──────────────────┐
            │     AGENT 4: Sandbox Agent         │
            │  Allowlist validation (docker,      │
            │    iptables, arp, kill, etc.)        │
            │  Test in alpine:3.18 --network none │
            └─────────────────┬──────────────────┘
                              │ Redis: swarmsec:verified
            ┌─────────────────▼──────────────────┐
            │    AGENT 5: Deployment Agent       │
            │  Apply fix via docker exec          │
            │  Log incident to MongoDB            │
            └─────────────────┬──────────────────┘
                              │
            ┌─────────────────▼──────────────────┐
            │    AGENT 6: Mongo Logger           │
            │  Subscribes to ALL 4 channels       │
            │  Persists to MongoDB collections    │
            └────────────────────────────────────┘
                              │
            ┌─────────────────▼──────────────────┐
            │      Streamlit Dashboard           │
            │  Overview │ Detections │ Graph      │
            │  Incidents │ Agents │ Evaluation    │
            └────────────────────────────────────┘
```

### Data Flow

```
Suricata Alert → Detection Agent → Graph Context Agent → Remediation Agent
                                                              ↓
              MongoDB ← Deployment Agent ← Sandbox Agent ← Fix Plan
```

### Inter-Agent Communication

All agents communicate via **Redis Pub/Sub** channels:

| Channel | Publisher | Subscriber |
|---------|-----------|------------|
| `swarmsec:detections` | Detection Agent | Graph Context Agent, Mongo Logger |
| `swarmsec:context` | Graph Context Agent | Remediation Agent, Mongo Logger |
| `swarmsec:remediation` | Remediation Agent | Sandbox Agent, Mongo Logger |
| `swarmsec:verified` | Sandbox Agent | Deployment Agent, Mongo Logger |

---

## 🚀 Quick Start

### Prerequisites

- Docker Desktop
- Python 3.11+
- Free Groq API key from [console.groq.com](https://console.groq.com/keys)

### 1. Clone & Setup

```bash
git clone https://github.com/Tusharparihar05/swarmsec.git
cd swarmsec

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env → add your GROQ_API_KEY
```

### 2. Start Docker Lab

```bash
cd docker
docker compose up -d
cd ..
```

This starts 8 containers: `web`, `api`, `db`, `admin`, `redis`, `mongodb`, `neo4j`, `suricata`

### 3. Load Neo4j Topology

```bash
python agents/load_topology.py
```

### 4. Start All Agents

**Option A — Single terminal:**
```bash
bash run_all_agents.sh
```

**Option B — Separate terminals (recommended for demo):**
```bash
# Terminal 1
python agents/detection_agent.py

# Terminal 2
python agents/graph_context_agent.py

# Terminal 3
python agents/remediation_agent.py

# Terminal 4
python agents/sandbox_agent.py

# Terminal 5
python agents/deployment_agent.py

# Terminal 6
python agents/mongo_logger.py
```

### 5. Open Dashboard

```bash
streamlit run dashboard.py
# Opens at http://localhost:8501
```

---

---

## 📊 Dashboard

The Streamlit dashboard provides 6 pages of real-time visibility:

| Page | Description |
|------|-------------|
| **Overview** | KPI metrics, scenario distribution pie chart, severity bar chart, sandbox pass/fail rate |
| **Live Detections** | Latest 30 alerts with timestamps, IPs, signatures, scenarios, LLM verdicts |
| **Network Graph** | Container topology — attacked nodes in 🔴 red, blast radius in 🟠 orange, safe in 🟢 green |
| **Incidents** | Timeline of auto-remediated vs escalated incidents with commands applied |
| **Agents** | Description cards for all 6 agents explaining their role |
| **Evaluation** | SwarmSec vs Suricata comparison table with live statistics |

```bash
streamlit run dashboard.py
# → http://localhost:8501
```

---

## 📈 Comparative Evaluation

### SwarmSec vs Baseline Suricata IDS

| Metric | Suricata Only | SwarmSec (Ours) |
|--------|---------------|-----------------|
| Detection Method | Signature-based | **Signature + LLM** |
| False Positive Handling | Manual review | **LLM auto-filters** |
| Context Awareness | None | **Neo4j blast radius** |
| Remediation | Manual / none | **Auto-generated (LLM)** |
| Fix Verification | None | **Sandbox testing** |
| Deployment | Manual | **Auto-deployment** |
| Response Time | > 30 min (human) | **< 5 seconds** |
| Lateral Movement Viz | No | **Yes (graph DB)** |
| Audit Trail | Log files | **MongoDB + dashboard** |

Run the evaluation script to generate a report from your MongoDB data:

```bash
python evaluate.py
```

---

## 🛠️ Tech Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| IDS | Suricata | Network intrusion detection (signature-based) |
| LLM | Groq API (Qwen 3.8-27B) | Alert reasoning + remediation generation |
| Graph DB | Neo4j | Container topology + blast radius queries |
| Message Bus | Redis Pub/Sub | Real-time inter-agent communication |
| Storage | MongoDB | Audit trail, incident logs, dashboard data |
| Containers | Docker Compose | 8-container lab environment |
| Dashboard | Streamlit + Plotly | Real-time visualization |
| Language | Python 3.11 | All agent logic |

---

## 📁 Project Structure

```
swarmsec/
├── agents/                      # All 6 agent scripts
│   ├── detection_agent.py       # Layer 1 rules + Layer 2 LLM detection
│   ├── graph_context_agent.py   # Neo4j blast radius analysis
│   ├── remediation_agent.py     # LLM-generated fix commands
│   ├── sandbox_agent.py         # Isolated fix verification
│   ├── deployment_agent.py      # Production fix deployment
│   ├── mongo_logger.py          # MongoDB audit logging
│   ├── rule_layer.py            # Regex + threshold rule engine
│   └── load_topology.py         # Neo4j graph initialization
├── docker/
│   ├── docker-compose.yml       # 8-container lab definition
│   └── suricata/
│       └── rules/local.rules    # Custom Suricata detection rules
├── dashboard.py                 # Streamlit real-time dashboard
├── evaluate.py                  # Comparative evaluation script
├── run_all_agents.sh            # Launch all agents in one command
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment template
└── README.md                    # This file
```

---

## 👨‍💻 Author

**Tushar Parihar** — Major Project, 2026

---

## 📄 License

This project is for academic purposes as part of a college Major Project.
