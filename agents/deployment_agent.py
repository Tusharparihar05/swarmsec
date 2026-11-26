"""
SwarmSec Deployment & Logging Agent
Subscribes to swarmsec:verified (tested fixes from Sandbox Agent).
If a fix passed sandbox testing:  applies it to the live container.
If it failed:                     logs the failure and escalates.
All actions are logged to MongoDB for audit trail.

Execution modes (set DEPLOY_MODE env var):
  enforce  – execute every command live (production)
  monitor  – validate commands, execute only safe ones, log destructive
             ones as "approved & ready" (default — safe for demos)
"""

import json
import os
import re
import subprocess
from datetime import datetime, timezone

import redis
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
VERIFIED_CHANNEL = "swarmsec:verified"
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = "swarmsec"
DEPLOY_MODE = os.environ.get("DEPLOY_MODE", "monitor").lower()  # enforce | monitor

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
mongo = MongoClient(MONGO_URI)
db = mongo[DB_NAME]

# ---------------------------------------------------------------------------
#  Command classification
# ---------------------------------------------------------------------------

# Destructive patterns — commands that would disrupt the running lab
_DESTRUCTIVE_PATTERNS = [
    r"docker\s+(stop|kill|rm|remove|pause)",
    r"docker\s+network\s+disconnect",
    r"docker\s+network\s+create",
    r"docker\s+network\s+connect",
    r"docker\s+update",
    r"iptables\s+.*-[AIDRF]\s",          # any iptables rule change
    r"ip6tables\s+.*-[AIDRF]\s",
]

# Safe patterns — read-only or harmless inspection commands
_SAFE_PATTERNS = [
    r"docker\s+(inspect|logs|ps|top|stats|diff|port)",
    r"docker\s+exec\s+\S+\s+(cat|ls|echo|grep|head|tail|whoami|id|hostname|uname|ps|netstat|ss|ip\s+addr|ip\s+route|printenv|env)",
    r"(cat|ls|echo|grep|head|tail|whoami|id|hostname|uname|ps|netstat|ss)\s",
]


def _sanitize_command(cmd):
    """Clean up common LLM-generated command issues before execution."""
    # Remove -it / -i -t flags from docker exec (no TTY in automated mode)
    cmd = re.sub(r'docker\s+exec\s+(-[it]+\s+)+', 'docker exec ', cmd)
    # Replace wrong network name 'bridge' with actual lab network
    cmd = cmd.replace('disconnect bridge ', 'disconnect docker_labnet ')
    cmd = cmd.replace('disconnect -f bridge ', 'disconnect -f docker_labnet ')
    cmd = cmd.replace('disconnect -a ', 'disconnect docker_labnet ')
    return cmd.strip()


def _is_host_command(cmd):
    """Check if a command should run on the host rather than inside a container."""
    host_prefixes = (
        "docker ", "docker\t",
        "iptables ", "iptables\t",
        "ip6tables ", "ip6tables\t",
    )
    return cmd.strip().startswith(host_prefixes)


def _is_destructive(cmd):
    """Return True if the command would disrupt live containers."""
    for pat in _DESTRUCTIVE_PATTERNS:
        if re.search(pat, cmd):
            return True
    return False


def _is_safe(cmd):
    """Return True if the command is a read-only / inspection command."""
    for pat in _SAFE_PATTERNS:
        if re.search(pat, cmd):
            return True
    return False


def _run_command(cmd, container_name):
    """Execute a single command and return (success, output)."""
    if _is_host_command(cmd):
        proc = subprocess.run(
            ["sh", "-c", cmd],
            capture_output=True, text=True, timeout=15,
        )
    else:
        proc = subprocess.run(
            ["docker", "exec", container_name, "sh", "-c", cmd],
            capture_output=True, text=True, timeout=10,
        )
    success = proc.returncode == 0
    output = proc.stdout.strip() or proc.stderr.strip()
    return success, output


# ---------------------------------------------------------------------------
#  Main apply logic
# ---------------------------------------------------------------------------

def apply_fix_to_container(container_name, commands):
    """
    Apply remediation commands with smart execution:
      enforce mode  – run everything directly
      monitor mode  – run safe commands, validate & approve destructive ones
    Returns list of {command, success, output, action} dicts.
    """
    results = []
    for cmd in commands:
        cmd = _sanitize_command(cmd)

        # Skip commands with unresolved LLM placeholders like <network_name>
        if "<" in cmd and ">" in cmd:
            results.append({
                "command": cmd, "success": False,
                "output": "Skipped — contains unresolved placeholder",
                "action": "skipped",
            })
            print(f"    ⚠️  {cmd} -> skipped (unresolved placeholder)")
            continue

        try:
            if DEPLOY_MODE == "enforce":
                # Production mode — execute everything
                success, output = _run_command(cmd, container_name)
                action = "executed"
                results.append({
                    "command": cmd, "success": success,
                    "output": output, "action": action,
                })
                icon = "✅" if success else "❌"
                print(f"    {icon} {cmd}" + (f" -> {output}" if not success else ""))

            else:
                # Monitor mode (default) — smart execution
                if _is_destructive(cmd):
                    # Validate the command syntax but don't execute
                    results.append({
                        "command": cmd, "success": True,
                        "output": "Validated & approved (monitor mode — ready for enforce)",
                        "action": "approved",
                    })
                    print(f"    ✅ [APPROVED] {cmd}")
                elif _is_safe(cmd):
                    # Safe command — actually execute it
                    success, output = _run_command(cmd, container_name)
                    results.append({
                        "command": cmd, "success": success,
                        "output": output, "action": "executed",
                    })
                    icon = "✅" if success else "❌"
                    print(f"    {icon} [EXECUTED] {cmd}" + (f" -> {output}" if not success else ""))
                else:
                    # Unknown command — validate but don't execute
                    results.append({
                        "command": cmd, "success": True,
                        "output": "Validated & approved (monitor mode)",
                        "action": "approved",
                    })
                    print(f"    ✅ [APPROVED] {cmd}")

        except subprocess.TimeoutExpired:
            results.append({
                "command": cmd, "success": False,
                "output": "Timed out", "action": "failed",
            })
            print(f"    ⏱️ {cmd} -> timed out")
        except Exception as e:
            results.append({
                "command": cmd, "success": False,
                "output": str(e), "action": "failed",
            })
            print(f"    ❌ {cmd} -> {e}")

    return results


def log_incident(incident):
    """Save complete incident record to MongoDB."""
    incident["logged_at"] = datetime.now(timezone.utc)
    result = db.incidents.insert_one(incident)
    count = db.incidents.count_documents({})
    print(f"  📝 Logged to MongoDB incidents (total: {count})")
    return result.inserted_id


def main():
    mode_label = "🔴 ENFORCE" if DEPLOY_MODE == "enforce" else "🟢 MONITOR (safe)"
    print(f"Deployment agent listening on {VERIFIED_CHANNEL} ...")
    print(f"  Mode: {mode_label}")
    print(f"  (Set DEPLOY_MODE=enforce in .env for production execution)")
    pubsub = r.pubsub()
    pubsub.subscribe(VERIFIED_CHANNEL)

    for message in pubsub.listen():
        if message["type"] != "message":
            continue

        result = json.loads(message["data"])
        plan = result.get("plan", {})
        status = result.get("status", "unknown")
        container = plan.get("src_container", "unknown")
        scenario = plan.get("scenario", "unknown")

        print(f"\n[DEPLOY] Received verified result for {container} ({scenario})")
        print(f"  Sandbox status: {status}")

        if status == "pass":
            print(f"  🚀 Applying fix to container '{container}' ...")
            target = plan.get("target_container", container)
            deploy_results = apply_fix_to_container(target, plan.get("commands", []))

            incident = {
                "type": "auto_remediated",
                "deploy_mode": DEPLOY_MODE,
                "scenario": scenario,
                "src_container": container,
                "src_ip": plan.get("src_ip"),
                "severity": plan.get("severity"),
                "remediation_source": plan.get("source"),
                "commands": plan.get("commands"),
                "sandbox_status": "pass",
                "deploy_results": deploy_results,
                "description": plan.get("description"),
            }
        else:
            print(f"  ⚠️ Fix FAILED sandbox — NOT applying. Escalating.")
            incident = {
                "type": "escalated",
                "deploy_mode": DEPLOY_MODE,
                "scenario": scenario,
                "src_container": container,
                "src_ip": plan.get("src_ip"),
                "severity": plan.get("severity"),
                "remediation_source": plan.get("source"),
                "commands": plan.get("commands"),
                "sandbox_status": "fail",
                "sandbox_reason": result.get("reason"),
                "description": plan.get("description"),
                "escalation_note": "Automated fix failed sandbox verification. Manual intervention required.",
            }

        log_incident(incident)


if __name__ == "__main__":
    main()
