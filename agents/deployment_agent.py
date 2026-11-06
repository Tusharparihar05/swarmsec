"""
SwarmSec Deployment & Logging Agent
Subscribes to swarmsec:verified (tested fixes from Sandbox Agent).
If a fix passed sandbox testing:  applies it to the live container.
If it failed:                     logs the failure and escalates.
All actions are logged to MongoDB for audit trail.
"""

import json
import os
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

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
mongo = MongoClient(MONGO_URI)
db = mongo[DB_NAME]


def apply_fix_to_container(container_name, commands):
    """
    Apply remediation commands to a live Docker container via docker exec.
    Returns list of (command, success, output) tuples.
    """
    results = []
    for cmd in commands:
        try:
            result = subprocess.run(
                ["docker", "exec", container_name, "sh", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            success = result.returncode == 0
            output = result.stdout.strip() or result.stderr.strip()
            results.append({
                "command": cmd,
                "success": success,
                "output": output,
            })
            if success:
                print(f"    ✅ {cmd}")
            else:
                print(f"    ❌ {cmd} -> {output}")
        except subprocess.TimeoutExpired:
            results.append({
                "command": cmd,
                "success": False,
                "output": "Timed out (10s)",
            })
            print(f"    ⏱️ {cmd} -> timed out")
        except Exception as e:
            results.append({
                "command": cmd,
                "success": False,
                "output": str(e),
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
    print(f"Deployment agent listening on {VERIFIED_CHANNEL} ...")
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
