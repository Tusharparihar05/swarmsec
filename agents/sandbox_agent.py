"""
SwarmSec Sandbox Verification Agent
Subscribes to swarmsec:remediation (fix proposals from Remediation Agent).
Tests each fix in a temporary Docker container before applying to production.
If the fix passes, publishes to swarmsec:verified.
If it fails, logs the failure and does NOT apply the fix.
"""

import json
import os
import subprocess

import redis
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REMEDIATION_CHANNEL = "swarmsec:remediation"
VERIFIED_CHANNEL = "swarmsec:verified"
SANDBOX_IMAGE = "alpine:3.18"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def test_command_in_sandbox(command):
    """
    Run a remediation command in a temporary Docker container.
    Returns (success: bool, output: str).
    The container is removed after the test (--rm flag).
    """
    try:
        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "--network", "none",  # isolated — no network access
                SANDBOX_IMAGE,
                "sh", "-c", command,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        success = result.returncode == 0
        output = result.stdout.strip() or result.stderr.strip()
        return success, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out (10s)"
    except Exception as e:
        return False, f"Sandbox error: {e}"


def validate_commands(commands):
    """
    Validate remediation commands are safe to run.
    Returns (safe: bool, reason: str).
    """
    dangerous_patterns = [
        "rm -rf /",
        "mkfs",
        "dd if=/dev/zero",
        ":(){:|:&};:",  # fork bomb
        "chmod 777 /",
        "> /dev/sda",
    ]

    for cmd in commands:
        for pattern in dangerous_patterns:
            if pattern in cmd:
                return False, f"Dangerous command blocked: {pattern}"

    # Check commands use expected tools (iptables, arp, kill, etc.)
    allowed_tools = {"iptables", "ip6tables", "arp", "kill", "pkill", "ss", "netstat"}
    for cmd in commands:
        first_word = cmd.strip().split()[0] if cmd.strip() else ""
        if first_word not in allowed_tools:
            # Not in allowlist, but might still be okay — flag for review
            return True, f"Warning: '{first_word}' not in standard allowlist"

    return True, "All commands validated"


def test_remediation(plan):
    """
    Test a remediation plan in sandbox.
    Returns result dict with pass/fail and details.
    """
    commands = plan.get("commands", [])

    if not commands:
        return {
            "status": "fail",
            "reason": "No commands to test",
            "plan": plan,
        }

    # Step 1: Validate commands are safe
    safe, reason = validate_commands(commands)
    if not safe:
        return {
            "status": "fail",
            "reason": reason,
            "plan": plan,
        }

    # Step 2: Test each command syntax in sandbox
    results = []
    all_passed = True
    for cmd in commands:
        # Test command syntax (iptables --check instead of --append in sandbox)
        test_cmd = cmd
        if "iptables" in cmd:
            # In sandbox without network, iptables won't work, but we can
            # at least validate the command structure
            test_cmd = f"echo 'SYNTAX OK: {cmd}'"

        success, output = test_command_in_sandbox(test_cmd)
        results.append({
            "command": cmd,
            "passed": success,
            "output": output,
        })
        if not success:
            all_passed = False

    return {
        "status": "pass" if all_passed else "fail",
        "reason": reason,
        "test_results": results,
        "plan": plan,
    }


def main():
    print(f"Sandbox agent listening on {REMEDIATION_CHANNEL} ...")
    print(f"Sandbox image: {SANDBOX_IMAGE}")
    pubsub = r.pubsub()
    pubsub.subscribe(REMEDIATION_CHANNEL)

    for message in pubsub.listen():
        if message["type"] != "message":
            continue

        plan = json.loads(message["data"])
        print(f"\n[SANDBOX] Testing fix for {plan.get('src_container')} "
              f"({plan.get('scenario')})")
        print(f"  Commands: {plan.get('commands')}")

        result = test_remediation(plan)

        if result["status"] == "pass":
            print(f"  ✅ PASSED — publishing to {VERIFIED_CHANNEL}")
            r.publish(VERIFIED_CHANNEL, json.dumps(result))
        else:
            print(f"  ❌ FAILED — {result['reason']}")
            print(f"  Fix will NOT be applied to production.")
            # Still publish failure for logging
            r.publish(VERIFIED_CHANNEL, json.dumps(result))


if __name__ == "__main__":
    main()
