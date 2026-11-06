"""
SwarmSec Remediation Agent
Subscribes to swarmsec:context (blast-radius data from Graph Context Agent).
Uses Groq LLM to generate a remediation command for the detected attack.
Publishes the proposed fix to swarmsec:remediation for sandbox testing.
"""

import json
import os

import redis
from groq import Groq
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
CONTEXT_CHANNEL = "swarmsec:context"
REMEDIATION_CHANNEL = "swarmsec:remediation"

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
MOCK_LLM = os.environ.get("MOCK_LLM", "false").lower() == "true"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# Groq client
groq_client = None
if GROQ_API_KEY and not MOCK_LLM:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("[INFO] Groq LLM client initialised for remediation.")
    except Exception as e:
        print(f"[WARN] Could not initialise Groq client: {e}")

# --- Pre-built remediation templates per scenario ---
# When the LLM is unavailable, we fall back to these deterministic fixes.
REMEDIATION_TEMPLATES = {
    "port_scan_lateral_movement": {
        "description": "Block attacker IP via iptables and kill suspicious connections",
        "commands": [
            "iptables -A INPUT -s {src_ip} -j DROP",
            "iptables -A FORWARD -s {src_ip} -j DROP",
        ],
        "severity": "high",
    },
    "api_abuse": {
        "description": "Rate-limit the source and block malicious request patterns",
        "commands": [
            "iptables -A INPUT -s {src_ip} -p tcp --dport 80 -m limit --limit 10/min -j ACCEPT",
            "iptables -A INPUT -s {src_ip} -p tcp --dport 80 -j DROP",
        ],
        "severity": "high",
    },
    "routing_spoofing": {
        "description": "Drop spoofed ARP packets and lock ARP table",
        "commands": [
            "arp -s {src_ip} $(arp -n {src_ip} | tail -1 | awk '{{print $3}}')",
            "iptables -A INPUT -s {src_ip} -j DROP",
        ],
        "severity": "critical",
    },
    "reverse_shell": {
        "description": "Kill all outbound connections and isolate the container",
        "commands": [
            "iptables -A OUTPUT -s {src_ip} -j DROP",
            "iptables -A INPUT -s {src_ip} -j DROP",
        ],
        "severity": "critical",
    },
}


def generate_llm_remediation(context):
    """Use Groq LLM to generate a smart remediation plan."""
    if groq_client is None:
        return None

    prompt = f"""You are a network security incident responder working with Docker containers.

An attack has been detected:
- Attack type: {context.get('scenario', 'unknown')}
- Attacker container: {context.get('src_container', 'unknown')} (IP: {context.get('src_ip', 'unknown')})
- Blast radius (containers the attacker can reach): {context.get('blast_radius', [])}
- Suricata signature: {context.get('signature', 'unknown')}

Generate a remediation plan. Reply in EXACTLY this JSON format:
{{
  "description": "one-sentence description of the fix",
  "commands": ["shell command 1", "shell command 2"],
  "severity": "critical|high|medium|low",
  "target_container": "which container to run the commands in"
}}
"""
    try:
        response = groq_client.chat.completions.create(
            model="qwen/qwen3.8-27b",
            max_tokens=300,
            temperature=0.2,
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert Docker security incident responder. Reply with ONLY valid JSON, no markdown, no explanation.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        text = response.choices[0].message.content.strip()
        # Try to extract JSON from response
        if text.startswith("{"):
            return json.loads(text)
        # If wrapped in code block
        if "```" in text:
            json_str = text.split("```")[1]
            if json_str.startswith("json"):
                json_str = json_str[4:]
            return json.loads(json_str.strip())
        return None
    except Exception as e:
        print(f"[WARN] LLM remediation failed: {e}")
        return None


def generate_remediation(context):
    """Generate remediation plan - tries LLM first, falls back to templates."""
    scenario = context.get("scenario")
    src_ip = context.get("src_ip", "0.0.0.0")
    src_container = context.get("src_container", "unknown")

    # Try LLM-generated remediation first
    llm_plan = generate_llm_remediation(context)
    if llm_plan:
        llm_plan["source"] = "llm"
        llm_plan["src_container"] = src_container
        llm_plan["src_ip"] = src_ip
        llm_plan["scenario"] = scenario
        return llm_plan

    # Fall back to template
    template = REMEDIATION_TEMPLATES.get(scenario)
    if template is None:
        return {
            "description": f"Unknown scenario '{scenario}' - isolate source container",
            "commands": [f"iptables -A INPUT -s {src_ip} -j DROP"],
            "severity": "medium",
            "target_container": src_container,
            "source": "fallback",
            "src_container": src_container,
            "src_ip": src_ip,
            "scenario": scenario,
        }

    return {
        "description": template["description"],
        "commands": [cmd.format(src_ip=src_ip) for cmd in template["commands"]],
        "severity": template["severity"],
        "target_container": src_container,
        "source": "template",
        "src_container": src_container,
        "src_ip": src_ip,
        "scenario": scenario,
    }


def main():
    print(f"Remediation agent listening on {CONTEXT_CHANNEL} ...")
    pubsub = r.pubsub()
    pubsub.subscribe(CONTEXT_CHANNEL)

    for message in pubsub.listen():
        if message["type"] != "message":
            continue

        context = json.loads(message["data"])
        print(f"\n[REMEDIATION] Received context for {context.get('src_container')} "
              f"({context.get('scenario')})")

        plan = generate_remediation(context)
        print(f"  Source: {plan['source']}")
        print(f"  Severity: {plan['severity']}")
        print(f"  Fix: {plan['description']}")
        print(f"  Commands: {plan['commands']}")

        r.publish(REMEDIATION_CHANNEL, json.dumps(plan))
        print(f"  -> Published to {REMEDIATION_CHANNEL}")


if __name__ == "__main__":
    main()
