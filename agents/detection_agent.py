"""
SwarmSec Detection Agent - full pipeline
Layer 1: rule_layer.py (regex + threshold, per scenario)
Layer 2: LLM reasoning, only for cases Layer 1 can't confidently resolve
Fault tolerance: an LLM failure marks that alert as "uncertain" and
logs the error, instead of crashing the whole agent.
"""

import json
import os
import time

import redis
from anthropic import Anthropic
from dotenv import load_dotenv

from rule_layer import rule_based_pass

load_dotenv()

EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", "docker/suricata/logs/eve.json")
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
DETECTION_CHANNEL = "swarmsec:detections"
MOCK_LLM = os.environ.get("MOCK_LLM", "false").lower() == "true"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
llm_client = Anthropic()


def tail_file(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def llm_reasoning_pass(alert_json, rule_result):
    if MOCK_LLM:
        return "VERDICT: uncertain\nREASON: mock mode - no real LLM call made."

    prompt = f"""You are a network security analyst reviewing a Suricata alert.

Alert details:
- Signature: {alert_json['alert']['signature']}
- Matched scenario: {rule_result['scenario']}
- Source IP: {alert_json['src_ip']}
- Destination IP: {alert_json['dest_ip']}
- Protocol: {alert_json['proto']}

Is this likely a real attack in progress, or benign/noise?
Reply in exactly this format:
VERDICT: <malicious|benign|uncertain>
REASON: <one sentence>
"""
    try:
        response = llm_client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=150,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
    except Exception as e:
        print(f"[WARN] LLM call failed: {e}")
        return f"VERDICT: uncertain\nREASON: LLM call failed ({type(e).__name__})"


def main():
    print(f"Detection agent watching {EVE_LOG_PATH} (live) ...")
    for line in tail_file(EVE_LOG_PATH):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        rule_result = rule_based_pass(event)
        llm_verdict = None

        if rule_result["needs_llm_review"]:
            llm_verdict = llm_reasoning_pass(event, rule_result)

        decision = {
            "timestamp": event["timestamp"],
            "src_ip": event["src_ip"],
            "dest_ip": event["dest_ip"],
            "signature": event["alert"]["signature"],
            "rule_result": rule_result,
            "llm_verdict": llm_verdict,
        }

        print(json.dumps(decision, indent=2))
        r.publish(DETECTION_CHANNEL, json.dumps(decision))


if __name__ == "__main__":
    main()
