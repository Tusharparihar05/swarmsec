"""
SwarmSec Detection Agent - full pipeline
Layer 1: rule_layer.py (regex + threshold, per scenario)
Layer 2: LLM reasoning via Groq (FREE - Llama model, ultra-fast)
         only for cases Layer 1 can't confidently resolve
Fault tolerance: an LLM failure marks that alert as "uncertain" and
logs the error, instead of crashing the whole agent.
"""

import json
import os
import time

import redis
from groq import Groq
from dotenv import load_dotenv

from rule_layer import rule_based_pass

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

# Resolve paths relative to THIS file's location, not where you run from
_AGENTS_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_EVE = os.path.join(_AGENTS_DIR, "..", "docker", "suricata", "logs", "eve.json")

EVE_LOG_PATH = os.environ.get("EVE_LOG_PATH", _DEFAULT_EVE)
REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
DETECTION_CHANNEL = "swarmsec:detections"
MOCK_LLM = os.environ.get("MOCK_LLM", "false").lower() == "true"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# --- Groq LLM client setup (FREE - https://console.groq.com) ---
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
groq_client = None
if GROQ_API_KEY and not MOCK_LLM:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("[INFO] Groq LLM client initialised successfully.")
    except Exception as e:
        print(f"[WARN] Could not initialise Groq client: {e}")
        print("[WARN] LLM reasoning will return 'uncertain' for all alerts.")
elif not MOCK_LLM:
    print("[WARN] GROQ_API_KEY not set in .env — get a FREE key at https://console.groq.com/keys")
    print("[WARN] LLM reasoning disabled. Set MOCK_LLM=true to suppress this warning.")


def tail_file(path):
    """Continuously reads new lines appended to a file (like tail -f)."""
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def llm_reasoning_pass(alert_json, rule_result):
    """
    Layer 2 - LLM-based reasoning using Groq (Llama 3.3-70B, free tier).
    Called only when Layer 1 (rule-based) is not confident enough.
    Returns a verdict string.
    """
    if MOCK_LLM:
        return "VERDICT: uncertain\nREASON: mock mode - no real LLM call made."

    if groq_client is None:
        return "VERDICT: uncertain\nREASON: LLM client not available (no API key)."

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
        response = groq_client.chat.completions.create(
            model="qwen/qwen3.8-27b",
            max_tokens=150,
            temperature=0.3,
            messages=[
                {
                    "role": "system",
                    "content": "You are an expert network security analyst. Be concise.",
                },
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[WARN] Groq LLM call failed: {e}")
        return f"VERDICT: uncertain\nREASON: LLM call failed ({type(e).__name__})"


def main():
    # Suricata built-in signatures that are always noise — skip them entirely
    SKIP_SIGNATURES = {
        "SURICATA TCPv4 invalid checksum",
        "SURICATA TCPv6 invalid checksum",
        "SURICATA STREAM Packet with invalid timestamp",
        "SURICATA STREAM ESTABLISHED packet out of window",
        "SURICATA STREAM CLOSEWAIT FIN out of window",
        "SURICATA STREAM Last ACK with wrong seq",
        "SURICATA STREAM SHUTDOWN RST invalid ack",
        "SURICATA STREAM Packet with broken ack",
        "SURICATA STREAM ESTABLISHED retransmission packet before base seq",
        "SURICATA STREAM ESTABLISHED SYN resend",
        "SURICATA TLS invalid record type",
        "SURICATA HTTP unable to match response to request",
    }

    print(f"Detection agent watching {EVE_LOG_PATH} (live) ...")
    for line in tail_file(EVE_LOG_PATH):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("event_type") != "alert":
            continue

        sig = event.get("alert", {}).get("signature", "")

        # Skip noisy Suricata built-in protocol alerts (not real attacks)
        if sig in SKIP_SIGNATURES or sig.startswith("SURICATA STREAM"):
            continue

        rule_result = rule_based_pass(event)
        llm_verdict = None

        if rule_result["needs_llm_review"]:
            llm_verdict = llm_reasoning_pass(event, rule_result)

        decision = {
            "timestamp": event["timestamp"],
            "src_ip": event["src_ip"],
            "dest_ip": event["dest_ip"],
            "signature": sig,
            "rule_result": rule_result,
            "llm_verdict": llm_verdict,
        }

        print(json.dumps(decision, indent=2))
        r.publish(DETECTION_CHANNEL, json.dumps(decision))


if __name__ == "__main__":
    main()
