import re
import time
from collections import defaultdict, deque

# --- Regex patterns per scenario ---
# Matched against Suricata's alert.signature text to classify which
# attack scenario (if any) this alert corresponds to.
SCENARIO_PATTERNS = {
    "port_scan_lateral_movement": re.compile(r"(?i)scan|nmap|syn|brute.?force"),
    "api_abuse": re.compile(r"(?i)http|sql injection|xss|web application"),
    "routing_spoofing": re.compile(r"(?i)arp|spoof|routing|icmp redirect"),
    "reverse_shell": re.compile(r"(?i)shell|trojan|backdoor|c2|command.?and.?control"),
}

# --- Per-scenario thresholds ---
# window_seconds: how far back to look
# min_count: how many matching alerts from the same source before
#            we're confident this is a real attack, not noise
# Some scenarios (routing spoofing, reverse shell) are treated as
# critical on a SINGLE occurrence - waiting for a "pattern" there
# would be too slow to be useful.
SCENARIO_THRESHOLDS = {
    "port_scan_lateral_movement": {"window_seconds": 5,  "min_count": 5},
    "api_abuse":                  {"window_seconds": 60, "min_count": 20},
    "routing_spoofing":           {"window_seconds": 1,  "min_count": 1},
    "reverse_shell":               {"window_seconds": 1,  "min_count": 1},
}

# Tracks recent match timestamps per (scenario, source_ip) pair
_recent_matches = defaultdict(lambda: deque(maxlen=200))


def classify_scenario(signature_text: str):
    """Returns the scenario name this alert's signature matches, or None
    if it doesn't match any of our 4 known patterns."""
    for scenario, pattern in SCENARIO_PATTERNS.items():
        if pattern.search(signature_text):
            return scenario
    return None


def rule_based_pass(alert_json: dict) -> dict:
    """
    Layer 1 - deterministic, no LLM call.
    Returns a decision dict: which scenario matched, whether the
    threshold for that scenario was met, and whether this needs
    escalation to the LLM reasoning pass (Layer 2).
    """
    signature = alert_json["alert"]["signature"]
    src_ip = alert_json["src_ip"]
    now = time.time()

    scenario = classify_scenario(signature)

    if scenario is None:
        # Doesn't match any known scenario pattern - deterministic layer
        # can't confidently judge this, so it must go to the LLM.
        return {
            "scenario": None,
            "threshold_met": False,
            "needs_llm_review": True,
        }

    key = (scenario, src_ip)
    _recent_matches[key].append(now)

    window = SCENARIO_THRESHOLDS[scenario]["window_seconds"]
    min_count = SCENARIO_THRESHOLDS[scenario]["min_count"]
    recent_count = sum(1 for t in _recent_matches[key] if now - t <= window)

    threshold_met = recent_count >= min_count

    return {
        "scenario": scenario,
        "recent_count": recent_count,
        "threshold_met": threshold_met,
        # If the threshold is met, layer 1 is confident - no LLM needed.
        # If it matched a scenario but hasn't hit the threshold yet,
        # it's borderline - let the LLM weigh in.
        "needs_llm_review": not threshold_met,
    }
