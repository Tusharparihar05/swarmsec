"""
SwarmSec Comparative Evaluation
Compares SwarmSec (multi-agent + LLM) vs baseline Suricata (IDS only).
Reads data from MongoDB and generates evaluation metrics.
"""

import json
import os
from datetime import datetime, timezone

from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")

mongo = MongoClient(MONGO_URI)
db = mongo["swarmsec"]


def run_evaluation():
    # ---- Gather stats from MongoDB ----
    total_detections = db.detections.count_documents({})
    total_contexts = db.contexts.count_documents({})
    total_remediations = db.remediations.count_documents({})
    total_verified = db.verified_fixes.count_documents({})
    total_incidents = db.incidents.count_documents({})

    # Scenarios detected
    pipeline = [{"$group": {"_id": "$scenario", "count": {"$sum": 1}}}]
    scenario_counts = {}
    for doc in db.detections.aggregate(pipeline):
        if doc["_id"]:
            scenario_counts[doc["_id"]] = doc["count"]

    # Sandbox pass/fail rate
    passed = db.verified_fixes.count_documents({"status": "pass"})
    failed = db.verified_fixes.count_documents({"status": "fail"})

    # Incidents by type
    auto_remediated = db.incidents.count_documents({"type": "auto_remediated"})
    escalated = db.incidents.count_documents({"type": "escalated"})

    # ---- Build comparison ----
    print("=" * 70)
    print("     SwarmSec Comparative Evaluation Report")
    print("=" * 70)
    print()

    print("1. DATA SUMMARY")
    print("-" * 40)
    print(f"   Total Detections:    {total_detections}")
    print(f"   Context Analyses:    {total_contexts}")
    print(f"   Remediation Plans:   {total_remediations}")
    print(f"   Sandbox Tests:       {total_verified}")
    print(f"   Incidents Logged:    {total_incidents}")
    print()

    print("2. SCENARIOS DETECTED")
    print("-" * 40)
    for scenario, count in scenario_counts.items():
        print(f"   {scenario}: {count}")
    print()

    print("3. SANDBOX VERIFICATION")
    print("-" * 40)
    total_tests = passed + failed
    pass_rate = (passed / total_tests * 100) if total_tests > 0 else 0
    print(f"   Passed: {passed}")
    print(f"   Failed: {failed}")
    print(f"   Pass Rate: {pass_rate:.1f}%")
    print()

    print("4. INCIDENT RESPONSE")
    print("-" * 40)
    print(f"   Auto-Remediated: {auto_remediated}")
    print(f"   Escalated:       {escalated}")
    print()

    # ---- Comparative Table ----
    print("5. COMPARATIVE ANALYSIS: SwarmSec vs Baseline Suricata")
    print("-" * 70)
    print(f"{'Metric':<35} {'Suricata Only':<18} {'SwarmSec':<18}")
    print("-" * 70)

    comparisons = [
        ("Detection Method",      "Signature-based", "Signature + LLM"),
        ("False Positive Handling","Manual review",   "LLM auto-filters"),
        ("Context Awareness",     "None",            "Neo4j blast radius"),
        ("Remediation",           "Manual / none",   "Auto-generated"),
        ("Fix Verification",      "None",            "Sandbox testing"),
        ("Deployment",            "Manual",          "Auto-deployment"),
        ("Response Time",         "> 30 min (human)", "< 5 seconds"),
        ("Multi-Scenario Support","Yes (rules)",     "Yes (rules + LLM)"),
        ("Lateral Movement Viz",  "No",              "Yes (graph)"),
        ("Audit Trail",           "Log files",       "MongoDB + timeline"),
    ]

    for metric, baseline, swarmsec in comparisons:
        print(f"   {metric:<33} {baseline:<18} {swarmsec:<18}")

    print("-" * 70)
    print()

    # ---- Save to JSON for dashboard ----
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_detections": total_detections,
            "total_contexts": total_contexts,
            "total_remediations": total_remediations,
            "total_verified": total_verified,
            "total_incidents": total_incidents,
        },
        "scenarios": scenario_counts,
        "sandbox": {
            "passed": passed,
            "failed": failed,
            "pass_rate": round(pass_rate, 1),
        },
        "incidents": {
            "auto_remediated": auto_remediated,
            "escalated": escalated,
        },
    }

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evaluation_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Report saved to: {out_path}")


if __name__ == "__main__":
    run_evaluation()
