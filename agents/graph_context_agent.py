"""
SwarmSec Graph-Context Agent
Subscribes to the detection channel on Redis. For every detection,
resolves the source IP to a container name (via Docker), then queries
Neo4j: "if this container is compromised, what else can it reach?"
"""

import json
import os
import subprocess

import redis
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv()

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
DETECTION_CHANNEL = "swarmsec:detections"
CONTEXT_CHANNEL = "swarmsec:context"

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (
    os.environ.get("NEO4J_USER", "neo4j"),
    os.environ.get("NEO4J_PASSWORD"),
)
NETWORK_NAME = os.environ.get("DOCKER_NETWORK", "docker_labnet")

if NEO4J_AUTH[1] is None:
    raise RuntimeError("NEO4J_PASSWORD not set - add it to your .env file.")

driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def get_ip_to_container_map():
    result = subprocess.run(
        ["docker", "network", "inspect", NETWORK_NAME],
        capture_output=True, text=True,
    )
    data = json.loads(result.stdout)
    mapping = {}
    for _, info in data[0]["Containers"].items():
        ip = info["IPv4Address"].split("/")[0]
        mapping[ip] = info["Name"]
    return mapping


def blast_radius(tx, container_name):
    result = tx.run(
        """
        MATCH (start:Container {name: $name})-[:CAN_REACH*1..]->(reachable)
        RETURN DISTINCT reachable.name AS name
        """,
        name=container_name,
    )
    return [record["name"] for record in result]


def handle_detection(decision, ip_map):
    src_ip = decision.get("src_ip")
    container_name = ip_map.get(src_ip)

    if container_name is None:
        print(f"[graph-context] Unknown source IP {src_ip}, skipping.")
        return

    with driver.session() as session:
        reachable = session.execute_read(blast_radius, container_name)

    context = {
        "src_ip": src_ip,
        "src_container": container_name,
        "blast_radius": reachable,
        "scenario": decision.get("rule_result", {}).get("scenario"),
        "signature": decision.get("signature"),
    }
    print(json.dumps(context, indent=2))
    r.publish(CONTEXT_CHANNEL, json.dumps(context))


def main():
    print(f"Graph-context agent listening on {DETECTION_CHANNEL} ...")
    ip_map = get_ip_to_container_map()
    print("IP -> container map:", ip_map)

    pubsub = r.pubsub()
    pubsub.subscribe(DETECTION_CHANNEL)

    for message in pubsub.listen():
        if message["type"] != "message":
            continue
        decision = json.loads(message["data"])
        handle_detection(decision, ip_map)


if __name__ == "__main__":
    main()
