"""
Loads the SwarmSec lab network topology into Neo4j.
Nodes = containers. Edges = "CAN_REACH" - who can talk to who.
Notice there is NO web -> admin edge: that missing edge is the whole
point, it's what the blast-radius query later depends on.
"""

import os
from neo4j import GraphDatabase
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
AUTH = (
    os.environ.get("NEO4J_USER", "neo4j"),
    os.environ.get("NEO4J_PASSWORD"),
)

NODES = ["web", "api", "db", "admin"]

EDGES = [
    ("web", "api"),
    ("api", "db"),
    ("admin", "api"),
    ("admin", "db"),
]


def load_topology(tx):
    for name in NODES:
        tx.run("MERGE (:Container {name: $name})", name=name)
    for src, dst in EDGES:
        tx.run(
            """
            MATCH (a:Container {name: $src}), (b:Container {name: $dst})
            MERGE (a)-[:CAN_REACH]->(b)
            """,
            src=src, dst=dst,
        )


def main():
    if AUTH[1] is None:
        raise RuntimeError(
            "NEO4J_PASSWORD not set - add it to your .env file."
        )
    driver = GraphDatabase.driver(URI, auth=AUTH)
    with driver.session() as session:
        session.execute_write(load_topology)
    driver.close()
    print("Topology loaded into Neo4j.")


if __name__ == "__main__":
    main()
