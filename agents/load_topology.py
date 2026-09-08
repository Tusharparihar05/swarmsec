"""
Loads the SwarmSec lab network topology into Neo4j.
Nodes = containers. Edges = "CAN_REACH" - who can talk to who.
Notice there is NO web -> admin edge: that missing edge is the whole
point, it's what the blast-radius query later depends on.
"""

from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
AUTH = ("neo4j", "swarmsecpass")

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
    driver = GraphDatabase.driver(URI, auth=AUTH)
    with driver.session() as session:
        session.execute_write(load_topology)
    driver.close()
    print("Topology loaded into Neo4j.")


if __name__ == "__main__":
    main()
