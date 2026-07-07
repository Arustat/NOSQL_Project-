#!/usr/bin/env python3
"""
Bonus — Insertion du SI CyberCorp dans Neo4j depuis les fichiers CSV.

Lit les CSV de ./csv/ et peuple la base via le driver officiel neo4j.
Alternative programmatique au chargement direct de seed.cypher.

Prérequis :
    pip install neo4j
    Neo4j démarré (docker compose up -d) — bolt sur localhost:7687

Usage :
    NEO4J_PASSWORD='monMotDePasse' python import_neo4j.py
"""

import csv
import os
from pathlib import Path

from neo4j import GraphDatabase

URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
USER = os.environ.get("NEO4J_USER", "neo4j")
PASSWORD = os.environ.get("NEO4J_PASSWORD", "neo4j")

CSV_DIR = Path(__file__).parent / "csv"


def read_csv(name):
    with open(CSV_DIR / name, encoding="utf-8") as f:
        return list(csv.DictReader(f))


def wipe(tx):
    tx.run("MATCH (n) DETACH DELETE n")


def create_nodes(tx):
    # Users
    for row in read_csv("users.csv"):
        tx.run("CREATE (:User {name:$name, role:$role})", **row)
    # Machines
    for row in read_csv("machines.csv"):
        tx.run(
            "CREATE (:Machine {name:$name, type:$type, criticality:$criticality})",
            **row,
        )
    # Services (port en int)
    for row in read_csv("services.csv"):
        tx.run(
            "CREATE (:Service {name:$name, port:$port})",
            name=row["name"],
            port=int(row["port"]),
        )
    # Vulnerabilities (score en float)
    for row in read_csv("vulnerabilities.csv"):
        tx.run(
            "CREATE (:Vulnerability {cve:$cve, name:$name, score:$score, description:$description})",
            cve=row["cve"],
            name=row["name"],
            score=float(row["score"]),
            description=row["description"],
        )
    # Groups
    for row in read_csv("groups.csv"):
        tx.run("CREATE (:Group {name:$name})", **row)
    # Resources
    for row in read_csv("resources.csv"):
        tx.run(
            "CREATE (:Resource {name:$name, sensitivity:$sensitivity})", **row
        )


# clé de correspondance (propriété) pour retrouver un nœud selon son label
KEY = {
    "User": "name",
    "Machine": "name",
    "Group": "name",
    "Service": "name",
    "Resource": "name",
    "Vulnerability": "cve",
}


def create_relationships(tx):
    for row in read_csv("relationships.csv"):
        src_label = row["source_label"]
        tgt_label = row["target_label"]
        rel = row["rel"]
        src_key = KEY[src_label]
        tgt_key = KEY[tgt_label]
        # rel type interpolé (whitelisté par nos CSV), valeurs paramétrées
        query = (
            f"MATCH (a:{src_label} {{{src_key}:$src}}), "
            f"(b:{tgt_label} {{{tgt_key}:$tgt}}) "
            f"CREATE (a)-[:{rel}]->(b)"
        )
        tx.run(query, src=row["source"], tgt=row["target"])


def counts(tx):
    n = tx.run("MATCH (n) RETURN count(n) AS c").single()["c"]
    r = tx.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]
    return n, r


def main():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    with driver.session() as session:
        session.execute_write(wipe)
        session.execute_write(create_nodes)
        session.execute_write(create_relationships)
        n, r = session.execute_read(counts)
        print(f"Import terminé : {n} nœuds, {r} relations.")
    driver.close()


if __name__ == "__main__":
    main()
