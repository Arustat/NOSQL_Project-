# Cartographie d'un SI et analyse des chemins d'attaque avec Neo4j

Projet NoSQL — B3 Cybersécurité (Ynov). Modélisation de l'infrastructure de l'entreprise fictive **CyberCorp** dans Neo4j et identification des chemins d'attaque depuis une machine compromise (`PC-ALICE`) vers les ressources critiques.

## Contexte

CyberCorp possède une infra interne composée de : postes utilisateurs, serveurs, comptes utilisateurs, groupes, services exposés, vulnérabilités connues et ressources sensibles.

Une alerte indique que **`PC-ALICE`** a été compromise via phishing. L'objectif est d'utiliser Neo4j pour cartographier les chemins possibles depuis cette machine vers les ressources critiques.

## Structure du projet

```
NOSQL_Project-/
├── docker-compose.yml     # Neo4j en local, data bind-mount sur ./data
├── Dockerfile             # image auto-portée avec la data figée dedans
├── .env                   # PASSWORD Neo4j (gitignore)
├── .gitignore
└── Livrables/
    └── Requêtes Cypher/   # req_cypher.md + captures + export CSV
```

## Prérequis

- Docker + Docker Compose
- Un compte Docker Hub (pour le push)

## Image du modèle de données

| Label           | Propriétés                                  |
| --------------- | ------------------------------------------- |
| `Ressource`     | `name`, `sensitivity`                       |
| `User`          | `name`, `role`                              |
| `Machine`       | `name`, `type`, `criticality`               |
| `Service`       | `name`, `port`                              |
| `Vulnerability` | `cve`, `name`, `score`, `description`       |
| `Group`         | `name`                                      |

> [!note]
> Les relations d'analyse (`RUNS`, `CONNECTS_TO`, `VULNERABLE_TO`, `MEMBER_OF`, `HAS_ACCESS`…) sont à ajouter en bas de `seed.cypher` ou directement en base.

## Utilisation rapide (image déjà buildée)

```bash
docker run -d -p 7474:7474 -p 7687:7687 arustat/no_sql_cybercorp:latest
```

Interface : http://localhost:7474 — login `neo4j` + mot de passe défini au build.

## Workflow de dev (local)

```bash
# 1. Démarrer Neo4j (crée ./data en local)
docker compose up -d
sleep 15

# 2. Charger le jeu de données
docker compose cp seed.cypher neo4j:/seed.cypher
docker compose exec neo4j cypher-shell -u neo4j -p "$PASSWORD" -f /seed.cypher

# Vérif
docker compose exec neo4j cypher-shell -u neo4j -p "$PASSWORD" "MATCH (n) RETURN count(n);"
```

## Build & push de l'image

```bash
# 1. Éteindre proprement pour flusher la data sur ./data
docker compose down

# 2. Build : COPY data /data fige la base dans l'image
docker build -t arustat/no_sql_cybercorp:1.0 .

# 3. Push
docker login
docker push arustat/no_sql_cybercorp:1.0
```

> [!warning]
> Le mot de passe et la base sont **baked** dans l'image. Push sur un repo **privé** si le contenu est sensible.

## Équipe

Mayssa · Yasser · Enzo 