# Cartographie d'un SI et analyse des chemins d'attaque avec Neo4j

Projet NoSQL — B3 Cybersécurité (Ynov). Modélisation de l'infrastructure de l'entreprise fictive **CyberCorp** dans Neo4j et identification des chemins d'attaque depuis une machine compromise (`PC-ALICE`) vers les ressources critiques.

## Contexte

CyberCorp possède une infra interne composée de : postes utilisateurs, serveurs, comptes utilisateurs, groupes, services exposés, vulnérabilités connues et ressources sensibles.

Une alerte indique que **`PC-ALICE`** a été compromise via phishing. L'objectif est d'utiliser Neo4j pour cartographier les chemins possibles depuis cette machine vers les ressources critiques.

## Structure du projet

```
NOSQL_Project-/
├── docker-compose.yml         # Neo4j en local, data bind-mount sur ./data
├── Dockerfile                 # image auto-portée avec la data figée dedans
├── .env                       # PASSWORD Neo4j (non versionné)
├── .gitignore
└── Livrables/
    ├── Graphe Neo4j/          # modele_de_donnees.md (Livrable 1)
    ├── Requêtes Cypher/       # req_cypher.md + captures + export CSV (Livrable 2)
    ├── Chemins d'attaque/     # seed.cypher, requetes_analyse.cypher, chemins_attaque.md
    ├── Rapport d'analyse cyber/  # rapport_analyse_cyber.md (Livrable 3)
    └── Bonus/                 # import CSV + script Python (points bonus)
```

> La présentation orale (Livrable 4) est le fichier `NoSQL_project_files.pptx`.

> `data/` (base Neo4j générée) et `.env` ne sont pas versionnés. La base se
> reconstruit via l'image Docker ou le `seed.cypher` (voir ci-dessous).

## Prérequis

- Docker + Docker Compose
- Un compte Docker Hub (pour le push)

## Modèle de données

| Label           | Propriétés                                  |
| --------------- | ------------------------------------------- |
| `User`          | `name`, `role`                              |
| `Machine`       | `name`, `type`, `criticality`               |
| `Group`         | `name`                                      |
| `Service`       | `name`, `port`                              |
| `Vulnerability` | `cve`, `name`, `score`, `description`       |
| `Resource`      | `name`, `sensitivity`                       |

> [!note]
> Le graphe complet (32 nœuds, 43 relations) est peuplé par
> `Livrables/Chemins d'attaque/seed.cypher`. Les 8 types de relations
> (`USES`, `MEMBER_OF`, `ADMIN_OF`, `HAS_ACCESS_TO`, `CONNECTED_TO`, `EXPOSES`,
> `HAS_VULNERABILITY`, `HOSTS`) y sont créés en masse via `UNWIND`.

## Utilisation rapide (image déjà buildée)

```bash
docker run -d -p 7474:7474 -p 7687:7687 arustat/no_sql_cybercorp:latest
```

Interface : http://localhost:7474 — login `neo4j` / mot de passe `CyberCorp-Neo4j-2026-lol-pelican99!`

> Mot de passe volontairement public et jetable : la base est une démo sans donnée
> réelle. En production, le secret ne serait pas figé dans l'image mais injecté au
> runtime (`NEO4J_AUTH` / gestionnaire de secrets).

## Workflow de dev (local)

```bash
# 1. Démarrer Neo4j (crée ./data en local)
docker compose up -d
sleep 15

# 2. Charger le jeu de données
docker compose cp "Livrables/Chemins d'attaque/seed.cypher" neo4j:/seed.cypher
docker compose exec neo4j cypher-shell -u neo4j -p "CyberCorp-Neo4j-2026-lol-pelican99!" -f /seed.cypher

# Vérif (doit renvoyer 32)
docker compose exec neo4j cypher-shell -u neo4j -p "CyberCorp-Neo4j-2026-lol-pelican99!" "MATCH (n) RETURN count(n);"
```

## Build & push de l'image

```bash
# 1. Éteindre proprement pour flusher la data sur ./data
docker compose down

# 2. Build : COPY data /data fige la base dans l'image
docker build -t arustat/no_sql_cybercorp:1.2 .
docker build -t arustat/no_sql_cybercorp:latest .

# 3. Push
docker login
docker push arustat/no_sql_cybercorp:1.2
docker push arustat/no_sql_cybercorp:latest
```

## Équipe

Mayssa · Yasser · Enzo