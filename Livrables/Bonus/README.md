# Bonus — Import CSV & script Python

Deux méthodes alternatives pour peupler le graphe CyberCorp à partir de données
tabulaires (points bonus du sujet : *import CSV* + *script Python*).

## Contenu

```
Bonus/
├── csv/                    # SI exporté en CSV (1 fichier par label + relations)
│   ├── users.csv
│   ├── machines.csv
│   ├── services.csv
│   ├── vulnerabilities.csv
│   ├── groups.csv
│   ├── resources.csv
│   └── relationships.csv   # source, source_label, rel, target, target_label
├── import_csv.cypher       # import natif Neo4j via LOAD CSV
└── import_neo4j.py         # import programmatique via le driver Python
```

## Méthode 1 — LOAD CSV (natif Neo4j)

```bash
# Copier les CSV dans le dossier import/ de Neo4j
docker compose cp csv/. neo4j:/var/lib/neo4j/import/

# Exécuter le script
docker compose cp import_csv.cypher neo4j:/import_csv.cypher
docker compose exec neo4j cypher-shell -u neo4j -p "$PASSWORD" -f /import_csv.cypher
```

Résultat attendu : **32 nœuds, 43 relations**.

## Méthode 2 — Driver Python

```bash
pip install neo4j
NEO4J_PASSWORD='<mot_de_passe>' python import_neo4j.py
# → "Import terminé : 32 nœuds, 43 relations."
```

Les deux méthodes produisent exactement le même graphe que `seed.cypher`.
