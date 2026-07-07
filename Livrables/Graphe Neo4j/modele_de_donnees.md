# Livrable 1 — Graphe Neo4j

Modélisation du système d'information de **CyberCorp** en base de données orientée
graphe. Ce document décrit le modèle de données, les scripts de création et fournit
la capture du graphe complet.

---

## 1. Description du modèle de données

Le système d'information est représenté par **6 types de nœuds** et **8 types de
relations**, soit au total **32 nœuds** et **43 relations**.

### Types de nœuds

| Label | Propriétés | Rôle dans le modèle |
|---|---|---|
| `:User` | `name`, `role` | Comptes utilisateurs (RH, dev, admin, RSSI, stagiaire) |
| `:Machine` | `name`, `type`, `criticality` | Postes, serveurs, contrôleur de domaine, sauvegarde |
| `:Group` | `name` | Groupes métiers/AD (RH, DEV, ADMINS, SECURITY) |
| `:Service` | `name`, `port` | Services réseau exposés (SSH, HTTP, HTTPS, RDP, SMB, MongoDB) |
| `:Vulnerability` | `cve`, `name`, `score`, `description` | Vulnérabilités connues avec score CVSS |
| `:Resource` | `name`, `sensitivity` | Ressources sensibles (base clients, AD, sauvegardes…) |

> **Convention** : le label anglais `:Resource` avec la propriété `sensitivity` est
> utilisé partout (`seed.cypher`, requêtes d'analyse). L'orthographe française
> `:Ressource` est à proscrire pour éviter que les requêtes ne retrouvent plus les
> ressources.

### Types de relations

| Relation | Sens | Signification |
|---|---|---|
| `:USES` | `(:User)→(:Machine)` | L'utilisateur utilise ce poste |
| `:MEMBER_OF` | `(:User)→(:Group)` | Appartenance à un groupe |
| `:ADMIN_OF` | `(:User)→(:Machine)` | Droits d'administration sur la machine |
| `:HAS_ACCESS_TO` | `(:Group)→(:Machine)` | Accès accordé au groupe |
| `:CONNECTED_TO` | `(:Machine)→(:Machine)` | Connexion réseau — **porte le déplacement latéral** |
| `:EXPOSES` | `(:Machine)→(:Service)` | Service exposé (surface d'attaque) |
| `:HAS_VULNERABILITY` | `(:Machine)→(:Vulnerability)` | Vulnérabilité présente sur la machine |
| `:HOSTS` | `(:Machine)→(:Resource)` | Ressource hébergée sur la machine |

La relation `CONNECTED_TO` est centrale : c'est elle que l'on parcourt en profondeur
(`*1..6`) pour retrouver les chemins d'attaque depuis le poste compromis.

### Volumétrie

| Label | Nb | | Relation | Nb |
|---|---|---|---|---|
| Machine | 7 | | CONNECTED_TO | 10 |
| Service | 6 | | EXPOSES | 6 |
| User | 5 | | MEMBER_OF | 5 |
| Vulnerability | 5 | | HAS_VULNERABILITY | 5 |
| Resource | 5 | | HAS_ACCESS_TO | 5 |
| Group | 4 | | HOSTS | 5 |
| **Total nœuds** | **32** | | USES | 4 |
| | | | ADMIN_OF | 3 |
| | | | **Total relations** | **43** |

Le modèle respecte les contraintes du sujet : ≥ 6 types de nœuds, ≥ 6 types de
relations, ≥ 20 relations.

---

## 2. Schéma du modèle

```text
(:User)-[:USES]------------>(:Machine)
(:User)-[:MEMBER_OF]------->(:Group)
(:User)-[:ADMIN_OF]-------->(:Machine)
(:Group)-[:HAS_ACCESS_TO]-->(:Machine)
(:Machine)-[:CONNECTED_TO]->(:Machine)
(:Machine)-[:EXPOSES]------>(:Service)
(:Machine)-[:HAS_VULNERABILITY]->(:Vulnerability)
(:Machine)-[:HOSTS]-------->(:Resource)
```

Topologie réseau (`CONNECTED_TO`) :

```text
PC-ALICE ─┬─> SRV-WEB ─┬─> SRV-DB ─┬─> DC-01
          │            │           └─> NAS-BACKUP
          └─> PC-BOB ──┘            
SRV-WEB ────────────────> NAS-BACKUP
PC-ADMIN ─> DC-01 / SRV-DB / NAS-BACKUP
```

---

## 3. Scripts de création

Le graphe entier est reconstruit d'une seule commande à partir de
[`../Chemins d'attaque/seed.cypher`](../Chemins%20d'attaque/seed.cypher).

- **Création des nœuds** : bloc `CREATE (...)` unique regroupant les 32 nœuds.
- **Création des relations** : sept blocs `UNWIND [...] AS r / MATCH / CREATE`, un
  par type de relation, pour insérer les 43 relations en masse.

Extrait :

```cypher
// Nœuds
CREATE
(:Machine {name:"PC-ALICE", type:"workstation", criticality:"low"}),
(:Vulnerability {cve:"CVE-2021-44228", name:"Log4Shell", score:10,
                 description:"Exécution de code à distance via Log4j"}),
...;

// Relations réseau (déplacement latéral)
UNWIND [["PC-ALICE","SRV-WEB"],["SRV-WEB","SRV-DB"],["SRV-DB","DC-01"], ...] AS r
MATCH (a:Machine {name:r[0]}), (b:Machine {name:r[1]})
CREATE (a)-[:CONNECTED_TO]->(b);
```

Chargement :

```bash
docker compose up -d && sleep 15
docker compose cp seed.cypher neo4j:/seed.cypher
docker compose exec neo4j cypher-shell -u neo4j -p "$PASSWORD" -f /seed.cypher
```

Vérification de la volumétrie :

```cypher
MATCH (n) RETURN count(n);            // 32
MATCH ()-[r]->() RETURN count(r);     // 43
```

---

## 4. Capture du graphe complet

```cypher
MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m;
```

![Graphe complet du SI](../Chemins%20d'attaque/captures/10_graphe_complet.png)

Chaque couleur correspond à un label. On distingue le cluster réseau
(`CONNECTED_TO`) reliant les machines, les grappes utilisateurs/groupes et les
vulnérabilités/ressources rattachées aux serveurs sensibles.
