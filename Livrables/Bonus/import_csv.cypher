// ─────────────────────────────────────────────────────────────────────────────
// Bonus — Import du SI CyberCorp depuis des fichiers CSV (LOAD CSV natif Neo4j)
//
// Prérequis : copier les CSV dans le dossier import/ de Neo4j, par ex.
//   docker compose cp csv/. neo4j:/var/lib/neo4j/import/
// puis exécuter ce script (cypher-shell -f import_csv.cypher).
// ─────────────────────────────────────────────────────────────────────────────

MATCH (n) DETACH DELETE n;

// ── Nœuds ──
LOAD CSV WITH HEADERS FROM 'file:///users.csv' AS row
CREATE (:User {name: row.name, role: row.role});

LOAD CSV WITH HEADERS FROM 'file:///machines.csv' AS row
CREATE (:Machine {name: row.name, type: row.type, criticality: row.criticality});

LOAD CSV WITH HEADERS FROM 'file:///services.csv' AS row
CREATE (:Service {name: row.name, port: toInteger(row.port)});

LOAD CSV WITH HEADERS FROM 'file:///vulnerabilities.csv' AS row
CREATE (:Vulnerability {cve: row.cve, name: row.name,
                        score: toFloat(row.score), description: row.description});

LOAD CSV WITH HEADERS FROM 'file:///groups.csv' AS row
CREATE (:Group {name: row.name});

LOAD CSV WITH HEADERS FROM 'file:///resources.csv' AS row
CREATE (:Resource {name: row.name, sensitivity: row.sensitivity});

// ── Relations ──
// Le type de relation ne pouvant pas être paramétré directement en Cypher pur,
// on filtre par type de relation via des passes successives sur relationships.csv.

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'USES'
MATCH (a:User {name: row.source}), (b:Machine {name: row.target})
CREATE (a)-[:USES]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'MEMBER_OF'
MATCH (a:User {name: row.source}), (b:Group {name: row.target})
CREATE (a)-[:MEMBER_OF]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'ADMIN_OF'
MATCH (a:User {name: row.source}), (b:Machine {name: row.target})
CREATE (a)-[:ADMIN_OF]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'CONNECTED_TO'
MATCH (a:Machine {name: row.source}), (b:Machine {name: row.target})
CREATE (a)-[:CONNECTED_TO]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'EXPOSES'
MATCH (a:Machine {name: row.source}), (b:Service {name: row.target})
CREATE (a)-[:EXPOSES]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'HAS_VULNERABILITY'
MATCH (a:Machine {name: row.source}), (b:Vulnerability {cve: row.target})
CREATE (a)-[:HAS_VULNERABILITY]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'HAS_ACCESS_TO'
MATCH (a:Group {name: row.source}), (b:Machine {name: row.target})
CREATE (a)-[:HAS_ACCESS_TO]->(b);

LOAD CSV WITH HEADERS FROM 'file:///relationships.csv' AS row
WITH row WHERE row.rel = 'HOSTS'
MATCH (a:Machine {name: row.source}), (b:Resource {name: row.target})
CREATE (a)-[:HOSTS]->(b);

// ── Vérification ──
MATCH (n) RETURN count(n) AS noeuds;
MATCH ()-[r]->() RETURN count(r) AS relations;
