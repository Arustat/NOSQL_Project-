MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(:Machine {name: "DC-01"})
RETURN path;

MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path, target.name AS cible, length(path) AS profondeur
ORDER BY profondeur;

MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve AS cve, v.name AS vulnerabilite, v.score AS score, length(path) AS profondeur
ORDER BY v.score DESC;

MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(m:Machine)-[:HOSTS]->(r:Resource)
RETURN r.name AS ressource, r.sensitivity AS sensibilite, m.name AS machine_hote, length(path) AS profondeur
ORDER BY profondeur;

MATCH path = (:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(m:Machine)-[:HOSTS]->(r:Resource)
WHERE r.sensitivity = "critical" AND EXISTS { (m)-[:HAS_VULNERABILITY]->(:Vulnerability) }
RETURN path, m.name AS machine_hote, r.name AS ressource_critique
ORDER BY length(path);

MATCH path = shortestPath((:Machine {name: "PC-ALICE"})-[:CONNECTED_TO*1..6]->(:Machine {name: "DC-01"}))
RETURN path, length(path) AS nombre_de_sauts;

MATCH (start:Machine {name: "PC-ALICE"}), (target:Machine)
WHERE target.criticality = "critical"
MATCH path = shortestPath((start)-[:CONNECTED_TO*1..6]->(target))
RETURN target.name AS cible, length(path) AS sauts, path
ORDER BY sauts;

MATCH (v:Vulnerability)
WITH v,
     CASE
       WHEN v.score >= 9.0 THEN "Critique"
       WHEN v.score >= 7.0 THEN "Élevée"
       WHEN v.score >= 4.0 THEN "Moyenne"
       ELSE "Faible"
     END AS criticite
RETURN criticite, count(v) AS nombre, collect(v.name) AS vulnerabilites
ORDER BY nombre DESC;

MATCH (m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
WITH m, max(v.score) AS pire_score
RETURN m.name AS machine, pire_score,
       CASE
         WHEN pire_score >= 9.0 THEN "Critique"
         WHEN pire_score >= 7.0 THEN "Élevée"
         WHEN pire_score >= 4.0 THEN "Moyenne"
         ELSE "Faible"
       END AS niveau_de_risque
ORDER BY pire_score DESC;

// ── 10. Utilisateurs disposant de droits d'administration (ADMIN_OF) ──
MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
RETURN u.name AS utilisateur, collect(m.name) AS machines_administrees, m.criticality AS criticite
ORDER BY utilisateur;

// ── 11. Utilisateurs accédant à des machines critiques via un groupe ──
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high","critical"]
RETURN u.name AS utilisateur, g.name AS groupe, m.name AS machine, m.criticality AS criticite
ORDER BY criticite DESC, utilisateur;

// ── 12. Surface d'attaque : services exposés par machine ──
MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN m.name AS machine, collect(s.name + " (" + toString(s.port) + ")") AS services_exposes
ORDER BY machine;
