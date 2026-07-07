# Rapport d'analyse cyber — CyberCorp

**Projet NoSQL · B3 Cybersécurité — Ynov 2026**
**Équipe :** Mayssa · Yasser · Enzo
**Outil :** Neo4j (Community 5.26) · Cypher

---

## 1. Présentation du système d'information modélisé

L'entreprise fictive **CyberCorp** dispose d'une infrastructure interne modélisée
dans une base de données orientée graphe Neo4j. Le graphe compte **32 nœuds** et
**43 relations**, répartis sur **6 types de nœuds** et **8 types de relations**.

| Élément | Détail |
|---|---|
| Utilisateurs | alice (RH), bob (Dev), charlie (Admin), diana (RSSI), eve (Stagiaire) |
| Machines | PC-ALICE, PC-BOB, PC-ADMIN, SRV-WEB, SRV-DB, DC-01, NAS-BACKUP |
| Groupes | RH, DEV, ADMINS, SECURITY |
| Services | SSH, HTTP, HTTPS, RDP, SMB, MongoDB |
| Vulnérabilités | Log4Shell, Zerologon, BlueKeep, Spring4Shell, SMB Misconfig |
| Ressources | Base clients, Données RH, Active Directory, Sauvegardes, Secrets applicatifs |

Le modèle de données complet (labels, propriétés, relations) est décrit dans le
livrable *Graphe Neo4j* ([`../Graphe Neo4j/modele_de_donnees.md`](../Graphe%20Neo4j/modele_de_donnees.md)).

La relation clé pour l'analyse est `CONNECTED_TO` entre machines : elle matérialise
les connexions réseau, donc les chemins qu'un attaquant peut emprunter pour se
déplacer latéralement.

---

## 2. Schéma / capture du graphe

Vue d'ensemble du système d'information (nœuds colorés par label, relations
orientées) :

```cypher
MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m;
```

![Graphe complet du SI](../Chemins%20d'attaque/captures/10_graphe_complet.png)

Topologie réseau simplifiée :

```text
PC-ALICE ─┬─> SRV-WEB ─┬─> SRV-DB ─┬─> DC-01        (Active Directory)
          │            │           └─> NAS-BACKUP   (Sauvegardes)
          └─> PC-BOB ──┘
SRV-WEB ────────────────> NAS-BACKUP
```

---

## 3. Hypothèse d'attaque

Le poste **PC-ALICE** (criticité *low*, utilisé par alice, service RH) est
**compromis à la suite d'une attaque par phishing**. On se place du point de vue
d'un attaquant ayant obtenu un accès initial sur ce poste, et on cherche à
déterminer :

> Depuis PC-ALICE, quels chemins mènent aux ressources critiques de CyberCorp, et
> quelles faiblesses (vulnérabilités, services, droits) les rendent exploitables ?

L'analyse suit la logique d'un déplacement latéral : parcours des liens
`CONNECTED_TO` (profondeur 1 à 6), croisé avec les vulnérabilités, les ressources
hébergées et les droits d'accès.

---

## 4. Chemins d'attaque identifiés

### 4.1 Accès au contrôleur de domaine

```cypher
MATCH path = (:Machine {name:"PC-ALICE"})-[:CONNECTED_TO*1..6]->(:Machine {name:"DC-01"})
RETURN path;
```

![Chemins PC-ALICE vers DC-01](../Chemins%20d'attaque/captures/1_chemins_pc-alice_dc01.png)

Plusieurs chemins relient PC-ALICE à DC-01, tous transitant par **SRV-WEB puis
SRV-DB**. Le plus court fait **3 sauts** : `PC-ALICE → SRV-WEB → SRV-DB → DC-01`.

### 4.2 Toutes les cibles critiques sont atteignables

```cypher
MATCH path = (:Machine {name:"PC-ALICE"})-[:CONNECTED_TO*1..6]->(target:Machine)
WHERE target.criticality = "critical"
RETURN path, target.name AS cible, length(path) AS profondeur
ORDER BY profondeur;
```

![Chemins vers les cibles critiques](../Chemins%20d'attaque/captures/2_chemins_cibles_critiques.png)

Les **deux** machines de criticité *critical* sont joignables :
**NAS-BACKUP à 2 sauts** et **DC-01 à 3 sauts**.

### 4.3 Le scénario le plus dangereux

Ressource critique hébergée sur une machine elle-même vulnérable :

```cypher
MATCH path = (:Machine {name:"PC-ALICE"})-[:CONNECTED_TO*1..6]->(m:Machine)-[:HOSTS]->(r:Resource)
WHERE r.sensitivity = "critical" AND EXISTS { (m)-[:HAS_VULNERABILITY]->(:Vulnerability) }
RETURN path, m.name AS machine_hote, r.name AS ressource_critique
ORDER BY length(path);
```

![Ressources critiques sur machine vulnérable](../Chemins%20d'attaque/captures/5_chemins_ressources_critiques.png)

**Active Directory** (DC-01) et **Sauvegardes** (NAS-BACKUP), toutes deux
critiques, sont hébergées sur des machines vulnérables et accessibles depuis le
poste compromis. C'est le cumul le plus à risque : accessibilité + criticité +
vulnérabilité.

---

## 5. Machines vulnérables

```cypher
MATCH (:Machine {name:"PC-ALICE"})-[:CONNECTED_TO*1..6]->(m:Machine)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN m.name AS machine, v.cve, v.name, v.score ORDER BY v.score DESC;
```

![Machines vulnérables sur le chemin](../Chemins%20d'attaque/captures/3_machines_vulnerables_chemin.png)

| Machine | CVE | Vulnérabilité | CVSS | Niveau |
|---|---|---|---:|---|
| SRV-WEB | CVE-2021-44228 | Log4Shell | 10 | Critique |
| DC-01 | CVE-2020-1472 | Zerologon | 10 | Critique |
| SRV-WEB | CVE-2022-22965 | Spring4Shell | 9.8 | Critique |
| PC-BOB | CVE-2019-0708 | BlueKeep | 9.8 | Critique |
| NAS-BACKUP | CVE-2023-0001 | SMB Misconfiguration | 7.5 | Élevée |

Classification : **4 vulnérabilités critiques** (CVSS ≥ 9) et **1 élevée**.
`SRV-WEB` cumule deux CVE critiques : c'est le nœud pivot des chemins d'attaque.

---

## 6. Services exposés

```cypher
MATCH (m:Machine)-[:EXPOSES]->(s:Service)
RETURN m.name AS machine, s.name AS service, s.port AS port ORDER BY machine;
```

![Ressources exposées via les chemins](../Chemins%20d'attaque/captures/4_ressources_exposees_chemin.png)

| Machine | Services exposés |
|---|---|
| SRV-WEB | HTTP (80), HTTPS (443) |
| SRV-DB | MongoDB (27017) |
| DC-01 | SMB (445) |
| PC-BOB / PC-ADMIN | RDP (3389) |

Chaque service exposé élargit la surface d'attaque : HTTP/HTTPS sur SRV-WEB sont la
porte d'entrée vers Log4Shell/Spring4Shell, SMB sur DC-01 se conjugue à Zerologon,
RDP sur PC-BOB expose BlueKeep, et MongoDB (27017) sur SRV-DB ouvre un accès direct
aux données si mal authentifié.

---

## 7. Utilisateurs et groupes à risque

```cypher
// Droits d'administration
MATCH (u:User)-[:ADMIN_OF]->(m:Machine)
RETURN u.name, collect(m.name) AS machines, m.criticality;

// Accès aux machines critiques via un groupe
MATCH (u:User)-[:MEMBER_OF]->(g:Group)-[:HAS_ACCESS_TO]->(m:Machine)
WHERE m.criticality IN ["high","critical"]
RETURN u.name, g.name, m.name, m.criticality;
```

- **charlie** est `ADMIN_OF` de DC-01, SRV-DB et NAS-BACKUP. La compromission de ce
  seul compte donne un contrôle total sur les trois machines les plus sensibles :
  c'est le compte le plus critique du SI.
- Le groupe **DEV** dispose d'un `HAS_ACCESS_TO` vers **SRV-DB** (base clients,
  secrets, données RH). **bob** et **eve** en sont membres — **eve étant stagiaire**,
  cet accès à une machine *high* est disproportionné.
- Le groupe **ADMINS** a accès à DC-01 et NAS-BACKUP ; toute compromission d'un
  compte admin mène à une compromission complète.
- **eve** utilise aussi **PC-ALICE** (le poste compromis) : un compte à faible
  privilège mais rattaché au groupe DEV, ce qui crée un pont RH → DEV → SRV-DB.

---

## 8. Recommandations de sécurité

1. **Segmenter le réseau.** Supprimer les liens `CONNECTED_TO` directs entre postes
   utilisateurs et serveurs critiques. Isoler SRV-DB, DC-01 et NAS-BACKUP dans des
   VLAN distincts avec filtrage strict.
2. **Casser le pivot SRV-WEB.** Patcher **Log4Shell** (CVE-2021-44228) et
   **Spring4Shell** (CVE-2022-22965) en priorité : une seule coupure sur SRV-WEB
   brise la quasi-totalité des chemins cartographiés.
3. **Patcher en urgence** **Zerologon** (DC-01) et **BlueKeep** (PC-BOB), qui
   permettent une escalade directe vers le domaine.
4. **Durcir SMB** sur NAS-BACKUP (signature SMB, désactivation SMBv1, ACL de
   partage) et désactiver les services non nécessaires.
5. **Appliquer le moindre privilège.** Retirer l'accès du groupe DEV — et surtout du
   stagiaire eve — à SRV-DB. Restreindre les droits admin de charlie au strict
   nécessaire et déployer une administration à comptes séparés (tiering AD).
6. **Renforcer l'authentification** des comptes administrateurs (MFA, PAW/bastion) et
   **surveiller** les connexions latérales anormales (SIEM sur les flux
   PC → serveurs).

---

## 9. Conclusion

La modélisation graphe démontre qu'à partir d'**un seul poste compromis à faible
criticité (PC-ALICE)**, l'intégralité des ressources critiques de CyberCorp est
atteignable en **2 à 3 sauts réseau**. Le facteur aggravant n'est pas une
vulnérabilité isolée mais leur **enchaînement le long des chemins** : accessibilité
réseau, services exposés, CVE critiques et droits trop permissifs se combinent.

Neo4j apporte une valeur défensive concrète : là où un inventaire tabulaire liste
des machines et des CVE séparément, le graphe **révèle les chemins** et permet de
prioriser la remédiation par impact — ici, corriger SRV-WEB et segmenter le réseau
offrent le meilleur retour sur effort pour réduire la surface d'attaque.
