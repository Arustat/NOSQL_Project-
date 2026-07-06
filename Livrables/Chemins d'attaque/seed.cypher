MATCH (n) DETACH DELETE n;

CREATE
(:User {name:"alice", role:"RH"}),
(:User {name:"bob", role:"Développeur"}),
(:User {name:"charlie", role:"Admin Système"}),
(:User {name:"diana", role:"RSSI"}),
(:User {name:"eve", role:"Stagiaire"}),
(:Machine {name:"PC-ALICE", type:"workstation", criticality:"low"}),
(:Machine {name:"PC-BOB", type:"workstation", criticality:"medium"}),
(:Machine {name:"PC-ADMIN", type:"workstation", criticality:"high"}),
(:Machine {name:"SRV-WEB", type:"server", criticality:"medium"}),
(:Machine {name:"SRV-DB", type:"database", criticality:"high"}),
(:Machine {name:"DC-01", type:"domain_controller", criticality:"critical"}),
(:Machine {name:"NAS-BACKUP", type:"backup_server", criticality:"critical"}),
(:Service {name:"SSH", port:22}),
(:Service {name:"HTTP", port:80}),
(:Service {name:"HTTPS", port:443}),
(:Service {name:"RDP", port:3389}),
(:Service {name:"SMB", port:445}),
(:Service {name:"MongoDB", port:27017}),
(:Vulnerability {cve:"CVE-2021-44228", name:"Log4Shell", score:10, description:"Exécution de code à distance via Log4j"}),
(:Vulnerability {cve:"CVE-2020-1472", name:"Zerologon", score:10, description:"Élévation de privilèges sur contrôleur de domaine"}),
(:Vulnerability {cve:"CVE-2019-0708", name:"BlueKeep", score:9.8, description:"Exécution de code à distance via RDP"}),
(:Vulnerability {cve:"CVE-2022-22965", name:"Spring4Shell", score:9.8, description:"Exécution de code à distance sur application Spring"}),
(:Vulnerability {cve:"CVE-2023-0001", name:"SMB Misconfiguration", score:7.5, description:"Mauvaise configuration du partage SMB"}),
(:Group {name:"RH"}),
(:Group {name:"DEV"}),
(:Group {name:"ADMINS"}),
(:Group {name:"SECURITY"}),
(:Resource {name:"Base clients", sensitivity:"high"}),
(:Resource {name:"Données RH", sensitivity:"high"}),
(:Resource {name:"Active Directory", sensitivity:"critical"}),
(:Resource {name:"Sauvegardes", sensitivity:"critical"}),
(:Resource {name:"Secrets applicatifs", sensitivity:"critical"});

UNWIND [["alice","PC-ALICE"],["bob","PC-BOB"],["charlie","PC-ADMIN"],["eve","PC-ALICE"]] AS r
MATCH (u:User {name:r[0]}), (m:Machine {name:r[1]})
CREATE (u)-[:USES]->(m);

UNWIND [["alice","RH"],["bob","DEV"],["charlie","ADMINS"],["diana","SECURITY"],["eve","DEV"]] AS r
MATCH (u:User {name:r[0]}), (g:Group {name:r[1]})
CREATE (u)-[:MEMBER_OF]->(g);

UNWIND [["charlie","DC-01"],["charlie","SRV-DB"],["charlie","NAS-BACKUP"]] AS r
MATCH (u:User {name:r[0]}), (m:Machine {name:r[1]})
CREATE (u)-[:ADMIN_OF]->(m);

UNWIND [["PC-ALICE","SRV-WEB"],["PC-ALICE","PC-BOB"],["PC-BOB","SRV-WEB"],["SRV-WEB","SRV-DB"],["SRV-WEB","NAS-BACKUP"],["SRV-DB","DC-01"],["SRV-DB","NAS-BACKUP"],["PC-ADMIN","DC-01"],["PC-ADMIN","SRV-DB"],["PC-ADMIN","NAS-BACKUP"]] AS r
MATCH (a:Machine {name:r[0]}), (b:Machine {name:r[1]})
CREATE (a)-[:CONNECTED_TO]->(b);

UNWIND [["SRV-WEB","HTTP"],["SRV-WEB","HTTPS"],["SRV-DB","MongoDB"],["DC-01","SMB"],["PC-BOB","RDP"],["PC-ADMIN","RDP"]] AS r
MATCH (m:Machine {name:r[0]}), (s:Service {name:r[1]})
CREATE (m)-[:EXPOSES]->(s);

UNWIND [["SRV-WEB","CVE-2021-44228"],["SRV-WEB","CVE-2022-22965"],["PC-BOB","CVE-2019-0708"],["DC-01","CVE-2020-1472"],["NAS-BACKUP","CVE-2023-0001"]] AS r
MATCH (m:Machine {name:r[0]}), (v:Vulnerability {cve:r[1]})
CREATE (m)-[:HAS_VULNERABILITY]->(v);

UNWIND [["RH","SRV-WEB"],["DEV","SRV-DB"],["ADMINS","DC-01"],["ADMINS","NAS-BACKUP"],["SECURITY","SRV-DB"]] AS r
MATCH (g:Group {name:r[0]}), (m:Machine {name:r[1]})
CREATE (g)-[:HAS_ACCESS_TO]->(m);

UNWIND [["SRV-DB","Base clients"],["SRV-DB","Secrets applicatifs"],["SRV-DB","Données RH"],["DC-01","Active Directory"],["NAS-BACKUP","Sauvegardes"]] AS r
MATCH (m:Machine {name:r[0]}), (res:Resource {name:r[1]})
CREATE (m)-[:HOSTS]->(res);
