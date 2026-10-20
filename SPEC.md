# OSTRAL — Spécification de la maquette (contrat commun aux lots)

Source : `OSTRAL_Dossier_Architecture_Ateliers_1-3.pdf` (M2 Cybersécurité EFREI 2026).
La maquette est une plateforme **Docker Compose** qui reproduit l'architecture cible :
9 zones (Z0–Z8), WAF/reverse proxy en DMZ, mTLS boutique→ERP, bastion + VPN + MFA,
SIEM Wazuh, supervision Uptime Kuma, sauvegardes 3-2-1-1-0 en mode pull, durcissement conteneurs.

## Règles générales (valables pour TOUS les lots)

- Racine du projet = dossier contenant ce fichier. Tous les chemins dans les fragments compose
  sont **relatifs à la racine** (ex. `./services/boutique`), car les fragments sont fusionnés
  via `COMPOSE_FILE` (voir `.env.example`) : le répertoire de projet est la racine.
- Chaque lot n'écrit **que** ses propres fichiers (voir "Propriété des fichiers"). Ne jamais modifier
  `docker-compose.yml`, `SPEC.md`, ni les fichiers d'un autre lot.
- Les réseaux sont déclarés UNE seule fois dans `docker-compose.yml` ; les fragments les référencent
  par leur nom (sans les redéclarer).
- Nom de projet compose : `ostral`.
- Variables d'environnement : secrets jamais dans les images ni dans git. Chaque lot écrit ses
  variables dans `env/<lot>.env.example` (valeurs d'exemple `CHANGEME_...`) ; l'intégrateur les
  concatène dans `.env.example`. Référencer dans compose avec `${VAR:?}` pour les secrets obligatoires.
- Durcissement obligatoire (E12, page 13 du dossier) sur chaque service :
  - image officielle, **tag de version fixé** (jamais `latest`) ;
  - `security_opt: ["no-new-privileges:true"]` ;
  - `user:` non-root quand l'image le permet ; `read_only: true` + `tmpfs` quand c'est faisable ;
  - `cap_drop: [ALL]` + `cap_add` minimal quand faisable ;
  - limites `mem_limit` / `cpus` (format compose classique, pas `deploy:`) ;
  - jamais de montage de `/var/run/docker.sock` ;
  - `restart: unless-stopped` ; `healthcheck` quand l'image le permet ;
  - journaux applicatifs écrits dans un volume nommé `logs_<service>` (pour le SIEM, E08).
- Code et commentaires : commentaires et docs **en français**, référencer les IDs du dossier
  (F01…F18, E01…E12, Z0…Z8, R1–R3, SS1–SS5) dans les commentaires pour la traçabilité.
- Docker n'est pas installé sur la machine de dev : valider statiquement (python `yaml.safe_load`,
  `node --check`, `bash -n`) et écrire du code soigné du premier coup.

## Réseaux (déclarés dans docker-compose.yml)

| Réseau          | Sous-réseau      | internal | Rôle                                                     |
|-----------------|------------------|----------|----------------------------------------------------------|
| `z0_internet`   | 10.10.0.0/24     | non      | "Internet" : WAF exposé, VPN, sonde externe              |
| `z1_cloud`      | 10.10.1.0/24     | oui      | Z1 cloud : boutique ↔ WAF (F02, F04)                     |
| `z1_data`       | 10.10.12.0/24    | oui      | base managée de la boutique (boutique seule)             |
| `z1_egress`     | 10.10.11.0/24    | oui      | F03 : boutique → PSP / transporteurs (simulés)           |
| `z2_dmz`        | 10.10.2.0/24     | oui      | Z2 DMZ                                                   |
| `z3_servers`    | 10.10.3.0/24     | oui      | Z3 serveurs internes (ERP), F05                          |
| `z4_data`       | 10.10.4.0/24     | oui      | Z4 données sensibles (PostgreSQL ERP), F06 — aucune sortie |
| `z5_identity`   | 10.10.5.0/24     | oui      | Z5 annuaire AD, F08                                      |
| `z6_admin`      | 10.10.6.0/24     | oui      | Z6 bastion Guacamole, F09/F10                            |
| `z6_data`       | 10.10.16.0/24    | oui      | base interne de Guacamole                                |
| `z7_supervision`| 10.10.7.0/24     | oui      | Z7 SIEM, supervision, sauvegarde                         |
| `z7_offsite`    | 10.10.17.0/24    | oui      | F17 : sauvegarde → stockage objet hors site (MinIO)      |
| `z8_postes`     | 10.10.8.0/24     | oui      | Z8 postes de travail, F07                                |

Principe de modélisation : un pare-feu (FW1 = côté cloud, FW2 = côté siège) est représenté par
**l'appartenance réseau** : un conteneur n'est attaché qu'aux réseaux nécessaires aux flux autorisés
de la matrice. Tout le reste est structurellement impossible (refus par défaut). Le conteneur
WireGuard applique en plus des règles iptables (FW1 pour le VPN, F09).

## Services, IP fixes et appartenance réseau

| Service (nom compose) | Zone | Réseaux : IP                                                                 | Port(s) | Lot |
|-----------------------|------|-------------------------------------------------------------------------------|---------|-----|
| `waf`                 | Z2   | z0_internet:10.10.0.10, z2_dmz:10.10.2.10, z1_cloud:10.10.1.10, z3_servers:10.10.3.10 | 8443 public (publié hôte `443:8443`), 9443 API ERP mTLS (F04) | B |
| `boutique`            | Z1   | z1_cloud:10.10.1.20, z1_data:10.10.12.20, z1_egress:10.10.11.20               | 3000    | A |
| `boutique-db`         | Z1   | z1_data:10.10.12.30                                                           | 5432    | A |
| `psp-mock`            | Z0 (logique) | z1_egress:10.10.11.30                                                 | 4000    | A |
| `odoo`                | Z3   | z3_servers:10.10.3.20, z4_data:10.10.4.10, z5_identity:10.10.5.20, z8_postes:10.10.8.20 | 8069 | C |
| `erp-db`              | Z4   | z4_data:10.10.4.20                                                            | 5432    | C |
| `samba-ad`            | Z5   | z5_identity:10.10.5.10                                                        | 53,88,389,636,445 | C |
| `wireguard`           | Z6/FW1 | z0_internet:10.10.0.20, z6_admin:10.10.6.5, z7_supervision:10.10.7.5        | 51820/udp publié hôte | D |
| `guacamole`           | Z6   | z6_admin:10.10.6.10, z6_data:10.10.16.10                                      | 8080    | D |
| `guacd`               | Z6   | z6_admin:10.10.6.11, z3_servers:10.10.3.11, z4_data:10.10.4.11, z5_identity:10.10.5.11, z7_supervision:10.10.7.11, z2_dmz:10.10.2.11 | 4822 | D |
| `guac-db`             | Z6   | z6_data:10.10.16.20                                                           | 5432    | D |
| `admin-target`        | Z3   | z3_servers:10.10.3.30                                                         | 22 (sshd, cible F10/F16) | D |
| `poste`               | Z8   | z8_postes:10.10.8.30, z5_identity:10.10.5.30                                  | -       | D |
| `wazuh-manager`       | Z7   | z7_supervision:10.10.7.20                                                     | 1514,1515,55000 | E (profil `siem`) |
| `wazuh-indexer`       | Z7   | z7_supervision:10.10.7.21                                                     | 9200    | E (profil `siem`) |
| `wazuh-dashboard`     | Z7   | z7_supervision:10.10.7.22                                                     | 5601    | E (profil `siem`) |
| `uptime-kuma`         | Z7   | z7_supervision:10.10.7.30, z0_internet:10.10.0.30, z3_servers:10.10.3.40, z6_admin:10.10.6.30 | 3001    | E |
| `backup`              | Z7   | z7_supervision:10.10.7.40, z4_data:10.10.4.40, z3_servers:10.10.3.41, z7_offsite:10.10.17.40 | - | E |
| `minio-offsite`       | Z0 (logique, 2e fournisseur) | z7_offsite:10.10.17.50                              | 9000    | E |

Le profil compose `siem` active Wazuh (gourmand : ~6 Go RAM). Sans profil, la maquette tourne en
version légère ; les journaux restent écrits dans les volumes `logs_*`.

## Volumes de journaux (partagés avec le SIEM, montés en lecture seule dans wazuh-manager)

`logs_waf` (access/error nginx + audit ModSecurity), `logs_boutique` (JSON lignes), `logs_odoo`,
`logs_guacamole` (+ volume `guac_recordings` pour les enregistrements de sessions),
`logs_admin_target` (auth.log), `logs_backup`, `logs_wireguard`.
Le manager Wazuh lit ces fichiers via `<localfile>` (équivalent maquette des agents, F11).

## Noms d'hôtes / TLS / PKI (lot B génère, les autres consomment)

- Domaine public de la boutique : `ostral.local` (servi par `waf` sur 8443, publié 443).
- API ERP interne : `erp-api.ostral.internal` → `waf:9443` (mTLS obligatoire, F04).
- Script `scripts/gen-certs.sh` (openssl, bash) génère dans `certs/` (gitignoré) :
  - `certs/ca.crt`, `certs/ca.key` — AC interne OSTRAL
  - `certs/waf-public.crt|.key` — CN/SAN `ostral.local`
  - `certs/waf-erp-api.crt|.key` — CN/SAN `erp-api.ostral.internal`, `waf`
  - `certs/boutique-client.crt|.key` — CN `boutique` (certificat client mTLS, extendedKeyUsage clientAuth)
- Montages : `waf` monte `./certs` en lecture seule sur `/etc/nginx/certs` ;
  `boutique` monte `./certs/ca.crt`, `boutique-client.crt|.key` dans `/run/certs/`.

## Contrat API boutique → ERP (lots A, B, C)

- La boutique appelle `https://waf:9443` (SNI/Host `erp-api.ostral.internal`) avec son certificat client.
- Le WAF n'autorise que `POST /jsonrpc` et `POST /xmlrpc/2/common`, `POST /xmlrpc/2/object` (routes
  d'API Odoo). Tout le reste (`/web`, `/web/login`, `/odoo`, `/website`…) → 403 (F05).
- Le WAF transmet à `http://odoo:8069` en ajoutant / exigeant l'en-tête ; l'authentification Odoo se
  fait par utilisateur technique `api-boutique` + clé API Odoo (variables `ODOO_API_USER`,
  `ODOO_API_KEY`, `ODOO_DB=ostral`).
- La boutique crée une commande via JSON-RPC `execute_kw` sur `sale.order` (partenaire créé si absent).
  Si l'ERP ne répond pas, la commande reste dans la **file d'attente** (table `outbox` de boutique-db)
  et un worker réessaie (R2, RTO ERP 8 h).

## Amendements après intégration (état final)

- Réseau `z3_api` 10.10.13.0/24 (F05) : seuls `waf` (10.10.13.10) et `odoo` (10.10.13.20). Le WAF
  n'est plus sur `z3_servers` : il ne peut joindre ni `admin-target` ni `guacd` (F14).
- `psp-mock` aussi sur `z0_internet` 10.10.0.40, publié `127.0.0.1:4000` (page de paiement hébergée).
- Le WAF publie aussi `80:8080` (redirection HTTPS uniquement). `guacd` n'écoute que sur 10.10.6.11.
- IP complémentaires : `odoo-init` 10.10.4.12, `wazuh-ism-init` 10.10.7.25, `minio-offsite-init`
  10.10.17.51, `bastion-demo` (profil `demo`) 10.10.0.21 / 10.10.6.6, publié `127.0.0.1:8080`.
- Volumes de journaux supplémentaires : `logs_samba`, `logs_erp_db`. `backup` monte `odoo_data`
  en lecture seule (filestore Odoo, hors base).
- Odoo → AD en STARTTLS 389 (l'`auth_ldap` d'Odoo 17 ne construit que des URI `ldap://`).
- Les certificats sont montés fichier par fichier (ni `ca.key` ni la clé de la boutique en DMZ).
- Amorçage : `scripts/init.sh` (secrets, PKI, clé de sauvegarde, certificats Wazuh, `up`).

## Propriété des fichiers

| Lot | Fichiers |
|-----|----------|
| Intégrateur | `SPEC.md`, `docker-compose.yml`, `.env.example`, `.gitignore`, `README.md` (racine) |
| A — Boutique (Z1) | `compose/z1-boutique.yml`, `services/boutique/**`, `services/psp-mock/**`, `env/a-boutique.env.example` |
| B — DMZ / WAF / PKI (Z2) | `compose/z2-dmz.yml`, `services/waf/**`, `scripts/gen-certs.sh`, `env/b-dmz.env.example` |
| C — ERP, base, annuaire (Z3–Z5) | `compose/z3-z5-erp-ad.yml`, `services/odoo/**`, `services/erp-db/**`, `services/samba-ad/**`, `env/c-erp.env.example` |
| D — Admin, postes (Z6, Z8) | `compose/z6-admin.yml`, `compose/z8-postes.yml`, `services/wireguard/**`, `services/guacamole/**`, `services/admin-target/**`, `services/poste/**`, `env/d-admin.env.example` |
| E — Supervision, sauvegarde (Z7) | `compose/z7-supervision.yml`, `services/wazuh/**`, `services/uptime-kuma/**`, `services/backup/**`, `services/minio-offsite/**`, `env/e-supervision.env.example` |
| F — Tests et documentation | `scripts/test-flux.sh`, `scripts/trivy-scan.sh`, `scripts/test-waf.sh`, `scripts/test-restore.sh`, `docs/**` |
