# OSTRAL — Matrice de traçabilité

Ce document relie chaque élément du dossier d'architecture (exigences E01–E12, flux F01–F18,
risques R1–R3, scénarios SS1–SS5) à sa **mise en œuvre dans la maquette** et au **test** qui le
démontre. Les scripts de test sont dans `scripts/`, le scénario de soutenance dans
[demo.md](demo.md).

Légende de couverture : ✅ couvert et testé — 🟡 partiel / simulé — ❌ non reproduit (écart assumé,
voir [architecture.md §6](architecture.md#6-écarts-entre-la-maquette-et-larchitecture-cible)).

## 1. Exigences E01–E12

| ID | Exigence (dossier) | Mise en œuvre dans la maquette | Test / preuve | Couv. |
|---|---|---|---|---|
| E01 | Boutique disponible à 99,5 %, absorbe les pics | WAF en frontal ; `limit_req`/`limit_conn` nginx ; `healthcheck` + `restart: unless-stopped` ; limites CPU/mémoire ; sonde Uptime Kuma | `test-waf.sh` (200 sur trafic sain, 429 en rafale) ; tableau de bord Uptime Kuma | 🟡 (pas d'élasticité réelle) |
| E02 | Aucune donnée de carte traitée par OSTRAL (SAQ A) | Paiement redirigé vers `psp-mock` (page de paiement hébergée par le PSP, `127.0.0.1:4000`) ; la boutique ne reçoit qu'une notification signée HMAC, directement par `z1_egress` ; `/payment/notify` est refusé (403) depuis Internet par le WAF | Démo étape 3 ; `test-waf.sh` §2 bis (`/payment/notify` → 403) ; absence de champ carte dans la boutique et dans `boutique-db` | ✅ |
| E03 | Chiffrement des flux exposés et des données personnelles | TLS 1.2/1.3 uniquement sur le WAF (AC interne `certs/`), HSTS ; mTLS F04 (seul le CN `boutique` est accepté) ; LDAP avec STARTTLS (389) entre Odoo et l'AD ; WireGuard F09 ; chiffrement des sauvegardes avant envoi (F17) | `test-waf.sh` §4 (TLS 1.0/1.1 refusés, SNI inconnu refusé) et §2 bis (HTTP 80 → 301) ; `test-flux.sh` F04 avec/sans certificat | ✅ |
| E04 | Protection des comptes clients contre le piratage en masse | ModSecurity + OWASP CRS ; limitation de débit sur `POST /login` et `POST /register` (10/min, rafale 5 → 429) ; jeton CSRF et session côté boutique ; alerte Wazuh sur les rafales de 429 | `test-waf.sh` §2 (403) et §5 (429) ; démo étape 2 | ✅ |
| E05 | Le site exposé n'atteint jamais directement le SI interne | Boutique attachée seulement à `z1_*` ; seul chemin F04 → F05 via le WAF, en mTLS, limité à `/jsonrpc` et `/xmlrpc/2/*`, puis réseau dédié `z3_api` (WAF + Odoo seuls) ; `erp-db` sur `z4_data` sans sortie | `test-flux.sh` : NEG boutique → odoo / erp-db / samba-ad, F05 `/web` → 403, F14 | ✅ |
| E06 | Administration uniquement par bastion, MFA, sessions enregistrées | WireGuard (règles iptables par pair) → Guacamole 1.6.0 (TOTP, `guacadmin` désactivé) → `guacd` → SSH ; enregistrements dans le volume `guac_recordings` ; aucun SSH depuis Z8 | `test-flux.sh` F09, F10, F15, NEG wireguard → SSH ; démo étapes 5 et 6 | ✅ |
| E07 | Accès prestataires nominatifs et limités dans le temps | Comptes Guacamole nominatifs (`admin1`, `admin2`, `agence-web`) ; `agence-web` limité par une fenêtre horaire (08:00–19:00) et une date d'expiration ; pair WireGuard `agenceweb` restreint au seul bastion | Démo étape 5 (compte `agence-web` expiré → refus) | 🟡 (procédure) |
| E08 | Journaux centralisés 12 mois, alertes | Wazuh 4.14.4 : volumes `logs_*` lus en lecture seule par `wazuh-manager` (profil `siem`) ; règles d'alerte (403/429 WAF, échecs SSH, sessions bastion) ; comptes SIEM locaux ; politique ISM 90 jours (`wazuh-ism-init`) | `test-flux.sh` F11 (montages RO) ; démo étape 2 (alerte) | 🟡 (rétention non démontrable) |
| E09 | Sauvegardes isolées du reste du SI | Serveur `backup` en Z7, mode *pull* (F16) avec compte lecture seule ; copie chiffrée vers `minio-offsite` avec verrouillage d'objets 30 jours (F17) ; empreintes vérifiées | `test-restore.sh` ; `test-flux.sh` F16, F17 | ✅ |
| E10 | RTO/RPO par service, testés au moins une fois par an | Calendrier de tests rejoué dans la maquette (mensuel, trimestriel, semestriel, annuel) | `test-restore.sh` (mensuel) ; `test-restore.sh --erp-down` (R2, RTO ERP) ; [exploitation.md §6](exploitation.md) | 🟡 |
| E11 | Indisponibilité détectée en moins de 5 min | Uptime Kuma : sonde externe sur `z0_internet` (10.10.0.10:8443) toutes les 60 s, alerte après 2 échecs | `test-flux.sh` F18 ; démo étape 4 (`docker compose stop boutique` → alerte < 3 min) | ✅ |
| E12 | Conteneurs scannés et durcis avant production | Tags fixés, `no-new-privileges`, non-root, `read_only`, `cap_drop`, limites, pas de `docker.sock`, secrets dans `.env` | `trivy-scan.sh` (bloque sur CRITICAL, contrôle du compose) | ✅ |

## 2. Flux F01–F18

| ID | Source → destination (dossier) | Statut | Mécanisme dans la maquette | Test (`scripts/`) |
|---|---|---|---|---|
| F01 | Internet → WAF, TCP 443 | AUTORISÉ | Port hôte `443:8443` publié sur `waf` ; TLS terminé au WAF | `test-flux.sh` F01 ; `test-waf.sh` |
| F02 | WAF → boutique, TCP 3000 | AUTORISÉ | Réseau `z1_cloud` partagé par `waf` et `boutique` uniquement | `test-flux.sh` F02 |
| F03 | Boutique → PSP / transporteurs, TCP 443 | AUTORISÉ | Réseau `z1_egress` (boutique ↔ `psp-mock` port 4000), clé API ; le PSP, logiquement en Z0, est aussi sur `z0_internet` (10.10.0.40) et publié `127.0.0.1:4000` pour le navigateur du client | `test-flux.sh` F03 (depuis la boutique et depuis l'hôte), NEG boutique → Internet |
| F04 | Boutique → API ERP sur le reverse proxy (mTLS) | AUTORISÉ | `waf:9443`, `ssl_verify_client on`, AC interne, certificat `boutique-client` | `test-flux.sh` F04 avec et sans certificat |
| F05 | Reverse proxy → Odoo, TCP 8069, routes d'API | AUTORISÉ | Réseau dédié `z3_api` (waf 10.10.13.10 → odoo 10.10.13.20) ; `location` nginx limitées à `POST /jsonrpc`, `/xmlrpc/2/common`, `/xmlrpc/2/object` ; le reste → 403 | `test-flux.sh` F05 (`/web/login`, `/odoo` → 403 ; waf → odoo 10.10.13.20:8069 ; NEG waf → odoo sur `z3_servers`) |
| F06 | ERP → base, TCP 5432 | AUTORISÉ | `z4_data` : seuls `odoo`, `erp-db`, `backup` (et `guacd` pour l'administration) | `test-flux.sh` F06, NEG boutique/poste/waf → erp-db |
| F07 | Postes → ERP, TCP 8069 | AUTORISÉ | `odoo` attaché à `z8_postes` (10.10.8.20) | `test-flux.sh` F07 |
| F08 | Postes et serveurs → AD (88, 389, 636, 53, 445) | AUTORISÉ | `z5_identity` : `samba-ad` (`dc1.ostral.local`), `odoo` (LDAP 389 + STARTTLS, groupe `GG-ERP-Utilisateurs`), `poste`, `guacd` | `test-flux.sh` F08 (5 ports depuis le poste, 389 depuis Odoo) ; démo étape 3 bis |
| F09 | Admins / prestataire → VPN → bastion et console SIEM | RESTREINT | Port hôte `51820/udp` ; `wireguard` route, par pair, vers `z6_admin` (8080) et `z7_supervision` (5601, 3001) ; le pair `agenceweb` n'atteint que le bastion ; TOTP Guacamole | `test-flux.sh` F09 ; démo étape 5 |
| F10 | Bastion → serveurs, TCP 22 | RESTREINT | `guacd` seul a une patte dans les zones administrées ; sessions enregistrées | `test-flux.sh` F10, NEG guacamole → SSH |
| F11 | Toutes zones → SIEM, TCP 1514-1515 | SURVEILLÉ | Volumes `logs_*` montés en lecture seule dans `wazuh-manager` (équivalent agents) ; ports 1514/1515 ouverts sur Z7 | `test-flux.sh` F11 (profil `siem`) |
| F12 | Serveurs Z3–Z7 → Internet (mises à jour) | AUTORISÉ en cible | **Non reproduit** : réseaux `internal` ; mises à jour par reconstruction d'images | `test-flux.sh` F12 (attendu BLOQUÉ dans la maquette) |
| F13 | Postes → Internet direct | BLOQUÉ | `poste` uniquement sur des réseaux `internal` | `test-flux.sh` F13 (443 et DNS 53) |
| F14 | DMZ → zones internes (sauf F05) | BLOQUÉ | `waf` absent de `z3_servers`, `z4_data`, `z5_identity`, `z6_admin`, `z8_postes` ; il ne partage avec l'ERP que `z3_api` ; `guacd` n'écoute que sur 10.10.6.11 | `test-flux.sh` F14 (erp-db, AD, bastion, admin-target:22, guacd:4822) |
| F15 | Postes → serveurs en SSH/RDP | BLOQUÉ | `poste` absent de `z3_servers` | `test-flux.sh` F15, NEG poste → guacamole |
| F16 | Sauvegarde → serveurs Z3–Z6, TCP 22 (pull) | RESTREINT | `backup` sur `z3_servers` et `z4_data`, clé SSH dédiée, compte PostgreSQL lecture seule | `test-flux.sh` F16 ; `test-restore.sh` |
| F17 | Sauvegarde → stockage objet hors site, TCP 443 | AUTORISÉ | Réseau dédié `z7_offsite` vers `minio-offsite:9000`, données chiffrées avant envoi, clé en écriture seule, verrouillage 30 jours | `test-flux.sh` F17 |
| F18 | Supervision → services de toutes les zones | SURVEILLÉ | `uptime-kuma` sur `z7_supervision`, `z0_internet` (sonde externe), `z3_servers` | `test-flux.sh` F18 |

En complément, `test-flux.sh` exécute des **tests négatifs** (préfixe `NEG`) : boutique → `erp-db`,
boutique → `odoo` direct, boutique → Internet, `erp-db` → Internet, poste → `guacamole`,
poste → console SIEM, WireGuard → SSH direct, ports non publiés sur l'hôte, etc.

## 3. Risques résiduels R1–R3

| Risque | Mesure complémentaire (dossier) | Présent dans la maquette | Démonstration |
|---|---|---|---|
| **R1** Code malveillant livré par l'agence web ou une dépendance | Revue de code, analyse des dépendances, comptes nominatifs de l'agence | `package-lock.json` versionné (dépendances figées) ; `trivy-scan.sh` (images et dépendances applicatives présentes dans les images) ; accès de l'agence via un compte bastion nominatif ; journaux applicatifs de la boutique vers le SIEM | `trivy-scan.sh` ; démo étape 8 |
| **R2** Coupure du lien boutique ↔ ERP | File d'attente des commandes, lien secondaire | Table `outbox` dans `boutique-db` + worker de réémission ; la boutique reste en ligne si l'ERP est arrêté | `test-restore.sh --erp-down` ; démo étape 4 |
| **R3** Vol d'un compte administrateur | FIDO2, alertes SIEM sur connexions inhabituelles | TOTP obligatoire sur Guacamole ; clé WireGuard par personne ; journaux Guacamole et `auth.log` d'`admin-target` dans Wazuh ; sessions enregistrées | Démo étapes 5 et 6 ; FIDO2 non reproduit |

## 4. Scénarios stratégiques SS1–SS5

| Scénario | Mesures de l'architecture | Présence dans la maquette | Test |
|---|---|---|---|
| **SS1** Rançongiciel via un poste ou un accès prestataire | Postes isolés (F13, F15), bastion, SIEM, sauvegardes isolées (E09) | `poste` sans Internet ni SSH ; accès prestataire uniquement par VPN + bastion ; sauvegarde *pull* + MinIO verrouillé | `test-flux.sh` F13/F15 ; `test-restore.sh` |
| **SS2** Piratage en masse des comptes clients | WAF, limitation de débit (F01), alertes SIEM | CRS + `limit_req` sur `/login` → 429 ; alerte Wazuh | `test-waf.sh` §5 ; démo étape 2 |
| **SS3** Code malveillant injecté par la chaîne de développement | Comptes nominatifs et temporaires (E07), revue de code | Compte bastion nominatif à durée limitée ; scan Trivy ; reste R1 | `trivy-scan.sh` ; démo étapes 5 et 8 |
| **SS4** Boutique indisponible (pic, saturation) | Cloud élastique, WAF, anti-DDoS hébergeur | Limitation de débit, limites de ressources, redémarrage automatique, sonde Uptime Kuma (E11) ; pas d'élasticité réelle | `test-waf.sh` ; démo étape 4 |
| **SS5** Abus de droits par un administrateur ou un prestataire | Bastion, MFA, sessions enregistrées, comptes temporaires | Guacamole + TOTP + enregistrement (`guac_recordings`) ; SIEM indépendant de l'AD (comptes locaux) | Démo étapes 5 et 6 |

## 5. Récapitulatif des scripts de test

| Script | Ce qu'il vérifie | Références |
|---|---|---|
| `scripts/test-flux.sh` | Matrice de flux, tests positifs et négatifs depuis chaque conteneur source | F01–F18, E05, E06, E09, E11 |
| `scripts/test-waf.sh` | Filtrage applicatif, en-têtes, versions TLS, limitation de débit | F01, E03, E04, SS2 |
| `scripts/test-restore.sh` | Restauration testée ; `--erp-down` : file d'attente des commandes | E09, E10, R2 |
| `scripts/trivy-scan.sh` | Vulnérabilités critiques des images, mauvaises configurations | E12, R1 |
