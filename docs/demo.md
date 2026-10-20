# OSTRAL — Scénario de démonstration (soutenance)

Durée visée : **20 à 25 minutes**. Chaque étape indique l'exigence ou le flux démontré, la
commande à lancer et le résultat attendu. Les commandes se lancent depuis la racine du projet
(Git Bash sous Windows ou shell Linux).

> **Démonstration express (5 min)** : `bash scripts/demo-securite.sh` joue 8 attaques réalistes
> (web, bourrage d'identifiants, fausse notification de paiement, accès direct depuis Internet,
> rebond depuis la boutique compromise, poste piégé, destruction des sauvegardes), affiche la
> mesure qui bloque chacune, puis les alertes Wazuh correspondantes. `--auto` pour l'enchaîner.

## 0. Préparation (avant la soutenance)

```bash
bash scripts/init.sh --siem                  # amorçage complet dans le bon ordre (voir exploitation.md)
docker compose --profile siem ps             # tous les services « running (healthy) »
bash scripts/test-flux.sh                    # matrice de flux conforme (à garder à l'écran)
```

Onglets à ouvrir dans le navigateur :

| Onglet | Adresse | Remarque |
|---|---|---|
| Boutique | https://ostral.local | entrée hosts `127.0.0.1 ostral.local` |
| Page de paiement du PSP | http://127.0.0.1:4000 | ouverte automatiquement par la redirection de la boutique |
| Guacamole | http://10.10.6.10:8080/guacamole via le VPN | sans VPN : profil `demo`, http://127.0.0.1:8080/ |
| Wazuh | https://10.10.7.22:5601 via le VPN (pair `admin1`) | profil `siem` |
| Uptime Kuma | http://10.10.7.30:3001 via le VPN (pair `admin1`) | |

Conseil : lancer `docker compose logs -f waf` dans un terminal annexe pour montrer les blocages en
direct.

---

## Étape 1 — Une attaque web est bloquée par le WAF (F01, E04, SS2)

**Message** : la boutique n'est joignable que par le WAF ; ModSecurity + OWASP CRS bloquent les
attaques classiques avant qu'elles n'atteignent le code.

```bash
# Requête légitime
curl -sk -o /dev/null -w '%{http_code}\n' https://ostral.local/                 # 200
# Injection SQL
curl -sk -o /dev/null -w '%{http_code}\n' "https://ostral.local/?id=1%27%20OR%20%271%27%3D%271"   # 403
# XSS
curl -sk -o /dev/null -w '%{http_code}\n' "https://ostral.local/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"  # 403
# Fausse notification de paiement envoyée depuis Internet
curl -sk -o /dev/null -w '%{http_code}\n' -X POST https://ostral.local/payment/notify  # 403
# HTTP en clair : simple redirection permanente vers HTTPS
curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' http://ostral.local/        # 301 https://ostral.local/
# La boutique n'est pas publiée directement
curl -s --max-time 3 http://127.0.0.1:3000/ || echo "boutique injoignable en direct"
```

À montrer : la ligne correspondante dans le journal d'audit ModSecurity (volume `logs_waf`), avec
l'identifiant de règle CRS (ex. 942100 pour l'injection SQL). Puis la version complète :

```bash
bash scripts/test-waf.sh
```

## Étape 2 — Bourrage d'identifiants : 429 puis alerte Wazuh (E04, E08, SS2)

**Message** : l'incident « comptes clients piratés par réutilisation de mots de passe » est traité
par une limitation de débit sur l'authentification (`POST /login` et `POST /register` : 10 par
minute et par IP, rafale de 5) et par une alerte SIEM.

```bash
for i in $(seq 1 30); do
  curl -sk -o /dev/null -w '%{http_code} ' -X POST \
    --data "email=victime$i%40exemple.fr&password=fuite$i" https://ostral.local/login
done; echo
# Résultat attendu : quelques réponses de la boutique (403 : jeton CSRF absent), puis une majorité de 429
```

Les premières requêtes atteignent la boutique, qui les refuse faute de jeton CSRF et de session.
Au-delà de la rafale autorisée, le WAF répond lui-même **429** et la boutique n'est plus sollicitée.

Dans Wazuh (*Threat Hunting* / *Discover*), filtrer sur les événements du WAF : une alerte
« rafale de 429 / tentative de bourrage d'identifiants » apparaît avec l'adresse source. Rappeler
que les comptes du SIEM sont **locaux** (indépendants de l'AD) : un attaquant qui prend l'annuaire
ne peut pas effacer ses traces.

## Étape 3 — Commande payée via le PSP, transmise à l'ERP en mTLS (E02, E03, F03 → F06)

**Message** : OSTRAL ne voit jamais un numéro de carte (SAQ A) ; le seul chemin du site vers le
SI interne est l'API ERP en mTLS, limitée aux routes d'API.

1. Sur https://ostral.local, **créer un compte** (`/register`) ou se connecter (`/login`) : les
   formulaires portent un jeton CSRF et ouvrent une session.
2. Ouvrir un produit (ex. `/products/OST-CHA-001`, « Chaise Lune » ; catalogue `OST-CHA-001` à
   `OST-LAM-006`) et cliquer sur **Commander** : `POST /orders` crée la commande
   (référence affichée sur `/orders/<ref>`).
3. Cliquer sur **Payer** : `POST /orders/<ref>/pay` redirige le navigateur vers la **page de
   paiement du PSP simulé** (http://127.0.0.1:4000). La carte est saisie chez le PSP, jamais chez
   OSTRAL : carte factice `4242 4242 4242 4242` = acceptée, `4000 0000 0000 0002` = refusée.
4. Le PSP renvoie le client vers `/orders/<ref>/return` et notifie la boutique par un message
   **signé HMAC**, qui arrive directement par `z1_egress`. Depuis Internet, `/payment/notify` est
   refusé par le WAF (étape 1).
5. La commande payée est inscrite dans la file `outbox` *dans la même transaction* que le
   paiement ; le worker la transmet à Odoo par l'API mTLS. Elle apparaît dans Odoo
   (*Ventes → Commandes*, créée par l'utilisateur technique `api-boutique`).

Preuves côté réseau et données :

```bash
# Sans certificat client, l'API ERP refuse ; /web/login est interdit même avec certificat (F04, F05)
bash scripts/test-flux.sh 2>/dev/null | grep -E '^F0[45]'
# File d'attente : la commande est passée au statut « done » (transmise à l'ERP)
docker compose exec boutique-db sh -c \
  'psql -U "$POSTGRES_USER" -d "${POSTGRES_DB:-$POSTGRES_USER}" -c "select status,count(*) from outbox group by 1"'
```

Point clé : même avec un certificat valide, `/web/login` renvoie **403** (F05). Une boutique
compromise ne peut pas atteindre l'interface d'administration d'Odoo, et le WAF ne partage avec
Odoo que le réseau dédié `z3_api`.

### 3 bis — Les salariés se connectent à l'ERP avec leur compte d'annuaire (F07, F08)

Depuis le poste (Z8), Odoo s'authentifie auprès de l'AD `dc1.ostral.local` en LDAP avec STARTTLS
(port 389). Seuls les membres de `GG-ERP-Utilisateurs` sont acceptés :

| Compte AD | Groupe | Résultat attendu dans Odoo |
|---|---|---|
| `alice.martin`, `bruno.durand` | `GG-ERP-Utilisateurs` | connexion acceptée |
| `chloe.petit` | aucun groupe ERP | connexion refusée |
| `adm.claire` | `GG-Admins` | compte d'administration : à utiliser par le bastion, pas pour l'usage métier |

## Étape 4 — L'ERP tombe : les commandes sont mises en file d'attente (R2, E10, E11)

**Message** : une heure de boutique coupée coûte plus qu'une journée sans ERP ; la boutique
continue donc de vendre (RTO ERP 8 h) sans perdre de commande.

```bash
bash scripts/test-restore.sh --erp-down
```

Le script arrête Odoo, vérifie que la boutique répond toujours, puis fait passer une commande.
La commande se passe par formulaires (session + CSRF) : **la faire à la main dans le navigateur**,
comme à l'étape 3, quand le script le demande, ou fournir une commande automatisée par
`COMMANDE_CMD`. Le script constate ensuite que la commande reste dans `outbox` (statut
`pending`), redémarre Odoo, puis mesure l'écoulement jusqu'au statut `done`. Pendant l'arrêt,
montrer dans Uptime Kuma la sonde ERP en rouge et la sonde boutique en vert.

Variante E11 (détection en moins de 5 min) : `docker compose stop boutique`, observer l'alerte
Uptime Kuma après deux sondes en échec (environ 2 min), puis `docker compose start boutique`.

## Étape 5 — Accès prestataire : VPN + bastion + TOTP + session enregistrée (F09, F10, E06, E07, SS5)

**Message** : l'agence web ne partage plus un compte administrateur. Elle dispose d'un compte
nominatif, temporaire, protégé par MFA, et chaque session est enregistrée.

1. Activer le tunnel WireGuard du prestataire : fichier
   `services/wireguard/config/peer_agenceweb/peer_agenceweb.conf` importé dans le client
   WireGuard. Ce pair n'atteint **que** le bastion (10.10.6.10:8080) ; Wazuh et Uptime Kuma lui
   sont refusés (règles iptables par pair, refus journalisés `OSTRAL-FW1-DROP`).
2. Ouvrir http://10.10.6.10:8080/guacamole, se connecter avec le compte nominatif `agence-web`,
   puis saisir le **code TOTP** (enrôlement au premier login).
3. Ouvrir la connexion SSH vers `admin-target` et exécuter quelques commandes (`id`, `sudo -l`).
4. Avec `admin1` (pair `admin1`) : *Paramètres → Historique* dans Guacamole, puis rejouer
   l'**enregistrement** de la session (volume `guac_recordings`). Dans Wazuh : ouverture de session
   bastion et `auth.log` d'`admin-target`.
5. Montrer les restrictions du compte `agence-web` : **fenêtre horaire** (08:00–19:00) et **date
   d'expiration**. Hors fenêtre ou après expiration, la connexion est refusée (E07). Le compte
   par défaut `guacadmin` est désactivé.

Sans tunnel VPN, le bastion est injoignable : il n'est publié ni sur l'hôte ni sur `z0_internet`.
Si aucun client WireGuard n'est disponible le jour de la soutenance, lancer
`docker compose --profile demo up -d bastion-demo` puis ouvrir http://127.0.0.1:8080/. C'est un
contournement de F09 assumé et limité à la boucle locale : le TOTP et l'enregistrement restent
appliqués.

## Étape 6 — SSH direct depuis un poste : bloqué (F15, F13, SS1)

**Message** : un poste piégé par hameçonnage n'atteint ni Internet ni les serveurs en
administration.

```bash
docker compose exec poste sh -c 'nc -z -w 3 10.10.3.30 22 && echo OUVERT || echo BLOQUÉ'   # BLOQUÉ (F15)
docker compose exec poste sh -c 'nc -z -w 3 10.10.6.10 8080 && echo OUVERT || echo BLOQUÉ' # BLOQUÉ (bastion via VPN seulement)
docker compose exec poste sh -c 'nc -z -w 3 1.1.1.1 443 && echo OUVERT || echo BLOQUÉ'     # BLOQUÉ (F13)
docker compose exec poste sh -c 'nc -z -w 3 10.10.8.20 8069 && echo OUVERT || echo BLOQUÉ' # OUVERT (F07, usage métier)
```

Expliquer le principe : le poste n'a **aucune interface** sur `z3_servers` ni sur `z6_admin`. Le
refus est donc structurel, l'équivalent de FW2 en refus par défaut.

## Étape 7 — Sauvegarde et restauration testée (E09, E10, F16, F17, 3-2-1-1-0)

**Message** : le serveur de sauvegarde va chercher les données (*pull*), envoie une copie chiffrée
hors site sur un stockage verrouillé, et chaque sauvegarde est restaurée pour être prouvée.

```bash
bash scripts/test-restore.sh      # exécute /usr/local/bin/restore-test.sh dans le conteneur backup
```

Résultat attendu : la base ERP est restaurée dans un environnement isolé, l'empreinte est vérifiée
et le nombre de tables et de commandes est cohérent. Montrer ensuite que la copie hors site
(`minio-offsite`, bucket verrouillé par `minio-offsite-init`) est **non modifiable** : une
tentative de suppression est refusée, même avec le compte de sauvegarde (règle
« 1 non modifiable »).

## Étape 8 — Scan Trivy avant déploiement (E12, R1, SS3)

**Message** : aucune image ne part en production avec une vulnérabilité critique corrigeable.

```bash
bash scripts/trivy-scan.sh
```

Montrer la synthèse (`reports/trivy-<date>/synthese.txt`) : images saines ou bloquées (officielles
et construites localement `ostral/*`), contrôles du compose (versions fixées, pas de
`docker.sock`, `no-new-privileges`). Démonstration du blocage :

```bash
bash scripts/trivy-scan.sh nginx:1.18.0   # image ancienne : BLOQUÉ, code de retour 1
echo $?
```

## Conclusion (1 minute)

Récapituler avec [tracabilite.md](tracabilite.md) : chaque exigence E01–E12 a une mise en œuvre et
un test. Citer les écarts assumés (deux pare-feux non reproduits, IDS Suricata absent, PRA à froid
simulé) et les pistes d'amélioration (Suricata, FIDO2, filtrage de la patte `z4_data` d'Odoo).
