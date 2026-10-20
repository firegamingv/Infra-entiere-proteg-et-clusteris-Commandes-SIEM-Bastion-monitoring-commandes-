# Wazuh : SIEM OSTRAL (Z7, profil `siem`)

Déploiement single-node **4.14.4**, inspiré de `wazuh-docker/single-node` : manager 10.10.7.20, indexer 10.10.7.21 et dashboard 10.10.7.22.
Prévoir environ 4,5 Go de RAM (indexer 2 Go dont 1 Go de heap, manager 1,5 Go, dashboard 1 Go).

## Initialisation (premier démarrage)

1. **Hôte Linux / WSL2 (Docker Desktop) :** exécuter `sysctl -w vm.max_map_count=262144`. OpenSearch l'exige et ce réglage n'est pas namespacé. Sous Docker Desktop, la commande se lance dans `wsl -d docker-desktop`.
2. **Mots de passe dans `.env` :** `INDEXER_PASSWORD`, `DASHBOARD_PASSWORD` et `API_PASSWORD`. Ce dernier suit la politique Wazuh : 8 à 64 caractères, avec majuscule, minuscule, chiffre et symbole.
3. **Démarrage :** `docker compose --profile siem up -d`. Les one-shots s'enchaînent automatiquement :
   - `wazuh-certs` (image `wazuh/wazuh-certs-generator:0.0.4`) crée l'AC et les certificats dans `services/wazuh/certs/`. Il ne s'exécute qu'une fois, puis ne fait plus rien tant que les certificats existent. Il a besoin d'Internet (téléchargement de `wazuh-certs-tool.sh`) et utilise pour cela le réseau `default` de compose.
   - `wazuh-users-init` produit `generated/internal_users.yml` (hachages bcrypt) et `generated/wazuh.yml`.
   - `wazuh-ism-init` applique la politique de rétention de 90 jours. Il peut être rejoué : `docker compose --profile siem run --rm wazuh-ism-init`.
4. **Console :** via le VPN, ouvrir `https://10.10.7.22:5601` avec le compte `admin` / `INDEXER_PASSWORD`.
   Pour une démonstration sans VPN, ajouter `services/wazuh/compose.dashboard-demo.yml` à `COMPOSE_FILE`. Le dashboard est alors publié sur `127.0.0.1:5601`.

**Comptes locaux (E08).** L'indexer (`admin`, `kibanaserver`) et l'API (`wazuh-wui`) utilisent des comptes locaux, sans backend LDAP/AD. Un attaquant qui contrôle l'annuaire ne peut donc pas effacer ses traces.

**Changer un mot de passe après le premier démarrage.** `internal_users.yml` n'est lu qu'à l'initialisation de l'index de sécurité. Il faut relancer `wazuh-users-init`, puis appliquer la configuration avec l'outil officiel :
`docker compose exec wazuh-indexer bash -c 'JAVA_HOME=/usr/share/wazuh-indexer/jdk /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/config/opensearch-security -nhnv -cacert config/certs/root-ca.pem -cert config/certs/admin.pem -key config/certs/admin-key.pem -h localhost'`.
Autre option : supprimer le volume `wazuh_indexer_data`, ce qui efface aussi les alertes.

## Collecte (F11, E08)

Le manager monte en lecture seule les volumes `logs_*` sous `/var/log/ostral/<service>/` (voir `ossec.conf`) :

| Volume | Fichier | Format |
|--------|---------|--------|
| logs_waf | waf_access.json, modsec_audit.json, waf_error.log | JSON / JSON / texte |
| logs_boutique | app.log | JSON lignes |
| logs_odoo | odoo.log | texte (décodeur `ostral-odoo`) |
| logs_erp_db | postgresql-AAAA-MM-JJ.log | texte (décodeur `ostral-pgsql`) |
| logs_samba | samba.log | audit JSON Samba (décodeur `ostral-samba`) |
| logs_guacamole | *.log (logback) | texte (décodeur `ostral-guacamole`) |
| logs_admin_target | auth.log | syslog (décodeur natif `sshd`, couvre aussi `sshd-session`) |
| logs_wireguard | wireguard.log | clé=valeur (décodeur `ostral-wireguard`) |
| logs_backup | backup.json | JSON (status OK/ECHEC) |

Les ports 1514 et 1515 (agents) ne sont ouverts que dans Z7 et ne sont pas publiés sur l'hôte.

## Règles (`local_rules.xml`, 100100-100999)

Un niveau supérieur ou égal à 10 déclenche un SMS d'astreinte ; les niveaux 7 à 9 déclenchent un e-mail (p. 12).

| Scénario | Règles | Niveau |
|----------|--------|--------|
| SS2, piratage en masse de comptes clients | 100103 (10 échecs en 60 s depuis la même IP), 100104 (30 échecs en 2 min, toutes IP), 100202 (rafale de 429 du WAF) | 10 / 12 / 10 |
| Attaques web | 100203/100204 (403 répétés), 100211-100213 (blocages ModSecurity, injections) | 5 à 10 |
| Ajout à un groupe d'administrateurs AD (Domain Admins, GG-Admins…) | 100401 | 12 |
| Bastion hors horaires (19 h – 7 h 30, week-end) | 100505/100506 | 10 |
| Compte prestataire (`agence-web`, `presta*`, `ext-*`) | 100502 (toute connexion), 100503/100504 (hors horaires) | 8 / 12 |
| SSH hors horaires sur un serveur (hors `backup-ro`) / clé de sauvegarde utilisée d'ailleurs | 100600 / 100601 | 10 |
| Échec de sauvegarde ou du test de restauration | 100702 / 100703 | 12 |
| Force brute Odoo, AD, PostgreSQL, bastion | 100303, 100403, 100352, 100508 | 10 |
| Taux de 5xx, disque à plus de 85 % | 100206, 100900 | 7 |

Pour tester une règle : `docker compose exec wazuh-manager /var/ossec/bin/wazuh-logtest`.

## Rétention (E08)

- **3 mois consultables :** la politique ISM `ism/ostral-retention-90j.json` supprime les index `wazuh-alerts-*` après 90 jours.
- **12 mois d'archives :** `logall_json` écrit tous les événements dans `/var/ossec/logs/archives/` (volume `wazuh_logs`). Chaque nuit, `backup` les copie, en lecture seule (GID 999 = groupe wazuh), vers le dépôt restic puis vers le bucket verrouillé (Object Lock 30 j). La rétention restic de 12 mensuelles couvre les 12 mois.
- **Limite :** le manager ne purge pas lui-même ses archives locales. En cible, un cron supprime les fichiers de plus de 12 mois après vérification de la copie.

## Durcissement et limites

- **Indexer et dashboard :** non-root (UID 1000), `cap_drop: ALL`. Les `ulimits` memlock et nofile sont exigés par OpenSearch.
- **Manager :** il démarre en root (s6-overlay), puis lance ses daemons sous l'utilisateur `wazuh`. Il conserve les capacités CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, SETGID, SETUID et SYS_CHROOT (chroot des daemons, lecture des journaux d'autres UID). Si un daemon ne démarre pas, regarder d'abord `docker compose logs wazuh-manager`.
- **Pas de `read_only` :** les trois images écrivent dans de nombreux répertoires.
- **Détection de vulnérabilités désactivée :** Z7 n'a pas d'accès Internet pour les flux CTI.
- **Les identifiants Filebeat du manager → indexer utilisent le compte `admin`,** comme dans le dépôt officiel. En cible, il faudrait un compte dédié avec un rôle d'écriture limité.
