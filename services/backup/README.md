# Serveur de sauvegarde OSTRAL (Z7) : 3-2-1-1-0, mode pull

Le service `backup` repose sur l'image `ostral/backup:1.0.0`, construite sur `alpine:3.20.10` avec restic 0.16.4, PostgreSQL 16, OpenSSH, mcli et supercronic.
Il tourne en non-root (UID 10001), avec la racine en lecture seule et sans aucune capacité. Ses adresses : 10.10.7.40, 10.10.4.40, 10.10.3.41 et 10.10.17.40.

| Règle | Mise en œuvre maquette |
|-------|------------------------|
| 3 copies | production, puis dépôt restic `backup_repo` (Z7), puis bucket `minio-offsite` |
| 2 supports | volume du serveur de sauvegarde + stockage objet (second fournisseur) |
| 1 hors site | `minio-offsite` (réseau `z7_offsite`), données chiffrées par restic avant l'envoi (F17) |
| 1 non modifiable | Object Lock COMPLIANCE 30 j ; la clé d'accès ne peut qu'écrire (pas de suppression, pas de lecture) |
| 0 erreur | `restic check` toutes les nuits (10 % des données relues, empreintes SHA-256), relecture complète et test de restauration chaque mois |

## Planning (`crontab`, heure de Paris)

- **Toutes les heures, à :05 :** `pg_dump` de `ostral` sur `erp-db` avec le rôle `backup_ro` (lecture seule, pg_read_all_data, autorisé depuis 10.10.4.40 uniquement par le lot C), puis copie hors site. RPO de 1 h.
- **Chaque nuit à 01:30 :**
  - pull SSH d'admin-target ;
  - copie du filestore Odoo ;
  - copie des archives Wazuh ;
  - application de la rétention (48 horaires, 30 quotidiennes, 12 mensuelles) ;
  - `restic check` ;
  - copie hors site.
- **Le 1er du mois à 04:00 :** `restore-test.sh`.

Chaque tâche écrit une ligne JSON (`status` OK/ECHEC) dans `logs_backup/backup.json`. Wazuh déclenche la règle 100702 (niveau 12) en cas d'échec. Uptime Kuma reçoit aussi un battement « push » : une sauvegarde absente déclenche une alerte.

## Clé SSH du pull (F16) : procédure avec le lot D

1. Démarrer (ou lancer une fois) le service :
   `docker compose run --rm --no-deps backup show-pubkey`
   Au premier lancement, la paire ed25519 est générée dans le volume `backup_ssh` (la clé privée ne quitte jamais ce volume). La commande affiche ensuite une ligne de la forme `BACKUP_SSH_PUBKEY="ssh-ed25519 AAAA... backup@ostral-z7"`.
2. Copier cette ligne dans `.env`.
3. Recréer la cible : `docker compose up -d --force-recreate admin-target`.
4. Tester : `docker compose exec backup backup-nightly.sh`.

Le compte distant est `backup-ro`, avec la commande forcée `backup-ro.sh` du lot D. `export` renvoie l'archive tar de `/srv/data`.
La clé d'hôte du serveur est mémorisée au premier contact (`known_hosts` dans le volume).

## Commandes utiles

```sh
docker compose exec backup restic snapshots              # liste des sauvegardes
docker compose exec backup backup-hourly.sh              # sauvegarde ERP immédiate
docker compose exec backup restore-test.sh --full-check  # test de restauration mensuel (E10)
```

`restore-test.sh` :

1. extrait le dernier dump ERP ;
2. le restaure dans un PostgreSQL 16 **jetable**, lancé dans le conteneur sur une socket Unix et sans écoute réseau ;
3. vérifie le nombre de tables (au moins `RESTORE_MIN_TABLES`), la présence de `sale_order` et un nombre de commandes cohérent avec la production (lu par `backup_ro`) ;
4. journalise la durée, à comparer au RTO ERP de 8 h.

## Écarts et limites (documentés)

- **Filestore Odoo :** le volume `odoo_data` (lot C) est monté **en lecture seule** dans `backup`. C'est un écart au pull SSH, équivalent à un export NFS en lecture seule. En cible, on ferait un pull SSH/rsync en lecture seule depuis le serveur ERP.
- **Archives Wazuh :** `wazuh_logs` est monté en lecture seule, avec `group_add: 999` (GID wazuh de l'image manager).
- **Copie hors site :** elle passe par `mcli mirror --md5`, sans `--overwrite` ni `--remove`. Le bucket est donc un sur-ensemble immuable du dépôt, que restic peut lire directement (`restic -r s3:http://minio-offsite:9000/ostral-backup-offsite/restic`, avec un compte de lecture créé ponctuellement par root lors d'un PRA). Les paquets supprimés localement par `prune` restent hors site. La purge hors site se fait manuellement par root, après expiration du verrouillage.
- **HTTP vers MinIO dans la maquette :** les données sont chiffrées par restic avant l'envoi. En cible, le flux F17 passe en TLS 443.
- **Version de PostgreSQL :** `pg_dump` 16 exige que la base ERP soit en version 16 au plus. Si le lot C passe en 17, il faut monter `postgresql17-client`.
