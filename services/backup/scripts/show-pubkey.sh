#!/bin/sh
# OSTRAL — affiche la clé publique de sauvegarde à recopier dans .env (BACKUP_SSH_PUBKEY, lot D).
# Côté admin-target (lot D), la clé est installée pour le compte backup-ro avec commande forcée
# (backup-ro.sh : « export » => tar de /srv/data) ; restriction de source recommandée from="10.10.3.41".
# Procédure : docker compose run --rm --no-deps backup show-pubkey  → copier la ligne dans .env
#             puis : docker compose up -d --force-recreate admin-target
set -eu
. /usr/local/bin/lib.sh
if [ ! -s "$SSH_KEY.pub" ]; then
  echo "clé absente : elle est générée au 1er démarrage du service backup" >&2
  exit 1
fi
printf 'BACKUP_SSH_PUBKEY="%s"\n' "$(cat "$SSH_KEY.pub")"
