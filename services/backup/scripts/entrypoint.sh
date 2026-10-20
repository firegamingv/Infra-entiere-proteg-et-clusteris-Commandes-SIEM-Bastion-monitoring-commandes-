#!/bin/sh
# OSTRAL — démarrage du serveur de sauvegarde (Z7).
#  1. génère la paire de clés SSH dédiée « backup » (F16) au 1er démarrage (volume backup_ssh) ;
#  2. initialise le dépôt restic chiffré (volume backup_repo) ;
#  3. lance le planificateur supercronic — ou une commande ponctuelle :
#     docker compose run --rm backup show-pubkey | hourly | nightly | restore-test | snapshots
set -eu
. /usr/local/bin/lib.sh

: "${RESTIC_PASSWORD:?RESTIC_PASSWORD manquant}"
case "$RESTIC_PASSWORD" in
  CHANGEME*) echo "RESTIC_PASSWORD vaut encore la valeur d'exemple : à changer dans .env" >&2; exit 1 ;;
esac

mkdir -p "$SCRATCH/restic-cache" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true

if [ ! -s "$SSH_KEY" ]; then
  info "génération de la clé SSH de sauvegarde (ed25519) dans le volume backup_ssh"
  ssh-keygen -q -t ed25519 -N '' -C "backup@ostral-z7" -f "$SSH_KEY"
  chmod 0600 "$SSH_KEY"
  info "clé publique à reporter dans .env (BACKUP_SSH_PUBKEY, lot D / admin-target) :"
  cat "$SSH_KEY.pub" >&2
fi

restic_init_if_needed

case "${1:-cron}" in
  cron)         info "planificateur supercronic démarré"; exec supercronic /etc/backup/crontab ;;
  show-pubkey)  exec /usr/local/bin/show-pubkey.sh ;;
  hourly)       exec /usr/local/bin/backup-hourly.sh ;;
  nightly)      exec /usr/local/bin/backup-nightly.sh ;;
  restore-test) shift; exec /usr/local/bin/restore-test.sh "$@" ;;
  snapshots)    exec restic snapshots ;;
  *)            exec "$@" ;;
esac
