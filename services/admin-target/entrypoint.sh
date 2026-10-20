#!/bin/sh
# =============================================================================
# OSTRAL — lot D — démarrage d'admin-target (Z3)
#  - construit les authorized_keys (root:root, 0644, dans /run : système de fichiers racine
#    en lecture seule) à partir de :
#      * /etc/ssh/ostral/bastion.pub  (clé du bastion, volume admin_target_ssh, guac-init)
#      * $BACKUP_SSH_PUBKEY           (clé publique du serveur de sauvegarde, lot E)
#  - démarre rsyslog (journaux d'authentification -> logs_admin_target)
#  - lance sshd au premier plan (PID enfant de tini).
# =============================================================================
set -eu

AUTHKEYS_DIR=/run/ostral-authkeys
HOSTKEY=/etc/ssh/ostral/hostkeys/ssh_host_ed25519_key
BASTION_PUB=/etc/ssh/ostral/bastion.pub
BASTION_IP=10.10.3.11   # guacd sur z3_servers (F10)
BACKUP_IP=10.10.3.41    # backup sur z3_servers (F16)

log() { echo "[admin-target] $*"; }

umask 022
mkdir -p /run/rsyslog "$AUTHKEYS_DIR"
chmod 0755 "$AUTHKEYS_DIR"

if [ ! -s "$HOSTKEY" ]; then
  log "ERREUR : clé d'hôte absente ($HOSTKEY) — le service guac-init doit s'exécuter avant." >&2
  exit 1
fi

# Valide une clé publique OpenSSH sur UNE ligne (empêche l'injection d'options authorized_keys).
cle_valide() {
  printf '%s' "$1" | grep -Eq '^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+( [A-Za-z0-9@._+-]*)?$'
}

# --- Clé du bastion : session interactive (pty), aucun transfert -------------------------
: > "$AUTHKEYS_DIR/ostral-admin"
if [ -s "$BASTION_PUB" ] && cle_valide "$(head -n 1 "$BASTION_PUB")"; then
  printf 'restrict,pty,from="%s" %s\n' "$BASTION_IP" "$(head -n 1 "$BASTION_PUB")" \
    > "$AUTHKEYS_DIR/ostral-admin"
  log "clé du bastion autorisée pour ostral-admin depuis $BASTION_IP uniquement"
else
  log "AVERTISSEMENT : clé du bastion absente ou invalide — aucun accès d'administration" >&2
fi

# --- Clé de sauvegarde : commande forcée, lecture seule (F16) -----------------------------
: > "$AUTHKEYS_DIR/backup-ro"
BACKUP_SSH_PUBKEY="${BACKUP_SSH_PUBKEY:-}"
if [ -n "$BACKUP_SSH_PUBKEY" ]; then
  if cle_valide "$BACKUP_SSH_PUBKEY"; then
    printf 'restrict,from="%s",command="/usr/local/bin/backup-ro.sh" %s\n' \
      "$BACKUP_IP" "$BACKUP_SSH_PUBKEY" > "$AUTHKEYS_DIR/backup-ro"
    log "clé de sauvegarde autorisée pour backup-ro depuis $BACKUP_IP (lecture seule)"
  else
    log "AVERTISSEMENT : BACKUP_SSH_PUBKEY invalide (une seule ligne 'type base64 [commentaire]')" >&2
  fi
else
  log "BACKUP_SSH_PUBKEY vide : compte backup-ro inutilisable"
fi
chmod 0644 "$AUTHKEYS_DIR/ostral-admin" "$AUTHKEYS_DIR/backup-ro"

# --- Journalisation -------------------------------------------------------------------------
mkdir -p /var/log/admin-target
chmod 0750 /var/log/admin-target
rsyslogd -i /run/rsyslogd.pid -f /etc/rsyslog.conf

# Vérification de la configuration avant lancement.
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
log "démarrage de sshd"
exec /usr/sbin/sshd -D -f /etc/ssh/sshd_config
