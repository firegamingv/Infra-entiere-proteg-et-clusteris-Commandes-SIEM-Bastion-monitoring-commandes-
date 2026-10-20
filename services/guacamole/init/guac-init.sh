#!/bin/sh
# =============================================================================
# OSTRAL — lot D — service one-shot "guac-init" (exécuté dans l'image admin-target, root,
# sans réseau). Idempotent : ne régénère jamais une clé existante.
#
#  1. Clé d'hôte ED25519 du serveur admin-target (épinglée ensuite dans la connexion
#     Guacamole via le paramètre host-key : pas de "trust on first use", F10).
#  2. Clé cliente du bastion (ED25519 par défaut, RSA 4096 PEM en repli via GUAC_SSH_KEY_TYPE=rsa) :
#     privée -> volume guac_sshkey (lu uniquement par guac-db pour l'injecter dans la connexion),
#     publique -> volume admin_target_ssh (authorized_keys d'admin-target).
#     Aucune clé n'est générée dans une image ni stockée dans git (E12).
#  3. Droits des volumes partagés :
#     guac_recordings : guacd (UID 1000) écrit, guacamole (GID 1001) lit — mode 2750 (E06).
#     logs_guacamole  : guacamole (UID 1001).
#     guac_initdb_sql : guacamole (UID 1001) y écrit le schéma SQL (service guac-initdb).
# =============================================================================
set -eu

KEY_TYPE="${GUAC_SSH_KEY_TYPE:-ed25519}"
PG_UID=70            # utilisateur postgres de l'image postgres:*-alpine
GUACD_UID=1000       # utilisateur guacd de l'image guacamole/guacd:1.6.0
GUAC_UID=1001        # utilisateur guacamole de l'image guacamole/guacamole:1.6.0

SSHKEY_DIR=/out/guac-sshkey
TARGET_DIR=/out/admin-target-ssh
HOSTKEY="$TARGET_DIR/hostkeys/ssh_host_ed25519_key"
CLIENTKEY="$SSHKEY_DIR/guac_ssh_key"

log() { echo "[guac-init] $*"; }

# --- 1. Clé d'hôte d'admin-target --------------------------------------------------------
mkdir -p "$TARGET_DIR/hostkeys"
if [ ! -s "$HOSTKEY" ]; then
  log "génération de la clé d'hôte ED25519 d'admin-target"
  ssh-keygen -q -t ed25519 -N '' -C 'admin-target.ostral.internal' -f "$HOSTKEY"
fi
chown -R 0:0 "$TARGET_DIR"
chmod 0755 "$TARGET_DIR" "$TARGET_DIR/hostkeys"
chmod 0600 "$HOSTKEY"
chmod 0644 "$HOSTKEY.pub"

# --- 2. Clé cliente du bastion ------------------------------------------------------------
mkdir -p "$SSHKEY_DIR"
if [ ! -s "$CLIENTKEY" ]; then
  case "$KEY_TYPE" in
    ed25519)
      log "génération de la clé cliente ED25519 du bastion"
      ssh-keygen -q -t ed25519 -N '' -C 'guacamole-bastion@ostral' -f "$CLIENTKEY" ;;
    rsa)
      log "génération de la clé cliente RSA 4096 (format PEM) du bastion"
      ssh-keygen -q -t rsa -b 4096 -m PEM -N '' -C 'guacamole-bastion@ostral' -f "$CLIENTKEY" ;;
    *)
      echo "[guac-init] GUAC_SSH_KEY_TYPE invalide : '$KEY_TYPE' (ed25519|rsa)" >&2
      exit 1 ;;
  esac
fi
cp "$CLIENTKEY.pub" "$TARGET_DIR/bastion.pub"
chmod 0644 "$TARGET_DIR/bastion.pub"
cp "$HOSTKEY.pub" "$SSHKEY_DIR/admin-target_host.pub"
chown -R "$PG_UID:$PG_UID" "$SSHKEY_DIR"
chmod 0750 "$SSHKEY_DIR"
chmod 0400 "$CLIENTKEY"
chmod 0444 "$CLIENTKEY.pub" "$SSHKEY_DIR/admin-target_host.pub"

# --- 3. Droits des volumes partagés ------------------------------------------------------
chown "$GUACD_UID:$GUAC_UID" /out/recordings
chmod 2750 /out/recordings

chown "$GUAC_UID:$GUAC_UID" /out/logs-guacamole
chmod 0750 /out/logs-guacamole

chown "$GUAC_UID:$GUAC_UID" /out/initdb-sql
chmod 0755 /out/initdb-sql

log "empreinte de la clé d'hôte d'admin-target : $(ssh-keygen -l -f "$HOSTKEY.pub")"
log "empreinte de la clé cliente du bastion     : $(ssh-keygen -l -f "$CLIENTKEY.pub")"
log "terminé"
