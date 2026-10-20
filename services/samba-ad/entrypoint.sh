#!/bin/bash
# OSTRAL — Lot C — entrypoint du contrôleur de domaine Samba AD OSTRAL.LOCAL (Z5, S3)
#
# Idempotent :
#   1. premier démarrage : provisionnement du domaine (samba-tool domain provision --use-rfc2307),
#      tout l'état (bases, SYSVOL, smb.conf, krb5.conf) est stocké dans le volume samba_data ;
#   2. à chaque démarrage : certificat TLS (LDAPS 636 / STARTTLS 389) créé s'il manque, AC exportée
#      dans le volume samba_tls (lue par Odoo pour vérifier le certificat, F07/F08) ;
#   3. à chaque démarrage : politique de mots de passe, OU, groupes, comptes de démonstration et
#      compte de liaison LDAP d'Odoo (svc-odoo-ldap) créés s'ils manquent (hors ligne, avant le démon) ;
#   4. lancement de « samba » au premier plan (journaux d'audit dans /var/log/samba → logs_samba).
set -Eeuo pipefail

log() { echo "[ostral/samba-ad] $*"; }
trap 'log "ERREUR ligne $LINENO (code $?)"' ERR

# ----------------------------------------------------------------------------- paramètres
T="${SAMBA_TARGETDIR:-/var/lib/samba/ad}"
CONF="$T/etc/smb.conf"
SAM="$T/private/sam.ldb"
TLS="$T/private/tls"
REALM="${SAMBA_REALM:-OSTRAL.LOCAL}"
DOMAIN="${SAMBA_DOMAIN:-OSTRAL}"
DC_NAME="${SAMBA_DC_HOSTNAME:-dc1}"
DC_IP="${SAMBA_DC_IP:-10.10.5.10}"
DNS_DOMAIN="${REALM,,}"
DC_FQDN="${DC_NAME}.${DNS_DOMAIN}"
BASE_DN="DC=${DNS_DOMAIN//./,DC=}"
OU_ROOT="OU=OSTRAL"
OU_USERS="OU=Utilisateurs,${OU_ROOT}"
OU_ADMINS="OU=Administrateurs,${OU_ROOT}"
OU_GROUPS="OU=Groupes,${OU_ROOT}"
OU_SVC="OU=Comptes-Service,${OU_ROOT}"

: "${SAMBA_ADMIN_PASSWORD:?SAMBA_ADMIN_PASSWORD manquant}"
: "${SAMBA_ODOO_BIND_PASSWORD:?SAMBA_ODOO_BIND_PASSWORD manquant}"
: "${SAMBA_DEMO_USER_PASSWORD:?SAMBA_DEMO_USER_PASSWORD manquant}"

st() { samba-tool "$@" -s "$CONF"; }

# ------------------------------------------------------------------- 1. provisionnement
provision() {
  if [[ -f "$SAM" ]]; then
    log "domaine $REALM déjà provisionné (volume samba_data)."
    return
  fi
  log "provisionnement du domaine $REALM (DC $DC_FQDN, $DC_IP)…"
  install -d -m 0755 "$T"
  samba-tool domain provision \
    --targetdir="$T" \
    --realm="$REALM" \
    --domain="$DOMAIN" \
    --server-role=dc \
    --dns-backend=SAMBA_INTERNAL \
    --use-rfc2307 \
    --host-name="$DC_NAME" \
    --host-ip="$DC_IP" \
    --adminpass="$SAMBA_ADMIN_PASSWORD" \
    --option="include = /etc/ostral/ostral-global.conf"
  log "provisionnement terminé."
}

# ---------------------------------------------------------------------- 2. TLS (F08)
tls_setup() {
  install -d -m 0700 "$TLS"
  if [[ ! -s "$TLS/cert.pem" || ! -s "$TLS/key.pem" || ! -s "$TLS/ca.pem" ]]; then
    log "génération de l'AC interne AD et du certificat LDAPS de $DC_FQDN…"
    local work
    work="$(mktemp -d)"
    (
      umask 077
      openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
        -subj "/O=OSTRAL/OU=Annuaire/CN=OSTRAL AD Root CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
      openssl req -new -newkey rsa:3072 -nodes -sha256 \
        -subj "/O=OSTRAL/OU=Annuaire/CN=${DC_FQDN}" \
        -keyout "$work/key.pem" -out "$work/req.csr" 2>/dev/null
      cat > "$work/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${DC_FQDN},DNS:${DNS_DOMAIN},DNS:samba-ad,DNS:${DC_NAME},IP:${DC_IP}
EOF
      openssl x509 -req -in "$work/req.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" \
        -CAcreateserial -days 825 -sha256 -extfile "$work/ext.cnf" -out "$work/cert.pem" 2>/dev/null
    )
    install -m 0600 "$work/key.pem" "$TLS/key.pem"     # Samba exige une clé en 0600
    install -m 0644 "$work/cert.pem" "$TLS/cert.pem"
    install -m 0644 "$work/ca.pem" "$TLS/ca.pem"
    # La clé de l'AC n'est pas conservée (S3) : un renouvellement régénère toute la chaîne.
    rm -rf "$work"
  fi
  # Export de la seule AC publique pour les clients LDAP (Odoo), volume samba_tls en lecture seule chez eux
  install -d -m 0755 /export/tls
  install -m 0644 "$TLS/ca.pem" /export/tls/ca.crt
}

# --------------------------------------------- 3. objets d'annuaire (idempotent, hors ligne)
dn_exists() {   # $1 = DN relatif au domaine
  ldbsearch -H "$SAM" -b "$1,$BASE_DN" -s base dn 2>/dev/null | grep -q '^dn:'
}

ensure_ou() {
  dn_exists "$1" && return 0
  # « ou create » (Samba 4.17, Debian 12) ; « ou add » sur les versions plus récentes
  st ou create "$1" >/dev/null 2>&1 || st ou add "$1" >/dev/null
  log "OU créée : $1"
}

ensure_group() {   # $1 = nom, $2 = OU, $3 = description
  st group show "$1" >/dev/null 2>&1 && return 0
  st group add "$1" --groupou="$2" --group-scope=Global --group-type=Security \
    --description="$3" >/dev/null
  log "groupe créé : $1"
}

ensure_user() {    # $1 = login, $2 = mdp, $3 = OU, $4 = prénom, $5 = nom, [$6 = options…]
  local login="$1" pw="$2" ou="$3" given="$4" sn="$5"
  shift 5
  st user show "$login" >/dev/null 2>&1 && return 0
  st user create "$login" "$pw" --userou="$ou" --given-name="$given" --surname="$sn" \
    --mail-address="${login}@${DNS_DOMAIN}" "$@" >/dev/null
  log "compte créé : $login ($ou)"
}

ensure_member() {  # $1 = groupe, $2 = membre
  if st group listmembers "$1" 2>/dev/null | grep -qxi "$2"; then return 0; fi
  st group addmembers "$1" "$2" >/dev/null
  log "ajout de $2 au groupe $1"
}

seed_directory() {
  # Politique de mots de passe forte (S3) : complexité, 12 caractères min., historique,
  # verrouillage après 5 échecs (contre la force brute / pulvérisation de mots de passe).
  st domain passwordsettings set \
    --complexity=on --store-plaintext=off \
    --min-pwd-length=12 --history-length=24 \
    --min-pwd-age=1 --max-pwd-age=90 \
    --account-lockout-threshold=5 --account-lockout-duration=30 \
    --reset-account-lockout-after=30 >/dev/null
  log "politique de mots de passe appliquée (12 car., complexité, verrouillage 5 échecs/30 min)."

  ensure_ou "$OU_ROOT"
  ensure_ou "$OU_USERS"
  ensure_ou "$OU_ADMINS"
  ensure_ou "$OU_GROUPS"
  ensure_ou "$OU_SVC"

  # F07 : seuls les membres de GG-ERP-Utilisateurs peuvent ouvrir une session Odoo (filtre LDAP)
  ensure_group "GG-ERP-Utilisateurs" "$OU_GROUPS" "Salariés autorisés sur l'ERP Odoo (F07)"
  # Comptes d'administration séparés (A3/E07) : GG-Admins est membre de « Domain Admins »
  ensure_group "GG-Admins" "$OU_GROUPS" "Administrateurs du SI (comptes adm.* dédiés)"
  ensure_member "Domain Admins" "GG-Admins"

  # Comptes de démonstration (mot de passe SAMBA_DEMO_USER_PASSWORD)
  ensure_user "alice.martin" "$SAMBA_DEMO_USER_PASSWORD" "$OU_USERS" "Alice" "Martin"
  ensure_user "bruno.durand" "$SAMBA_DEMO_USER_PASSWORD" "$OU_USERS" "Bruno" "Durand"
  ensure_user "chloe.petit"  "$SAMBA_DEMO_USER_PASSWORD" "$OU_USERS" "Chloé" "Petit"
  ensure_user "adm.claire"   "$SAMBA_DEMO_USER_PASSWORD" "$OU_ADMINS" "Claire" "Admin"
  ensure_member "GG-ERP-Utilisateurs" "alice.martin"
  ensure_member "GG-ERP-Utilisateurs" "bruno.durand"
  # chloe.petit n'est volontairement PAS dans GG-ERP-Utilisateurs (test de refus F07)
  ensure_member "GG-Admins" "adm.claire"

  # Compte de liaison LDAP d'Odoo : lecture seule de l'annuaire (droits d'un utilisateur standard),
  # mot de passe long sans expiration (compte de service), jamais utilisé en session interactive.
  ensure_user "svc-odoo-ldap" "$SAMBA_ODOO_BIND_PASSWORD" "$OU_SVC" "Service" "Odoo LDAP" \
    --description="Compte de liaison LDAP de l'ERP Odoo (F07) - lecture seule"
  st user setexpiry "svc-odoo-ldap" --noexpiry >/dev/null
}

# --------------------------------------------------------------------------- démarrage
provision
tls_setup
seed_directory

log "démarrage de samba (DC $DC_FQDN) — journaux d'audit dans /var/log/samba/samba.log"
exec samba --foreground --no-process-group -s "$CONF"
