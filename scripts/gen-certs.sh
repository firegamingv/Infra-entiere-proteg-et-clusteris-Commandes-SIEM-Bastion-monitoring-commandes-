#!/usr/bin/env bash
# =============================================================================
# OSTRAL — Lot B : PKI interne de la maquette (E03 : TLS sur tous les flux
# exposés, mTLS entre le site et l'ERP — F01, F04).
#
# Génère dans certs/ (gitignoré) :
#   ca.crt / ca.key                     AC interne OSTRAL (racine, pathlen 0)
#   waf-public.crt / .key               F01 : vhost public ostral.local (serverAuth)
#   waf-erp-api.crt / .key              F04 : API ERP erp-api.ostral.internal + SAN waf (serverAuth)
#   boutique-client.crt / .key          F04 : certificat client mTLS CN=boutique (clientAuth)
#
# Clés EC P-256, SHA-256. AC : 5 ans ; feuilles : 397 jours.
# Idempotent : un fichier valide (signé par l'AC, non expiré) n'est pas régénéré.
# Si l'AC est (re)créée, toutes les feuilles sont réémises.
#
# Usage : scripts/gen-certs.sh [--force] [--out DIR] [--container-readable]
#   --force               supprime et régénère toute la PKI
#   --out DIR             répertoire de sortie (défaut : <racine>/certs)
#   --container-readable  clés des feuilles en 0644 au lieu de 0600 (hôte Linux
#                         uniquement : nginx tourne en uid 101 dans le conteneur
#                         et doit pouvoir lire les clés montées en lecture seule).
#                         ca.key reste toujours en 0600. Inutile sous Docker Desktop.
#                         NB : boutique-client.key est toujours en 0644 (lu par l'uid
#                         1000 du conteneur boutique via bind mount, cf. plus bas).
#
# Fonctionne sous Linux, macOS et Git Bash (Windows) : les sujets sont passés
# par fichier de configuration (pas de -subj "/CN=..." converti en chemin par MSYS).
# =============================================================================
set -euo pipefail

# Git Bash (Windows) : on n'utilise volontairement PAS -subj "/C=FR/CN=..." (que MSYS
# convertirait en chemin Windows) mais des fichiers de configuration openssl. On garde
# donc la conversion automatique des chemins MSYS active : elle est nécessaire pour que
# l'openssl natif Windows (mingw64) trouve les fichiers de /tmp ou /c/... .
# (Ne pas exporter MSYS_NO_PATHCONV=1 ici : les chemins POSIX ne seraient plus traduits.)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUT_DIR="${ROOT_DIR}/certs"
FORCE=0
LEAF_KEY_MODE=600

CA_DAYS=1825
LEAF_DAYS=397
ORG="OSTRAL"
COUNTRY="FR"

usage() { sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1 ;;
    --out) shift; [ $# -gt 0 ] || { echo "--out requiert un argument" >&2; exit 2; }; OUT_DIR="$1" ;;
    --container-readable) LEAF_KEY_MODE=644 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

command -v openssl >/dev/null 2>&1 || { echo "openssl introuvable" >&2; exit 1; }

umask 077
mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}" 2>/dev/null || true

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

log() { printf '[gen-certs] %s\n' "$*"; }

# Numéro de série aléatoire (128 bits, premier octet forcé < 0x80 pour rester positif)
serial() { printf '0x%s' "$(openssl rand -hex 16 | sed 's/^[89a-fA-F]/7/')"; }

new_key() { # $1 = chemin de la clé
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
}

# Vrai si le certificat $1 existe, est signé par l'AC et valide encore au moins 30 jours
cert_ok() { # $1 = crt, $2 = key
  [ -s "$1" ] && [ -s "$2" ] || return 1
  openssl verify -CAfile "${OUT_DIR}/ca.crt" "$1" >/dev/null 2>&1 || return 1
  openssl x509 -in "$1" -noout -checkend 2592000 >/dev/null 2>&1 || return 1
  # La clé privée correspond bien au certificat
  local a b
  a="$(openssl x509 -in "$1" -noout -pubkey | openssl sha256)"
  b="$(openssl pkey -in "$2" -pubout | openssl sha256)"
  [ "$a" = "$b" ]
}

# ---------------------------------------------------------------- --force
if [ "${FORCE}" -eq 1 ]; then
  log "--force : suppression de la PKI existante dans ${OUT_DIR}"
  rm -f "${OUT_DIR}"/{ca,waf-public,waf-erp-api,boutique-client}.{crt,key}
fi

# ---------------------------------------------------------------- AC interne
CA_REGEN=0
if [ -s "${OUT_DIR}/ca.crt" ] && [ -s "${OUT_DIR}/ca.key" ] \
   && openssl x509 -in "${OUT_DIR}/ca.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
  log "AC existante conservée : ${OUT_DIR}/ca.crt"
else
  log "Création de l'AC interne OSTRAL"
  cat > "${TMP_DIR}/ca.cnf" <<EOF
[ req ]
prompt             = no
distinguished_name = dn
x509_extensions    = v3_ca
[ dn ]
C  = ${COUNTRY}
O  = ${ORG}
OU = PKI interne
CN = OSTRAL Internal CA
[ v3_ca ]
basicConstraints       = critical, CA:TRUE, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
EOF
  new_key "${OUT_DIR}/ca.key"
  openssl req -new -x509 -sha256 -days "${CA_DAYS}" -set_serial "$(serial)" \
    -config "${TMP_DIR}/ca.cnf" -key "${OUT_DIR}/ca.key" -out "${OUT_DIR}/ca.crt"
  CA_REGEN=1
fi
chmod 600 "${OUT_DIR}/ca.key"
chmod 644 "${OUT_DIR}/ca.crt"

# ---------------------------------------------------------------- feuilles
# issue NOM CN OU EKU SAN
issue() {
  local name="$1" cn="$2" ou="$3" eku="$4" san="$5"
  local crt="${OUT_DIR}/${name}.crt" key="${OUT_DIR}/${name}.key"

  if [ "${CA_REGEN}" -eq 0 ] && cert_ok "${crt}" "${key}"; then
    log "${name} : déjà valide, conservé"
    chmod "${LEAF_KEY_MODE}" "${key}"; chmod 644 "${crt}"
    return 0
  fi

  log "${name} : émission (CN=${cn}, EKU=${eku})"
  cat > "${TMP_DIR}/${name}.cnf" <<EOF
[ req ]
prompt             = no
distinguished_name = dn
[ dn ]
C  = ${COUNTRY}
O  = ${ORG}
OU = ${ou}
CN = ${cn}
[ ext ]
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature
extendedKeyUsage       = ${eku}
subjectAltName         = ${san}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
EOF
  new_key "${key}"
  openssl req -new -sha256 -config "${TMP_DIR}/${name}.cnf" -key "${key}" -out "${TMP_DIR}/${name}.csr"
  openssl x509 -req -sha256 -days "${LEAF_DAYS}" -set_serial "$(serial)" \
    -in "${TMP_DIR}/${name}.csr" -CA "${OUT_DIR}/ca.crt" -CAkey "${OUT_DIR}/ca.key" \
    -extfile "${TMP_DIR}/${name}.cnf" -extensions ext -out "${crt}" 2>/dev/null
  chmod "${LEAF_KEY_MODE}" "${key}"
  chmod 644 "${crt}"
}

# F01 : vhost public de la boutique
issue waf-public      "ostral.local"            "Z2 DMZ - WAF public"  "serverAuth" "DNS:ostral.local"
# F04 : API ERP exposée par le WAF sur z1_cloud (SNI erp-api.ostral.internal ou nom compose « waf »)
issue waf-erp-api     "erp-api.ostral.internal" "Z2 DMZ - API ERP"     "serverAuth" "DNS:erp-api.ostral.internal, DNS:waf"
# F04 : identité de la boutique pour le mTLS (seul CN accepté par le WAF)
issue boutique-client "boutique"                "Z1 Cloud - Boutique"  "clientAuth" "DNS:boutique"

# Maquette : la boutique (lot A) lit sa clé client via un bind mount en tant qu'uid 1000
# (utilisateur « node » du conteneur), différent du propriétaire du fichier sur l'hôte.
# On rend donc CE fichier lisible (0644). En production : secret géré par l'orchestrateur
# (Docker secrets / coffre) avec propriétaire = uid du service, mode 0400.
chmod 644 "${OUT_DIR}/boutique-client.key"

# ---------------------------------------------------------------- contrôle
log "Vérification de la chaîne de confiance"
openssl verify -CAfile "${OUT_DIR}/ca.crt" -purpose sslserver \
  "${OUT_DIR}/waf-public.crt" "${OUT_DIR}/waf-erp-api.crt"
openssl verify -CAfile "${OUT_DIR}/ca.crt" -purpose sslclient "${OUT_DIR}/boutique-client.crt"

log "PKI prête dans ${OUT_DIR}"
if [ "${LEAF_KEY_MODE}" = "600" ] && [ "$(uname -s)" = "Linux" ]; then
  log "Note (hôte Linux) : nginx tourne en uid 101 ; si le WAF ne peut pas lire ses clés,"
  log "relancer avec --container-readable ou : sudo chown 101 certs/waf-*.key"
fi
