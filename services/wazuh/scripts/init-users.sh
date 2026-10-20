#!/bin/bash
# OSTRAL — comptes LOCAUX du SIEM (E08) : le SIEM ne dépend pas de l'AD ; un attaquant
# maître de l'annuaire ne peut ni s'y connecter ni effacer ses traces.
#  - internal_users.yml : comptes admin et kibanaserver de l'indexer (hash bcrypt) ;
#  - wazuh.yml          : connexion du dashboard à l'API du manager (compte wazuh-wui).
# Exécuté dans l'image wazuh-indexer (outil hash.sh d'OpenSearch Security), sans réseau.
# Les fichiers produits (services/wazuh/generated/, gitignoré) contiennent des secrets.
set -euo pipefail

OUT=/ostral/generated
TPL=/ostral/internal_users.yml.tpl
HASH_TOOL=/usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh

: "${INDEXER_PASSWORD:?INDEXER_PASSWORD manquant}"
: "${DASHBOARD_PASSWORD:?DASHBOARD_PASSWORD manquant}"
: "${API_PASSWORD:?API_PASSWORD manquant}"
API_USERNAME="${API_USERNAME:-wazuh-wui}"

# Politique de mot de passe de l'API Wazuh : 8 à 64 caractères, majuscule, minuscule, chiffre, symbole
check_api_password() {
  local p="$1"
  if [ "${#p}" -lt 8 ] || [ "${#p}" -gt 64 ] \
     || ! [[ "$p" =~ [A-Z] ]] || ! [[ "$p" =~ [a-z] ]] || ! [[ "$p" =~ [0-9] ]] \
     || ! [[ "$p" =~ [^A-Za-z0-9] ]]; then
    echo "[wazuh-users] API_PASSWORD ne respecte pas la politique Wazuh (8-64 car., Aa, 0-9, symbole)" >&2
    exit 1
  fi
}
check_api_password "$API_PASSWORD"

for v in INDEXER_PASSWORD DASHBOARD_PASSWORD API_PASSWORD; do
  val="${!v}"
  if [ -z "$val" ] || [[ "$val" == CHANGEME* ]]; then
    echo "[wazuh-users] $v vaut encore la valeur d'exemple : à changer dans .env" >&2
    exit 1
  fi
done

bcrypt() {
  local h
  h="$(bash "$HASH_TOOL" -p "$1" 2>/dev/null | tail -n 1 | tr -d '\r')"
  if ! [[ "$h" =~ ^\$2[aby]\$[0-9]{2}\$.{53}$ ]]; then
    echo "[wazuh-users] échec du calcul de hash bcrypt (hash.sh)" >&2
    exit 1
  fi
  printf '%s' "$h"
}

mkdir -p "$OUT"
ADMIN_HASH="$(bcrypt "$INDEXER_PASSWORD")"
KIBANA_HASH="$(bcrypt "$DASHBOARD_PASSWORD")"

# Les hash bcrypt ne contiennent que [./$A-Za-z0-9] : remplacement sûr (délimiteur |)
sed -e "s|__ADMIN_HASH__|${ADMIN_HASH}|" -e "s|__KIBANASERVER_HASH__|${KIBANA_HASH}|" \
  "$TPL" > "$OUT/internal_users.yml.tmp"
mv "$OUT/internal_users.yml.tmp" "$OUT/internal_users.yml"
chown 1000:1000 "$OUT/internal_users.yml"   # UID wazuh-indexer
chmod 0600 "$OUT/internal_users.yml"

# Échappement YAML (chaîne entre guillemets doubles)
yaml_escape() { printf '%s' "$1" | sed 's/[\\"]/\\&/g'; }
cat > "$OUT/wazuh.yml.tmp" <<YML
# OSTRAL — généré par services/wazuh/scripts/init-users.sh (ne pas éditer, ne pas versionner)
# Compte LOCAL de l'API Wazuh (E08), indépendant de l'AD.
hosts:
  - 1513629884013:
      url: "https://10.10.7.20"
      port: 55000
      username: "$(yaml_escape "$API_USERNAME")"
      password: "$(yaml_escape "$API_PASSWORD")"
      run_as: true
YML
mv "$OUT/wazuh.yml.tmp" "$OUT/wazuh.yml"
chown 1000:1000 "$OUT/wazuh.yml"            # UID wazuh-dashboard
chmod 0600 "$OUT/wazuh.yml"

echo "[wazuh-users] internal_users.yml et wazuh.yml générés dans services/wazuh/generated/"
echo "[wazuh-users] rappel : internal_users.yml n'est appliqué qu'au 1er démarrage de l'indexer"
