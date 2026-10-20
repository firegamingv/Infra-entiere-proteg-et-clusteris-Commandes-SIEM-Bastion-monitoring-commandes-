#!/bin/sh
# OSTRAL — E08 : applique la politique ISM « 90 jours consultables » aux index d'alertes Wazuh.
#  - crée (ou met à jour) la politique ostral-retention-90j ;
#  - la rattache aux index wazuh-alerts-* / wazuh-archives-* déjà existants
#    (les nouveaux index la reçoivent automatiquement via ism_template).
# Rejouable : docker compose --profile siem run --rm wazuh-ism-init
set -eu

URL="${INDEXER_URL:-https://10.10.7.21:9200}"
POLICY_ID="ostral-retention-90j"
POLICY_FILE="${ISM_POLICY_FILE:-/ostral/ostral-retention-90j.json}"
CA=/ostral/root-ca.pem
: "${INDEXER_PASSWORD:?INDEXER_PASSWORD manquant}"
USERNAME="${INDEXER_USERNAME:-admin}"

# Identifiants passés par un fichier de config curl (jamais en argument de ligne de commande)
CFG="$(mktemp 2>/dev/null || echo /tmp/curl.cfg)"
trap 'rm -f "$CFG"' EXIT
# shellcheck disable=SC2016
printf 'user = "%s:%s"\n' "$USERNAME" "$(printf '%s' "$INDEXER_PASSWORD" | sed 's/[\\"]/\\&/g')" > "$CFG"

api() { # api METHODE CHEMIN [fichier-ou-json]
  if [ $# -ge 3 ]; then
    curl -sS --cacert "$CA" -K "$CFG" -H 'Content-Type: application/json' -X "$1" "$URL$2" -d "$3"
  else
    curl -sS --cacert "$CA" -K "$CFG" -X "$1" "$URL$2"
  fi
}

echo "[ism] attente de l'indexer et du plugin de sécurité..."
i=0
until api GET "/_cluster/health" 2>/dev/null | grep -q '"status":"\(green\|yellow\)"'; do
  i=$((i + 1))
  [ "$i" -ge 60 ] && { echo "[ism] indexer injoignable après 10 min" >&2; exit 1; }
  sleep 10
done

EXISTING="$(api GET "/_plugins/_ism/policies/$POLICY_ID" || true)"
if printf '%s' "$EXISTING" | grep -q '"_seq_no"'; then
  SEQ="$(printf '%s' "$EXISTING" | sed -n 's/.*"_seq_no":\([0-9]*\).*/\1/p')"
  TERM="$(printf '%s' "$EXISTING" | sed -n 's/.*"_primary_term":\([0-9]*\).*/\1/p')"
  echo "[ism] mise à jour de la politique $POLICY_ID (seq_no=$SEQ)"
  RES="$(api PUT "/_plugins/_ism/policies/$POLICY_ID?if_seq_no=$SEQ&if_primary_term=$TERM" "@$POLICY_FILE")"
else
  echo "[ism] création de la politique $POLICY_ID"
  RES="$(api PUT "/_plugins/_ism/policies/$POLICY_ID" "@$POLICY_FILE")"
fi
printf '%s\n' "$RES"
printf '%s' "$RES" | grep -q '"_id":"'"$POLICY_ID"'"' || { echo "[ism] échec d'enregistrement de la politique" >&2; exit 1; }

for pattern in 'wazuh-alerts-*' 'wazuh-archives-*'; do
  echo "[ism] rattachement aux index existants $pattern"
  api POST "/_plugins/_ism/add/$pattern" "{\"policy_id\":\"$POLICY_ID\"}" || true
  echo
done
echo "[ism] OK : alertes consultables 90 jours (E08)"
