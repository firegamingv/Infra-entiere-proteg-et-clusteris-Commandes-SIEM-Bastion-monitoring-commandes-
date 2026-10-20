#!/bin/bash
# OSTRAL — enveloppe idempotente de wazuh-certs-generator (one-shot du profil siem).
# Génère l'AC interne Wazuh et les certificats TLS indexer / manager / dashboard / admin
# dans services/wazuh/certs/ (gitignoré, E12) UNIQUEMENT s'ils n'existent pas encore :
# un « docker compose --profile siem up » ultérieur ne casse donc pas les certificats en place.
# Pour régénérer : supprimer services/wazuh/certs/ (et le volume wazuh_indexer_data).
set -euo pipefail

# Le certificat de l'AC est public : lisible par tous (le conteneur wazuh-ism-init tourne en
# uid 100 et doit pouvoir vérifier l'indexer). Les clés privées restent en 0400.
ca_public() { chmod 0444 /certificates/root-ca*.pem 2>/dev/null || true; }

if [ -s /certificates/root-ca.pem ] && [ -s /certificates/wazuh-indexer.pem ] \
   && [ -s /certificates/wazuh-manager.pem ] && [ -s /certificates/wazuh-dashboard.pem ] \
   && [ -s /certificates/admin.pem ]; then
  ca_public
  echo "[wazuh-certs] certificats déjà présents : rien à faire"
  exit 0
fi

echo "[wazuh-certs] génération des certificats internes Wazuh (outil officiel ${CERT_TOOL_VERSION:-?})"
/entrypoint.sh
ca_public
