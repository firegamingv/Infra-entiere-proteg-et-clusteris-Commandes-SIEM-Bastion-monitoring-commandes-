#!/usr/bin/env bash
# OSTRAL — accès de DÉMONSTRATION aux interfaces internes depuis l'hôte (127.0.0.1 uniquement).
#
#   bash scripts/demo-acces.sh          # ouvre les relais
#   bash scripts/demo-acces.sh stop     # les ferme
#
# En cible, ces consoles ne sont joignables que par le VPN d'administration (F09) ou depuis un
# poste (F07, Odoo). Les réseaux des zones sont « internal » : Docker ne peut pas y publier de
# port. Chaque relais est un petit conteneur socat placé sur z0_internet (port publié sur la
# boucle locale) et sur la zone visée. Le MFA du bastion et l'authentification des consoles
# restent appliqués. À fermer après la démonstration.
set -euo pipefail
export MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.."

IMAGE=ostral/bastion-demo:1.0.0   # alpine + socat, non-root (services/guacamole/demo-proxy)

# nom | port hôte | réseau de la zone | cible
RELAIS=(
  "bastion|8080|z6_admin|10.10.6.10:8080"
  "wazuh|5601|z7_supervision|10.10.7.22:5601"
  "uptime-kuma|3001|z7_supervision|10.10.7.30:3001"
  "odoo|8069|z8_postes|10.10.8.20:8069"
)

arreter() {
  for r in "${RELAIS[@]}"; do
    docker rm -f "ostral-demo-${r%%|*}" >/dev/null 2>&1 || true
  done
}

if [ "${1:-}" = "mdp" ]; then
  # Affiche les identifiants de démonstration lus dans .env (fichier local, jamais versionné)
  grep -E '^(GUAC_ADMIN_PASSWORD|GUAC_ADMIN2_PASSWORD|GUAC_AGENCE_WEB_PASSWORD|INDEXER_PASSWORD|ODOO_WEB_ADMIN_PASSWORD|SAMBA_DEMO_USER_PASSWORD)=' .env
  echo "(bastion : admin1 = GUAC_ADMIN_PASSWORD, admin2 = GUAC_ADMIN2_PASSWORD, agence-web = GUAC_AGENCE_WEB_PASSWORD ;"
  echo " salariés AD alice.martin / bruno.durand = SAMBA_DEMO_USER_PASSWORD)"
  exit 0
fi

if [ "${1:-}" = "stop" ]; then
  arreter
  echo "Relais de démonstration fermés."
  exit 0
fi

docker image inspect "$IMAGE" >/dev/null 2>&1 || docker compose --profile demo build bastion-demo
arreter

for r in "${RELAIS[@]}"; do
  IFS='|' read -r nom port reseau cible <<<"$r"
  if [ "$nom" = "wazuh" ] && ! docker compose ps --status running --format '{{.Service}}' | grep -qx wazuh-dashboard; then
    echo "  (wazuh : profil siem non démarré, relais ignoré)"
    continue
  fi
  docker run -d --name "ostral-demo-$nom" --restart no \
    --network ostral_z0_internet -p "127.0.0.1:$port:$port" \
    --security-opt no-new-privileges:true --cap-drop ALL --memory 32m \
    "$IMAGE" socat "TCP-LISTEN:$port,fork,reuseaddr,max-children=20" "TCP:$cible" >/dev/null
  docker network connect "ostral_$reseau" "ostral-demo-$nom"
done

cat <<'FIN'

Relais ouverts (127.0.0.1 uniquement) :
  Boutique        https://ostral.local          (entrée hosts : 127.0.0.1 ostral.local)
  PSP simulé      http://localhost:4000         (s'ouvre au moment du paiement)
  Bastion         http://localhost:8080/        comptes admin1 / admin2 / agence-web, puis TOTP
  Wazuh           https://localhost:5601        compte admin / INDEXER_PASSWORD (certificat auto-signé)
  Uptime Kuma     http://localhost:3001         créer le compte au 1er accès, importer monitors-backup.json
  Odoo (poste Z8) http://localhost:8069         compte admin / ODOO_WEB_ADMIN_PASSWORD, ou salarié AD

Mots de passe : bash scripts/demo-acces.sh mdp
Fermer : bash scripts/demo-acces.sh stop
FIN
