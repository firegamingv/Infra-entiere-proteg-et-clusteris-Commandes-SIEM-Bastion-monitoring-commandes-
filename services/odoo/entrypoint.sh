#!/bin/bash
# OSTRAL — Lot C — entrypoint Odoo (Z3), utilisé par les services `odoo` et `odoo-init`.
#   - rend /run/odoo/odoo.conf à partir du gabarit + variables d'environnement (secrets hors image) ;
#   - `init` : initialisation idempotente de la base `ostral` (modules, compte api-boutique, clé API,
#     LDAP vers l'AD) puis sortie ;
#   - sinon : lance le serveur Odoo avec les arguments fournis.
# L'image officielle tourne déjà sous l'utilisateur non privilégié `odoo` (E12).
set -Eeuo pipefail

export ODOO_RC=/run/odoo/odoo.conf
python3 /opt/ostral/render_conf.py

if [[ "${1:-}" == "init" ]]; then
  shift
  exec bash /opt/ostral/init/odoo-init.sh "$@"
fi

# Tolère la commande par défaut de l'image (« odoo ») si elle est transmise
if [[ "${1:-}" == "odoo" ]]; then shift; fi
exec odoo -c "$ODOO_RC" "$@"
