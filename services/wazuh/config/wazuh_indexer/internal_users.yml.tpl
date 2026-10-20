---
# OSTRAL — comptes LOCAUX du SIEM (E08) : base interne de l'indexer, AUCUN lien avec l'AD.
# Modèle rendu par scripts/init-users.sh (hashs bcrypt calculés à partir du .env).
# Les comptes de démonstration d'OpenSearch (kibanaro, logstash, readall, snapshotrestore)
# sont volontairement supprimés (réduction de surface).
# ATTENTION : ce fichier n'est lu qu'à l'initialisation de l'index de sécurité (1er démarrage).
# Pour changer un mot de passe ensuite : voir services/wazuh/README.md.

_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "__ADMIN_HASH__"
  reserved: true
  backend_roles:
  - "admin"
  description: "OSTRAL - administrateur local du SIEM (utilise aussi par Filebeat du manager)"

kibanaserver:
  hash: "__KIBANASERVER_HASH__"
  reserved: true
  description: "OSTRAL - compte technique du Wazuh dashboard"
