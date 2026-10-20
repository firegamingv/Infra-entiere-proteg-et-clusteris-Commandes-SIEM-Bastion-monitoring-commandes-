#!/bin/sh
# =============================================================================
# OSTRAL — lot D — auto-test des flux depuis le poste Z8
#   docker compose exec poste test-flux-poste
# Vérifie, depuis l'intérieur de la zone Z8, que la matrice de flux est respectée :
#   F07  poste -> ERP Odoo (8069)               AUTORISÉ
#   F08  poste -> annuaire AD (53/88/389/636/445) AUTORISÉ
#   F13  poste -> Internet en direct            BLOQUÉ
#   F15  poste -> serveurs en SSH/RDP direct    BLOQUÉ (administration par le bastion, E06)
#        poste -> bastion / VPN / SIEM          BLOQUÉ (zone d'administration isolée)
# Code retour 0 si tous les résultats sont conformes. (Les tests complets de la maquette
# sont dans scripts/test-flux.sh, lot F.)
# =============================================================================
set -u

ODOO_IP="${ODOO_IP:-10.10.8.20}"        # odoo sur z8_postes
AD_IP="${AD_IP:-10.10.5.10}"            # samba-ad sur z5_identity
DELAI=3
ok=0; ko=0

tcp() { nc -z -w "$DELAI" "$1" "$2" >/dev/null 2>&1; }

attendu() { # attendu <AUTORISÉ|BLOQUÉ> <id> <description> <commande...>
  attente="$1"; id="$2"; desc="$3"; shift 3
  if "$@"; then obtenu="AUTORISÉ"; else obtenu="BLOQUÉ"; fi
  if [ "$obtenu" = "$attente" ]; then
    printf '[ OK ] %-4s %-50s %s\n' "$id" "$desc" "$obtenu"; ok=$((ok + 1))
  else
    printf '[ KO ] %-4s %-50s %s (attendu : %s)\n' "$id" "$desc" "$obtenu" "$attente"; ko=$((ko + 1))
  fi
}

attendu "AUTORISÉ" F07 "poste -> odoo $ODOO_IP:8069"            tcp "$ODOO_IP" 8069
attendu "AUTORISÉ" F08 "poste -> AD $AD_IP:88 (Kerberos)"        tcp "$AD_IP" 88
attendu "AUTORISÉ" F08 "poste -> AD $AD_IP:389 (LDAP)"           tcp "$AD_IP" 389
attendu "AUTORISÉ" F08 "poste -> AD $AD_IP:636 (LDAPS)"          tcp "$AD_IP" 636
attendu "AUTORISÉ" F08 "poste -> AD $AD_IP:53 (DNS)"             tcp "$AD_IP" 53

attendu "BLOQUÉ"   F13 "poste -> Internet https://example.com"   curl -s -o /dev/null -m "$DELAI" https://example.com
attendu "BLOQUÉ"   F13 "poste -> Internet 1.1.1.1:443"           tcp 1.1.1.1 443
attendu "BLOQUÉ"   F13 "poste -> Internet 9.9.9.9:53"            tcp 9.9.9.9 53

attendu "BLOQUÉ"   F15 "poste -> admin-target 10.10.3.30:22"     tcp 10.10.3.30 22
attendu "BLOQUÉ"   F15 "poste -> odoo $ODOO_IP:22 (SSH)"         tcp "$ODOO_IP" 22
attendu "BLOQUÉ"   F15 "poste -> odoo 10.10.3.20:3389 (RDP)"     tcp 10.10.3.20 3389
attendu "BLOQUÉ"   F15 "poste -> AD $AD_IP:22 (SSH)"             tcp "$AD_IP" 22
attendu "BLOQUÉ"   F15 "poste -> AD $AD_IP:3389 (RDP)"           tcp "$AD_IP" 3389
attendu "BLOQUÉ"   E06 "poste -> bastion 10.10.6.10:8080"        tcp 10.10.6.10 8080
attendu "BLOQUÉ"   E06 "poste -> guacd 10.10.6.11:4822"          tcp 10.10.6.11 4822
attendu "BLOQUÉ"   E08 "poste -> SIEM 10.10.7.22:5601"           tcp 10.10.7.22 5601

echo "----"
echo "Conformes : $ok   Non conformes : $ko"
[ "$ko" -eq 0 ]
