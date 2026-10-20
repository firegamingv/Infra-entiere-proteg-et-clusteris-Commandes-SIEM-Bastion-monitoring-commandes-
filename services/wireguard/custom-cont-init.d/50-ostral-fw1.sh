#!/usr/bin/with-contenv bash
# shellcheck shell=bash
# =============================================================================
# OSTRAL — lot D — règles iptables du point d'entrée VPN (rôle FW1, flux F09)
#
# Exécuté par l'image linuxserver/wireguard à chaque démarrage, APRÈS la génération
# des configurations serveur/pairs et AVANT le démarrage de l'interface wg0.
#
# Politique (refus par défaut) :
#   - pairs administrateurs (admin1, admin2) : uniquement
#       bastion Guacamole      10.10.6.10:8080  (E06 : administration par le bastion)
#       console SIEM Wazuh     10.10.7.22:5601 (et 443 si le lot E publie la console sur 443)
#       supervision Uptime Kuma 10.10.7.30:3001
#   - pair prestataire (agenceweb, E07) : UNIQUEMENT le bastion 10.10.6.10:8080
#   - tout le reste (SSH direct, autres zones, pair à pair, routage z0<->z6/z7) : LOG + DROP
#
# L'identité d'un pair = son adresse dans le tunnel : WireGuard (cryptokey routing) n'accepte
# d'un pair que les paquets dont la source correspond à ses AllowedIPs côté serveur (/32),
# l'usurpation d'adresse entre pairs est donc impossible.
#
# Variables (voir env/d-admin.env.example) :
#   WG_ADMIN_DESTS       liste ip:port autorisée aux pairs administrateurs
#   WG_RESTRICTED_PEERS  pairs "prestataires" (noms séparés par des virgules)
#   WG_RESTRICTED_DESTS  liste ip:port autorisée aux pairs prestataires
# =============================================================================
set -euo pipefail

WG_IF="${WG_INTERFACE:-wg0}"
CONF_DIR="/config"
LOG_DIR="/var/log/wireguard"
ADMIN_DESTS="${WG_ADMIN_DESTS:-10.10.6.10:8080,10.10.7.22:5601,10.10.7.22:443,10.10.7.30:3001}"
RESTRICTED_PEERS="${WG_RESTRICTED_PEERS:-agenceweb}"
RESTRICTED_DESTS="${WG_RESTRICTED_DESTS:-10.10.6.10:8080}"
# Adresse du serveur dans le tunnel (INTERNAL_SUBNET, .1) : DNS CoreDNS de l'image (PEERDNS=auto).
SUBNET_BASE="${INTERNAL_SUBNET:-10.13.13.0}"
TUNNEL_IP="${SUBNET_BASE%.*}.1"

mkdir -p "$LOG_DIR"
chmod 0750 "$LOG_DIR"
JOURNAL="$LOG_DIR/fw1-regles.log"

horodatage() { date -u +%Y-%m-%dT%H:%M:%SZ; }
journal() { printf '%s ostral-fw1: %s\n' "$(horodatage)" "$*" | tee -a "$JOURNAL"; }

ipt() { iptables -w "$@"; }

# Journalisation limitée en débit pour ne pas saturer le journal noyau.
LOG_LIMIT=(-m limit --limit 20/min --limit-burst 40)

est_ipv4() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
est_port() { [[ "$1" =~ ^[0-9]{1,5}$ ]] && (( $1 >= 1 && $1 <= 65535 )); }

dans_liste() { # dans_liste <élément> <liste,séparée,par,virgules>
  local item="$1" liste=",${2// /},"
  [[ "$liste" == *",$item,"* ]]
}

# --- 1. Chaînes dédiées (idempotent : ré-exécution à chaque redémarrage) ----------------
for ch in OSTRAL_FW1 OSTRAL_WG_IN OSTRAL_WG_LOCAL; do
  ipt -N "$ch" 2>/dev/null || ipt -F "$ch"
done
while ipt -D FORWARD -j OSTRAL_FW1 2>/dev/null; do :; done
while ipt -D INPUT -i "$WG_IF" -j OSTRAL_WG_LOCAL 2>/dev/null; do :; done

# Les sauts sont insérés EN TÊTE : les règles ACCEPT ajoutées ensuite par le PostUp du modèle
# linuxserver (iptables -A FORWARD -i wg0 -j ACCEPT ...) ne sont donc jamais atteintes.
ipt -I FORWARD 1 -j OSTRAL_FW1
ipt -I INPUT 1 -i "$WG_IF" -j OSTRAL_WG_LOCAL
ipt -P FORWARD DROP

# --- 2. Chaîne principale de transit -----------------------------------------------------
ipt -A OSTRAL_FW1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A OSTRAL_FW1 -m conntrack --ctstate INVALID -j DROP
ipt -A OSTRAL_FW1 -i "$WG_IF" -j OSTRAL_WG_IN
# Aucune connexion NOUVELLE vers les clients VPN, et le conteneur ne route pas entre z0/z6/z7.
ipt -A OSTRAL_FW1 "${LOG_LIMIT[@]}" -j LOG --log-prefix "OSTRAL-FW1-DROP-FWD: "
ipt -A OSTRAL_FW1 -j DROP

# --- 3. Trafic local depuis le tunnel : DNS du tunnel + ping uniquement ------------------
ipt -A OSTRAL_WG_LOCAL -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A OSTRAL_WG_LOCAL -d "$TUNNEL_IP/32" -p udp --dport 53 -j ACCEPT
ipt -A OSTRAL_WG_LOCAL -d "$TUNNEL_IP/32" -p tcp --dport 53 -j ACCEPT
ipt -A OSTRAL_WG_LOCAL -d "$TUNNEL_IP/32" -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
ipt -A OSTRAL_WG_LOCAL "${LOG_LIMIT[@]}" -j LOG --log-prefix "OSTRAL-FW1-DROP-LOCAL: "
ipt -A OSTRAL_WG_LOCAL -j DROP

# --- 4. Règles par pair nominatif (E07) ---------------------------------------------------
nb_pairs=0
shopt -s nullglob
for conf in "$CONF_DIR"/peer_*/peer_*.conf; do
  nom="$(basename "$conf" .conf)"
  nom="${nom#peer_}"
  ip="$(awk -F'=' '/^[[:space:]]*Address[[:space:]]*=/ {
          gsub(/[[:space:]]/, "", $2); split($2, a, ","); split(a[1], b, "/"); print b[1]; exit }' "$conf")"
  if ! est_ipv4 "$ip"; then
    journal "AVERTISSEMENT pair=$nom adresse illisible dans $conf : aucun accès accordé"
    continue
  fi

  if dans_liste "$nom" "$RESTRICTED_PEERS"; then
    profil="prestataire"; destinations="$RESTRICTED_DESTS"
  else
    profil="administrateur"; destinations="$ADMIN_DESTS"
  fi

  # Préfixe LOG limité à 29 caractères par le noyau : nom tronqué.
  prefixe="OSTRAL-FW1-OK-${nom:0:12}: "
  IFS=',' read -r -a liste_dest <<< "${destinations// /}"
  for dest in "${liste_dest[@]}"; do
    [[ -z "$dest" ]] && continue
    hote="${dest%:*}"; port="${dest##*:}"
    if ! est_ipv4 "$hote" || ! est_port "$port"; then
      journal "AVERTISSEMENT destination invalide '$dest' ignorée (pair=$nom)"
      continue
    fi
    ipt -A OSTRAL_WG_IN -s "$ip/32" -d "$hote/32" -p tcp --dport "$port" \
        -m conntrack --ctstate NEW "${LOG_LIMIT[@]}" -j LOG --log-prefix "$prefixe"
    ipt -A OSTRAL_WG_IN -s "$ip/32" -d "$hote/32" -p tcp --dport "$port" \
        -m conntrack --ctstate NEW -j ACCEPT
  done
  journal "pair=$nom ip=$ip profil=$profil destinations=$destinations"
  nb_pairs=$((nb_pairs + 1))
done

# Refus par défaut : SSH/RDP direct, autres zones, pair à pair, pairs inconnus (E06, F09).
ipt -A OSTRAL_WG_IN "${LOG_LIMIT[@]}" -j LOG --log-prefix "OSTRAL-FW1-DROP: "
ipt -A OSTRAL_WG_IN -j DROP

# IPv6 : aucun transit (le tunnel est IPv4 uniquement).
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -w -P FORWARD DROP 2>/dev/null || true
fi

journal "règles FW1 appliquées : $nb_pairs pair(s), interface=$WG_IF, dns_tunnel=$TUNNEL_IP"
{ printf '%s ostral-fw1: --- iptables -S ---\n' "$(horodatage)"; iptables -w -S; } >> "$JOURNAL"
