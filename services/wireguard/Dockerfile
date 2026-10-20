# OSTRAL — lot D — point d'entrée VPN WireGuard (Z6 / rôle FW1 pour l'administration, F09)
# Image dérivée de l'image linuxserver (tag de version fixé, E12) : on y COPIE les scripts
# personnalisés plutôt que de les monter, car l'image refuse les scripts de /custom-cont-init.d
# qui ne sont pas possédés par root ou qui sont modifiables par d'autres (cas des montages
# depuis Windows / Docker Desktop, vus en 0777).
FROM linuxserver/wireguard:1.0.20260223-r0-ls126

# Règles iptables FW1 (F09, E06, E07) appliquées à l'initialisation du conteneur.
COPY --chmod=0755 custom-cont-init.d/ /custom-cont-init.d/
# Service de journalisation (connexions des pairs, refus du pare-feu) vers logs_wireguard (E08).
COPY --chmod=0755 custom-services.d/ /custom-services.d/
