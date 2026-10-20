# OSTRAL — lot D — relais de DÉMONSTRATION vers le bastion (profil compose `demo`, désactivé
# par défaut). Uniquement si le VPN WireGuard ne peut pas être monté sur le poste de démo.
# Publie 127.0.0.1:8080 (boucle locale de l'hôte seulement) -> guacamole 10.10.6.10:8080.
# ATTENTION : contourne le VPN (F09) ; le MFA TOTP et l'enregistrement des sessions (E06)
# restent appliqués par le bastion. Ne jamais activer hors démonstration.
FROM alpine:3.24.2
RUN apk add --no-cache socat tini \
 && adduser -D -H -u 10001 -s /sbin/nologin relais
USER relais
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["socat", "TCP-LISTEN:8080,fork,reuseaddr,max-children=20", "TCP:10.10.6.10:8080"]
