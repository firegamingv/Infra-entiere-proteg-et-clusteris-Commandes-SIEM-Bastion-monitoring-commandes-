# OSTRAL — lot D — poste de travail simulé (Z8)
# Sert aux tests de la matrice de flux : F07 (poste -> ERP 8069 AUTORISÉ), F08 (poste -> AD
# AUTORISÉ), F13 (poste -> Internet BLOQUÉ), F15 (poste -> serveurs SSH/RDP BLOQUÉ).
# Base alpine 3.24 (3.20 en fin de vie depuis avril 2026), tag fixé (E12), utilisateur non-root.
FROM alpine:3.24.2

RUN apk add --no-cache curl netcat-openbsd openssh-client openldap-clients bind-tools \
                       ca-certificates tini \
 && adduser -D -u 1000 -s /bin/sh -g "Employe OSTRAL (poste Z8)" employe

COPY --chmod=0755 test-flux-poste.sh /usr/local/bin/test-flux-poste

USER employe
WORKDIR /tmp
ENV HOME=/tmp
ENTRYPOINT ["/sbin/tini", "--"]
# Reste en vie pour `docker compose exec poste ...`.
CMD ["/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait $!; done"]
