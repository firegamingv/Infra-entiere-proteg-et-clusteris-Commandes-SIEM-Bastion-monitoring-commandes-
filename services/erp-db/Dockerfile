# OSTRAL — Lot C — Base PostgreSQL de l'ERP (Z4, données sensibles, S2)
# Image officielle à tag fixé (E12). La seule surcouche crée le répertoire de journaux
# appartenant à l'utilisateur postgres : le volume nommé `logs_erp_db` hérite ainsi de ces
# droits au premier montage, ce qui permet de tourner en `user: postgres` avec cap_drop ALL
# tout en écrivant les journaux de connexion dans un volume lisible par le SIEM (E08).
FROM postgres:16.15-alpine3.24

# gosu (binaire Go) ne sert qu'à quitter root ; le conteneur tourne déjà en postgres :
# on le retire (CVE de la bibliothèque standard Go signalée par Trivy, E12).
RUN install -d -o postgres -g postgres -m 0750 /var/log/postgresql /etc/postgresql \
 && rm -f /usr/local/bin/gosu

# pg_hba.conf restrictif (F06) intégré à l'image : évite les soucis de droits des montages
# depuis un hôte Windows. Le fichier reste aussi versionné dans services/erp-db/.
COPY --chown=postgres:postgres --chmod=0640 pg_hba.conf /etc/postgresql/pg_hba.conf
# Scripts d'initialisation (exécutés une seule fois, à la création du volume de données)
COPY --chown=postgres:postgres --chmod=0750 init/ /docker-entrypoint-initdb.d/

USER postgres
