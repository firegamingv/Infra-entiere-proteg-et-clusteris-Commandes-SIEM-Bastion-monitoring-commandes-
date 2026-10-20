# OSTRAL — serveur de sauvegarde Z7 (lot E) : mode pull (F16), 3-2-1-1-0 (E09), copie hors site (F17)
# Image minimale Alpine (tag fixé, E12 ; Alpine 3.24 : restic ≥ 0.17 requis pour --stdin-from-command), aucun secret dans l'image : tout vient du .env.
FROM alpine:3.24.2

# restic (dépôt chiffré AES-256 + empreintes SHA-256), client PostgreSQL 16 (pg_dump / pg_restore),
# serveur PostgreSQL 16 (instance jetable du test de restauration mensuel, socket Unix uniquement),
# client SSH (pull F16), mcli (client MinIO : copie vers le stockage objet verrouillé F17),
# supercronic (cron pour conteneurs, non-root), jq (journal JSON pour Wazuh), tzdata.
RUN apk add --no-cache \
      restic \
      postgresql16-client \
      postgresql16 \
      postgresql16-contrib \
      openssh-client-default \
      minio-client \
      supercronic \
      jq \
      tzdata \
      ca-certificates \
 && addgroup -S -g 10001 backup \
 && adduser -S -D -H -u 10001 -G backup -h /var/lib/backup -s /sbin/nologin backup \
 && mkdir -p /repo /var/lib/backup/ssh /var/lib/backup/scratch /var/log/backup /etc/backup \
 && chown -R 10001:10001 /repo /var/lib/backup /var/log/backup \
 && chmod 0700 /repo /var/lib/backup/ssh /var/lib/backup/scratch \
 && chmod 0750 /var/log/backup

COPY --chmod=0755 scripts/ /usr/local/bin/
COPY --chmod=0644 crontab /etc/backup/crontab

ENV TZ=Europe/Paris \
    HOME=/tmp \
    RESTIC_REPOSITORY=/repo \
    RESTIC_CACHE_DIR=/var/lib/backup/scratch/restic-cache

USER 10001:10001
WORKDIR /var/lib/backup

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["cron"]
