# OSTRAL — lot D — serveur Linux de démonstration en Z3 (admin-target, 10.10.3.30)
# Cible des flux F10 (bastion -> serveurs en SSH) et F16 (sauvegarde en mode pull, lecture seule).
# Image également réutilisée par le service one-shot guac-init (génération des clés, ssh-keygen).
#
# Base : alpine 3.24 (la branche 3.20 est en fin de vie depuis avril 2026 : plus de correctifs
# de sécurité ; on retient une branche maintenue, tag de version fixé — E12).
FROM alpine:3.24.2

RUN apk add --no-cache openssh-server openssh-keygen rsyslog rsync tar tini \
 # Comptes : ostral-admin (utilisé par le bastion, F10) et backup-ro (pull de sauvegarde, F16).
 && adduser -D -u 1000 -s /bin/sh -g "Compte d'administration (via bastion)" ostral-admin \
 && adduser -D -u 1001 -s /bin/sh -g "Sauvegarde en lecture seule (F16)" backup-ro \
 # Mot de passe "*" : aucune authentification par mot de passe possible, mais compte non
 # verrouillé ("!" ferait refuser aussi l'authentification par clé par sshd sans PAM).
 && printf 'ostral-admin:*\nbackup-ro:*\n' | chpasswd -e \
 # Pas de clé d'hôte dans l'image : elle est fournie par le volume admin_target_ssh (guac-init).
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /srv/data/erp-exports /srv/data/config /var/log/admin-target \
 && printf 'Données de démonstration OSTRAL (Z3) — sauvegardées en mode pull (F16).\n' > /srv/data/LISEZMOI.txt \
 && printf 'commande;client;montant\nSO001;Client démo;42.00\n' > /srv/data/erp-exports/commandes-demo.csv \
 && printf 'parametre=valeur\n' > /srv/data/config/application.conf \
 && chown -R root:root /srv/data && chmod -R u=rwX,go=rX /srv/data

COPY sshd_config /etc/ssh/sshd_config
COPY banner.txt /etc/ssh/banner.txt
COPY rsyslog.conf /etc/rsyslog.conf
COPY --chmod=0755 entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=0755 backup-ro.sh /usr/local/bin/backup-ro.sh

EXPOSE 22
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
