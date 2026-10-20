# minio-offsite : stockage objet hors site verrouillé (F17, E09)

Ce service simule le « second fournisseur européen » (Z0 logique). Il n'est relié qu'au réseau `z7_offsite` (10.10.17.50:9000) : seul `backup` (10.10.17.40) peut le joindre. Il n'a pas de console web (`MINIO_BROWSER=off`).

- **Images utilisées :** `bitnamilegacy/minio:2025.7.23-debian-12-r5` et `bitnamilegacy/minio-client:2025.7.21-debian-12-r3`. Ce sont des images Bitnami figées, en non-root (UID 1001).
  Les dépôts `minio/minio` et `minio/mc` ne sont plus publiés sur Docker Hub (vérifié le 2026-10-19). Si un miroir interne les fournit, remplacer l'image et adapter les points suivants : `command: server /data`, le volume `/data` et le chemin de `mc`.
- **Initialisation :** le one-shot `minio-offsite-init` (`init-offsite.sh`) s'exécute à chaque `up` et peut être rejoué sans risque. Il :
  1. crée le bucket `ostral-backup-offsite` avec `--with-lock` (Object Lock, versionnage) ;
  2. applique une rétention par défaut **COMPLIANCE 30 jours** : personne, root compris, ne peut supprimer ou écraser une version avant son échéance ;
  3. crée l'utilisateur `MINIO_BACKUP_ACCESS_KEY` et lui attache la politique `policy-backup-writeonly.json`. Elle autorise `PutObject` et `List`, et refuse explicitement Delete*, la lecture et la modification du verrouillage, du versionnage ou des politiques ;
  4. vérifie que ce compte peut écrire mais pas supprimer.
- **Mode de rétention :** `MINIO_OFFSITE_RETENTION_MODE=GOVERNANCE` permet à root de contourner le verrouillage, ce qui peut servir à nettoyer la maquette. La valeur par défaut COMPLIANCE est conforme au dossier.
- **Remise à zéro de la maquette :** `docker compose down` puis `docker volume rm ostral_minio_offsite_data`. Cela revient à détruire physiquement le support, ce qui reste possible en dehors de l'API S3.
