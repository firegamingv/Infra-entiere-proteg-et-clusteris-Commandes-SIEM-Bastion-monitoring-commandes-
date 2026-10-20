# OSTRAL — maquette de l'architecture sécurisée

Projet M2 Cybersécurité EFREI 2026 : mise en œuvre, sous Docker Compose, de l'architecture cible
définie dans le dossier « OSTRAL — Ateliers 1 à 3 » (PME fictive de mobilier en ligne).

La maquette reproduit les 9 zones Z0 à Z8, la matrice de flux F01 à F18 et les exigences E01 à E12.
On y retrouve :
- un WAF ModSecurity en DMZ ;
- le mTLS entre la boutique et l'ERP ;
- l'administration par VPN, bastion, MFA et sessions enregistrées ;
- le SIEM Wazuh et la supervision Uptime Kuma ;
- les sauvegardes 3-2-1-1-0 en mode pull, avec une copie hors site non modifiable ;
- le durcissement des conteneurs, contrôlé avec Trivy.

## Démarrage rapide

Prérequis : Docker Desktop (WSL2) ou Docker Engine avec Compose v2, Git Bash, openssl.
Prévoir environ 6 Go de RAM libres sans SIEM et environ 11 Go avec.

```bash
bash scripts/init.sh            # version légère
```

```bash
bash scripts/init.sh --siem     # avec Wazuh
```

Ajouter ensuite `127.0.0.1 ostral.local` au fichier hosts, puis ouvrir https://ostral.local.
L'autorité de certification à approuver est `certs/ca.crt`.

## Vérifications

| Script | Ce qu'il vérifie |
|--------|------------------|
| `scripts/demo-securite.sh` | **Démo de soutenance** : 8 attaques réalistes, la mesure qui bloque chacune, puis les alertes Wazuh |
| `scripts/test-flux.sh` | La matrice de flux F01 à F18, flux autorisés comme flux bloqués |
| `scripts/test-waf.sh` | Le blocage des attaques web (403), la limitation de débit (429) et la configuration TLS |
| `scripts/trivy-scan.sh` | Les vulnérabilités critiques des images et la configuration (E12) |
| `scripts/test-restore.sh` | La restauration de la base ERP ; avec `--erp-down`, la file de commandes pendant une panne de l'ERP (R2) |

## Organisation

| Chemin | Contenu |
|--------|---------|
| `docker-compose.yml` | Zones réseau (fichier de base) |
| `compose/` | Un fragment par zone, fusionnés via `COMPOSE_FILE` (voir `.env.example`) |
| `services/` | Images, configurations et scripts de chaque service |
| `scripts/` | Amorçage, PKI et tests |
| `docs/` | Architecture, traçabilité, démonstration, exploitation |
| `SPEC.md` | Contrat technique : réseaux, adresses IP, noms de services |

Pour aller plus loin : [docs/architecture.md](docs/architecture.md), [docs/tracabilite.md](docs/tracabilite.md),
[docs/demo.md](docs/demo.md), [docs/exploitation.md](docs/exploitation.md).

## Limites connues

- Maquette démarrée et testée le 19/10/2026 sous Docker Desktop 29.8 (Windows 11, WSL2, 8 Go). Résultats :
  - matrice de flux conforme : 79 tests OK, 0 KO (`test-flux.sh`) ;
  - WAF conforme : 25/25 (`test-waf.sh`) ;
  - parcours d'achat de bout en bout, de la commande à Odoo en mTLS (`test-commande.py`) ;
  - panne de l'ERP : la commande reste en file d'attente puis arrive dans Odoo au redémarrage (R2) ;
  - sauvegardes horaire et nocturne, puis restauration vérifiée en 16 s ;
  - alertes Wazuh déclenchées : campagne d'injections au niveau 10, rafale de 429.
  Détails : section « Bilan du premier lancement » de `docs/exploitation.md`.
- Trivy bloque encore 8 images tierces (MinIO, Guacamole web, Uptime Kuma, Postgres officiel,
  Wazuh) : il faut attendre les versions corrigées des éditeurs. Toutes les images construites
  par le projet sont saines.
- Écarts assumés avec la cible : les pare-feux FW1 et FW2 sont modélisés par l'appartenance aux
  réseaux et non par deux pare-feux d'éditeurs différents ; il n'y a ni tunnel IPsec, ni PRA cloud,
  ni sonde IDS Suricata ; le « cloud » est simulé en local. Le détail figure dans `docs/architecture.md`.
# Infra-entiere-proteg-et-clusteris-Commandes-SIEM-Bastion-monitoring-commandes-
