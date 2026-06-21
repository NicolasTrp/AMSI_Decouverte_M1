#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# prebuild.sh — build des images PARTAGÉES du lab découverte (tags ctflab-dec-*).
#
# À lancer UNE fois (et après chaque modif d'un service). Le launcher réutilise
# ensuite ces images pour toutes les équipes via scoring/overrides.yml (pas de
# rebuild par équipe → déploiements rapides, disque mutualisé).
#
# Tags DÉDIÉS `ctflab-dec-*` → aucune collision avec les images `ctflab-*` du lab
# avancé : les deux labs cohabitent sur le même hôte.
# ─────────────────────────────────────────────────────────────────────────────
set -eu
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Détection compose v1/v2 (comme le Makefile).
if docker compose version >/dev/null 2>&1; then DC=(docker compose); else DC=(docker-compose); fi

echo "[prebuild] build des images ctflab-dec-* depuis ${ROOT_DIR}"
for svc in web firewall files workstation; do
    tag="ctflab-dec-${svc}:latest"
    echo "  → ${tag}"
    docker build -t "${tag}" "${ROOT_DIR}/services/${svc}"
done

echo "[prebuild] terminé. Images :"
docker images --filter 'reference=ctflab-dec-*' --format '  {{.Repository}}:{{.Tag}}  {{.Size}}'
echo
echo "Le launcher (avec scoring/overrides.yml) réutilisera ces images sans rebuild."
