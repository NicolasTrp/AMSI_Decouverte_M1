#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# host-net.sh — pré-requis réseau de l'HÔTE pour le lab (idempotent).
#
# Pose `net.bridge.bridge-nf-call-iptables=0`.
#
# POURQUOI : le LAN est un réseau Docker `internal: true`. Docker matérialise
# cette isolation par une règle hôte
#     DOCKER-ISOLATION-STAGE-1: -i br-lan -d !<LAN_SUBNET> -j DROP
# qui, tant que `bridge-nf-call-iptables=1`, s'applique AUSSI aux trames
# *bridgées* vers le conteneur firewall → elle casse le routage LAN↔DMZ qu'on
# veut autoriser (le pivot). En mettant le sysctl à 0, l'hôte cesse d'appliquer
# iptables aux trames de même pont ; le firewall (routeur L3 dans son propre
# netns) peut alors router LAN↔DMZ.
#
# Ce réglage NE diminue PAS la posture anti-escape (cap_drop, pas de
# privileged/socket). À lancer en root (fait par `make up`).
# ─────────────────────────────────────────────────────────────────────────────
set -eu

KEY="net.bridge.bridge-nf-call-iptables"
WANT=0

if [ ! -e "/proc/sys/${KEY//.//}" ]; then
    modprobe br_netfilter 2>/dev/null || true
fi

cur="$(sysctl -n "$KEY" 2>/dev/null || echo "?")"
if [ "$cur" = "$WANT" ]; then
    echo "[host-net] ${KEY} déjà à ${WANT}."
else
    sysctl -w "${KEY}=${WANT}"
    echo "[host-net] ${KEY} positionné à ${WANT} (était: ${cur})."
fi

PERSIST=/etc/sysctl.d/99-ctf-decouverte.conf
if [ "$(id -u)" = "0" ]; then
    printf '%s = %s\n' "$KEY" "$WANT" > "$PERSIST" 2>/dev/null \
        && echo "[host-net] persisté dans ${PERSIST}." \
        || echo "[host-net] (persistance ignorée : ${PERSIST} non inscriptible)."
fi
