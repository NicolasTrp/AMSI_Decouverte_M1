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

# ─────────────────────────────────────────────────────────────────────────────
# Cloisonnement de l'egress LAN vers l'HÔTE (durcissement, finding audit LOW).
#
# Le LAN sort sur internet UNIQUEMENT via le proxy du firewall. Mais comme la
# passerelle du pont LAN est l'hôte, les conteneurs LAN peuvent joindre les
# services NATIFS de l'hôte (sshd, web…) sur ses IP locales (ex. 172.17.0.1).
# On bloque donc, côté hôte, toute connexion NEW issue du subnet LAN à
# destination de l'hôte lui-même (chaîne INPUT). N'affecte PAS :
#   - le pivot DMZ↔LAN (chaîne FORWARD), - le proxy tinyproxy (= conteneur
#   firewall, pas l'hôte), - l'intra-LAN, - le port web publié (source externe).
# Idempotent. Scopé au LAN_SUBNET du .env (autonome). Sous le launcher CTFd,
# chaque équipe a un subnet 172.30.<101+2·slot>.0/24 → couvrir 172.30.0.0/16.
# ─────────────────────────────────────────────────────────────────────────────
if [ "$(id -u)" = "0" ] && command -v iptables >/dev/null 2>&1; then
    ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
    LAN_SUBNET="172.31.20.0/24"
    [ -f "$ROOT_DIR/.env" ] && LAN_SUBNET="$(grep -E '^LAN_SUBNET=' "$ROOT_DIR/.env" | cut -d= -f2 | tr -d ' ' || true)"
    LAN_SUBNET="${LAN_SUBNET:-172.31.20.0/24}"
    for net in "$LAN_SUBNET" "172.30.0.0/16"; do
        if ! iptables -C INPUT -s "$net" -m conntrack --ctstate NEW -j DROP 2>/dev/null; then
            iptables -I INPUT -s "$net" -m conntrack --ctstate NEW -j DROP 2>/dev/null || true
        fi
    done
    echo "[host-net] egress LAN→hôte bloqué (INPUT DROP NEW depuis ${LAN_SUBNET} + 172.30.0.0/16)."
fi
