#!/bin/sh
# ─────────────────────────────────────────────────────────────────────────────
# firewall.sh — routeur/pare-feu central du lab découverte.
#
# Objectif de filtrage (directionnel ET stateful) — VERSION DÉCOUVERTE :
#     DMZ → LAN : AUTORISÉ  (permet le PIVOT depuis web01 compromis)
#     LAN → DMZ : AUTORISÉ  (retour + accès web depuis le LAN)
#
# La leçon « segmentation » reste posée par l'infra : seul `web` est PUBLIÉ, donc
# l'étudiant n'atteint le LAN qu'APRÈS avoir compromis `web` et pivoté par lui.
# Le firewall est le SEUL chemin L3 entre `dmz` et `lan` (réseaux Docker isolés) ;
# il NAT les deux sens pour que ni `web` ni les hôtes LAN n'aient besoin de route
# retour spécifique.
#
# Détection des interfaces PAR SUBNET (eth0/eth1 ne sont pas garantis).
# ─────────────────────────────────────────────────────────────────────────────
set -eu

DMZ_SUBNET="${DMZ_SUBNET:-172.31.10.0/24}"
LAN_SUBNET="${LAN_SUBNET:-172.31.20.0/24}"
FIREWALL_LAN_IP="${FIREWALL_LAN_IP:-172.31.20.2}"
PROXY_PORT="${PROXY_PORT:-8888}"

log() { echo "[firewall] $*"; }

# --- 0. Backend iptables ----------------------------------------------------
if command -v iptables-legacy >/dev/null 2>&1 && iptables-legacy -L >/dev/null 2>&1; then
    IPT=iptables-legacy
elif iptables -L >/dev/null 2>&1; then
    IPT=iptables
else
    IPT=iptables-nft
fi
log "backend iptables = ${IPT}"

# --- 1. Détection des interfaces par subnet --------------------------------
prefix_of() { echo "$1" | sed -E 's#([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/[0-9]+#\1.#'; }
iface_for_prefix() {
    prefix="$1"
    ip -o -4 addr show | awk -v p="$prefix" '$4 ~ ("^" p) { print $2; exit }'
}

DMZ_PREFIX="$(prefix_of "$DMZ_SUBNET")"
LAN_PREFIX="$(prefix_of "$LAN_SUBNET")"

DMZ_IF=""; LAN_IF=""
i=0
while [ "$i" -lt 30 ]; do
    DMZ_IF="$(iface_for_prefix "$DMZ_PREFIX")"
    LAN_IF="$(iface_for_prefix "$LAN_PREFIX")"
    [ -n "$DMZ_IF" ] && [ -n "$LAN_IF" ] && break
    i=$((i + 1)); sleep 1
done
if [ -z "$DMZ_IF" ] || [ -z "$LAN_IF" ]; then
    log "ERREUR: interfaces introuvables (dmz='$DMZ_IF' lan='$LAN_IF')"
    ip -o -4 addr show; exit 1
fi
log "interface DMZ = ${DMZ_IF} (${DMZ_PREFIX}x)"
log "interface LAN = ${LAN_IF} (${LAN_PREFIX}x)"

# --- 2. Routage -------------------------------------------------------------
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    ( echo 1 > /proc/sys/net/ipv4/ip_forward ) 2>/dev/null || true
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    log "ERREUR: ip_forward != 1 — déclarez 'sysctls: net.ipv4.ip_forward=1' sur firewall."
    exit 1
fi
log "ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"

# --- 3. Règles de filtrage --------------------------------------------------
$IPT -F
$IPT -t nat -F

$IPT -P INPUT   ACCEPT
$IPT -P OUTPUT  ACCEPT
$IPT -P FORWARD DROP

# (a) Conntrack — retours établis dans les deux sens.
$IPT -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# (b) LAN → DMZ : NEW autorisé.
$IPT -A FORWARD -i "$LAN_IF" -o "$DMZ_IF" -m conntrack --ctstate NEW -j ACCEPT
# (c) DMZ → LAN : NEW autorisé (PIVOT depuis web01). En découverte on ouvre ce
#     sens ; la segmentation vient de « seul web est publié ».
$IPT -A FORWARD -i "$DMZ_IF" -o "$LAN_IF" -m conntrack --ctstate NEW -j ACCEPT

# (d) NAT bidirectionnel : chaque hôte voit la source comme l'IP du firewall sur
#     son propre subnet → aucune route retour à configurer côté hôtes.
$IPT -t nat -A POSTROUTING -o "$DMZ_IF" -s "$LAN_SUBNET" -j MASQUERADE
$IPT -t nat -A POSTROUTING -o "$LAN_IF" -s "$DMZ_SUBNET" -j MASQUERADE

log "règles appliquées :"
$IPT -S FORWARD | sed 's/^/[firewall]   /'
$IPT -t nat -S POSTROUTING | sed 's/^/[firewall]   /'
log "firewall opérationnel — DMZ↔LAN routé (pivot ouvert), seul web est publié."

# --- 4. Egress CONTRÔLÉ du LAN vers internet (proxy tinyproxy) --------------
PROXY_LOG=/var/log/tinyproxy/tinyproxy.log
mkdir -p /var/log/tinyproxy
chown root:tinyproxy /var/log/tinyproxy 2>/dev/null || true
chmod 0775 /var/log/tinyproxy 2>/dev/null || true
cat > /etc/tinyproxy/tinyproxy.conf <<EOF
User tinyproxy
Group tinyproxy
Port ${PROXY_PORT}
Listen ${FIREWALL_LAN_IP}
Timeout 600
LogFile "${PROXY_LOG}"
LogLevel Critical
PidFile "/run/tinyproxy.pid"
Allow ${LAN_SUBNET}
ConnectPort 443
ConnectPort 563
EOF
: > "${PROXY_LOG}" 2>/dev/null || true
chown tinyproxy:tinyproxy "${PROXY_LOG}" 2>/dev/null || true
chmod 0644 "${PROXY_LOG}" 2>/dev/null || true

log "egress LAN via proxy ${FIREWALL_LAN_IP}:${PROXY_PORT}. démarrage tinyproxy (avant-plan)."

# --- 5. tinyproxy en avant-plan = process principal (self-healing) ----------
exec tinyproxy -d
