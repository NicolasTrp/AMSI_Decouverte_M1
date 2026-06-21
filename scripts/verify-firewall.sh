#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify-firewall.sh — critères d'acceptation RÉSEAU du lab découverte.
#
# À lancer APRÈS `make up`. Asserte automatiquement les invariants de topologie :
#   1. firewall ROUTE (ip_forward=1, conteneur healthy) ............... DOIT être vrai
#   2. PIVOT DMZ→LAN ouvert : web → files:445 ET web → admin:22 ........ DOIT réussir
#   3. intra-LAN : files → admin:22 ................................... DOIT réussir
#   4. SEUL `web` est publié sur l'hôte (entrée unique des étudiants) .. DOIT être vrai
#   5. egress LAN : DIRECT interdit, via le proxy firewall autorisé .... DOIT être vrai
#   6. aucun conteneur privileged / aucun docker.sock monté ........... DOIT être vrai
#
# Contrairement au lab avancé, ici DMZ→LAN est VOULU ouvert (pivot débutant) :
# la segmentation tient au fait que SEUL `web` est publié.
#
# Sortie non nulle si un seul test échoue.
# ─────────────────────────────────────────────────────────────────────────────
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

# Variables (subnets / IP) depuis .env, sinon valeurs par défaut découverte.
if [ -f "$ROOT_DIR/.env" ]; then
    # shellcheck disable=SC1091
    set -a; . "$ROOT_DIR/.env"; set +a
fi
WEB_DMZ_IP="${WEB_DMZ_IP:-172.31.10.10}"
FILES_LAN_IP="${FILES_LAN_IP:-172.31.20.11}"
WORKSTATION_LAN_IP="${WORKSTATION_LAN_IP:-172.31.20.12}"
FIREWALL_LAN_IP="${FIREWALL_LAN_IP:-172.31.20.2}"
WEB_APP_PORT="${WEB_APP_PORT:-8080}"
WEB_PUBLISH_PORT="${WEB_PUBLISH_PORT:-8080}"
PROXY_PORT="${PROXY_PORT:-8888}"
PROXY="http://${FIREWALL_LAN_IP}:${PROXY_PORT}"

# Détection compose v1/v2 (comme le Makefile).
if docker compose version >/dev/null 2>&1; then DC=(docker compose); else DC=(docker-compose); fi
dc(){ "${DC[@]}" -f "$ROOT_DIR/docker-compose.yml" "$@"; }

# Résolution des conteneurs : container_name non figé (multi-instance). On demande
# à compose le vrai nom ; repli sur les noms du projet par défaut.
WEB="$(dc ps -q web 2>/dev/null)";   FW="$(dc ps -q firewall 2>/dev/null)"
FILES="$(dc ps -q files 2>/dev/null)"; WS="$(dc ps -q workstation 2>/dev/null)"
P="$(basename "$ROOT_DIR")"
: "${WEB:=${P}_web_1}" "${FW:=${P}_firewall_1}" "${FILES:=${P}_files_1}" "${WS:=${P}_workstation_1}"

PASS=0; FAIL=0
ok()   { printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
ko()   { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
head() { printf '\n\033[1m%s\033[0m\n' "$1"; }

# Connexion TCP testée en python3 (présent dans tous les conteneurs du lab).
# `-i` indispensable : sans lui, docker exec ne transmet pas le heredoc → `python3 -`
# lirait un stdin vide et ne produirait aucune sortie.
tcp_try() { # <container> <ip> <port> <timeout_s>
    docker exec -i "$1" python3 - "$2" "$3" "$4" <<'PY' 2>/dev/null
import socket, sys
ip, port, t = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
s = socket.socket(); s.settimeout(t)
try:
    s.connect((ip, port)); print("CONNECTED"); sys.exit(0)
except Exception as e:
    print("BLOCKED:%s" % type(e).__name__); sys.exit(1)
PY
}

# ── Préflight — pré-requis réseau de l'hôte ─────────────────────────────────
head "Préflight — net.bridge.bridge-nf-call-iptables = 0 (requis pour le routage)"
bnf="$(sysctl -n net.bridge.bridge-nf-call-iptables 2>/dev/null || echo '?')"
if [ "$bnf" = "0" ]; then
    ok "bridge-nf-call-iptables = 0 (routage DMZ↔LAN possible)"
else
    ko "bridge-nf-call-iptables = ${bnf} — lancez 'make host-setup' (sinon le pivot échoue)"
fi

# ── Test 1 — le firewall route (ip_forward + healthy) ───────────────────────
head "Test 1 — firewall actif : ip_forward=1 et conteneur healthy"
[ "$(docker exec "$FW" cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" = "1" ] \
  && ok "ip_forward = 1 sur le firewall (routeur L3 actif)" || ko "ip_forward != 1 (firewall ne route pas)"
hstatus="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$FW" 2>/dev/null)"
[ "$hstatus" = "healthy" ] && ok "firewall healthy ($hstatus)" || ko "firewall non healthy ($hstatus)"

# ── Test 2 — PIVOT DMZ→LAN ouvert (web atteint le LAN) ──────────────────────
head "Test 2 — PIVOT : web (DMZ) → LAN doit RÉUSSIR (volontairement ouvert)"
out="$(tcp_try "$WEB" "$FILES_LAN_IP" 445 5)"
[ "$out" = "CONNECTED" ] && ok "web → files:445 (SMB) joignable [pivot OK]" \
  || ko "web → files:445 bloqué [${out:-timeout}] — le pivot est cassé"
out="$(tcp_try "$WEB" "$WORKSTATION_LAN_IP" 22 5)"
[ "$out" = "CONNECTED" ] && ok "web → admin:22 (SSH) joignable [pivot OK]" \
  || ko "web → admin:22 bloqué [${out:-timeout}] — le pivot est cassé"

# ── Test 3 — intra-LAN (files → admin) ──────────────────────────────────────
head "Test 3 — intra-LAN : files → admin:22 doit RÉUSSIR (loot clé SSH)"
out="$(tcp_try "$FILES" "$WORKSTATION_LAN_IP" 22 5)"
[ "$out" = "CONNECTED" ] && ok "files → admin:22 joignable (rebond clé SSH possible)" \
  || ko "files → admin:22 bloqué [${out:-timeout}]"

# ── Test 4 — un SEUL service publié sur l'hôte : web ────────────────────────
head "Test 4 — SEUL \`web\` publié (point d'entrée unique des étudiants)"
pub_web="$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$WEB" 2>/dev/null)"
[ -n "$pub_web" ] && ok "web publié sur l'hôte (${pub_web% })" || ko "web n'est PAS publié (point d'entrée manquant!)"
leak=""
for pair in "firewall:$FW" "files:$FILES" "workstation:$WS"; do
    name="${pair%%:*}"; c="${pair#*:}"
    pb="$(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{if $b}}{{$p}} {{end}}{{end}}' "$c" 2>/dev/null)"
    [ -n "$pb" ] && leak="${leak} ${name}(${pb% })"
done
[ -z "$leak" ] && ok "ni firewall ni files ni workstation ne sont publiés (segmentation OK)" \
  || ko "service(s) interne(s) publié(s) sur l'hôte :${leak}"

# ── Test 5 — egress LAN : direct interdit, via firewall autorisé ────────────
head "Test 5 — egress LAN (files) : DIRECT interdit, via proxy firewall AUTORISÉ"
if docker exec "$FILES" curl -fsS -m 6 --noproxy '*' -o /dev/null "http://1.1.1.1/" 2>/dev/null; then
    ko "files : egress DIRECT vers internet possible (devrait passer par le firewall)"
else
    ok "files : egress direct bloqué (LAN internal, pas de route hors LAN)"
fi
code="$(docker exec "$FILES" curl -s -m 12 -o /dev/null -w '%{http_code}' -x "$PROXY" "http://1.1.1.1/" 2>/dev/null)"
[ -n "$code" ] && [ "$code" != "000" ] \
  && ok "files : egress via firewall OK (proxy ${PROXY}, http=${code})" \
  || ko "files : egress via firewall KO (proxy ${PROXY} injoignable, http='${code:-000}')"

# ── Test 6 — posture : pas de privileged / pas de docker.sock ───────────────
head "Test 6 — aucun conteneur privileged, aucun docker.sock monté"
priv_bad=""; sock_bad=""
for c in $(dc ps -q 2>/dev/null); do
    [ -z "$c" ] && continue
    cname="$(docker inspect -f '{{.Name}}' "$c" | sed 's#^/##')"
    priv="$(docker inspect -f '{{.HostConfig.Privileged}}' "$c")"
    [ "$priv" = "true" ] && priv_bad="${priv_bad} ${cname}"
    if docker inspect -f '{{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}' "$c" | grep -q 'docker.sock'; then
        sock_bad="${sock_bad} ${cname}"
    fi
done
[ -z "$priv_bad" ] && ok "aucun conteneur en privileged" || ko "privileged détecté :${priv_bad}"
[ -z "$sock_bad" ] && ok "aucun montage docker.sock" || ko "docker.sock monté :${sock_bad}"

# ── Bilan ───────────────────────────────────────────────────────────────────
head "Bilan : ${PASS} OK / ${FAIL} FAIL"
[ "$FAIL" -eq 0 ] || exit 1
echo "Tous les critères réseau du lab découverte sont verts."
