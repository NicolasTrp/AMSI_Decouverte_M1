#!/bin/sh
# entrypoint admin (workstation) — pose les flags PER INSTANCE puis lance sshd.
# RESTART-SAFE.
set -eu

FLAG_WS_ROOT="${FLAG_WS_ROOT:-AMSI_dev_ws_root}"
FLAG_FINAL="${FLAG_FINAL:-AMSI_dev_final}"

mkdir -p /opt/shopxpress /var/log/supervisor

# --- [Pwn] FLAG_WS_ROOT : root uniquement (après exploitation de vault) ------
printf '%s\n' "$FLAG_WS_ROOT" > /root/flag_root.txt
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt

# --- [Reverse] trophée final : lu par backoffice-check (SUID) si master correct
cat > /opt/shopxpress/trophy <<EOF
=== ACCES BACK-OFFICE ShopXpress — COMPROMISSION COMPLETE ===
$FLAG_FINAL
EOF
chmod 600 /opt/shopxpress/trophy; chown root:root /opt/shopxpress/trophy

# --- comptes / SSH ----------------------------------------------------------
# root VERROUILLÉ : pas de mot de passe → aucun `su root` ni login root. Les seules
# voies root prévues sont le pwn (vault) et le reverse (backoffice-check). Poser un
# mot de passe root ici (script world-readable) court-circuiterait les DEUX.
passwd -l root >/dev/null 2>&1 || true
ssh-keygen -A >/dev/null 2>&1 || true
# j.martin se connecte par CLÉ (clé privée lootée sur fileshare).

echo "[admin] poste admin prêt — vault (pwn) + backoffice-check (reverse) armés, flags posés."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
