#!/bin/sh
# entrypoint admin (workstation) — pose les flags PER INSTANCE puis lance sshd.
# RESTART-SAFE.
set -eu

FLAG_WS_ROOT="${FLAG_WS_ROOT:-AMSI_dev_ws_root}"
FLAG_FINAL="${FLAG_FINAL:-AMSI_dev_final}"

mkdir -p /opt/licornia /var/log/supervisor

# --- [Pwn] FLAG_WS_ROOT : root uniquement (après exploitation de vault) ------
printf '%s\n' "$FLAG_WS_ROOT" > /root/flag_root.txt
chmod 600 /root/flag_root.txt; chown root:root /root/flag_root.txt

# --- [Reverse] trophée final : lu par licornia-check (SUID) si master correct -
cat > /opt/licornia/trophy <<EOF
=== PRISE DU DOMAINE LICORNIA ===
$FLAG_FINAL
EOF
chmod 600 /opt/licornia/trophy; chown root:root /opt/licornia/trophy

# --- comptes / SSH ----------------------------------------------------------
# root VERROUILLÉ : pas de mot de passe → aucun `su root` ni login root. Les seules
# voies root prévues sont le pwn (vault) et le reverse (licornia-check). Poser un
# mot de passe root ici (script world-readable) court-circuiterait les DEUX.
passwd -l root >/dev/null 2>&1 || true
ssh-keygen -A >/dev/null 2>&1 || true
# c.vasseur se connecte par CLÉ (clé privée lootée sur fileshare).

echo "[admin] poste admin prêt — vault (pwn) + licornia-check (reverse) armés, flags posés."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/ctf.conf
