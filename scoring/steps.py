"""
Les 10 étapes/flags du lab DÉCOUVERTE « ShopXpress » (M1).

⚠️ COMPATIBILITÉ PLUGIN — ce module reprend EXACTEMENT le contrat du plugin CTFd
`ctflab` de référence (cf. /root/challmsi-ref/scoring/plugin/ctflab/steps.py) :

  - `key` = identifiant d'étape stable, saisi côté challenge CTFd dans un flag de
    type `ctflab`. Les 10 clefs sont IDENTIQUES à la référence (WEB_RCE … FINAL) →
    le plugin valide sans modification.
  - `env` = nom EXACT de la variable d'environnement lue par les entrypoints du
    lab (services/*/entrypoint.sh). IDENTIQUES à la référence → le launcher pousse
    les 10 flags tels quels.
  - Le plugin reste l'AUTORITÉ : un jeton hex unique par équipe est généré, chaque
    flag en est dérivé déterministe `AMSI{<slug>_<jeton>}` (restart-safe), puis
    POUSSÉ au launcher. Le lab ne choisit jamais une valeur, il l'écrit.

SEULES différences avec la référence (cosmétique, sans impact sur la validation) :
  - `slug` : reflète la VULN DÉCOUVERTE (ex. `web_upload_php` au lieu de `web_rce`).
  - `cat`  : la catégorie pédagogique (Web, OSINT, Crypto…), pour l'affichage.
  - `user`/`machine` : la cible (utilisateur @ machine) du lab découverte (pas de
    machine `db` : les 2 flags `DB_*` sont matérialisés sur `files`).

Le slug est cosmétique (intérieur du flag) ; ce qui compte pour la compat plugin,
c'est que `key` et `env` soient figés et que le couple (plugin pousse / lab écrit)
soit cohérent — ce qui est le cas par construction.
"""

# key | env (figé) | slug (intérieur du flag) | catégorie | utilisateur cible | machine
STEPS = [
    ("WEB_RCE",     "FLAG_WEB_RCE",     "web_upload_php", "Web (upload RCE)", "www-data",  "web"),
    ("WEB_REVERSE", "FLAG_WEB_REVERSE", "web_lfi",        "Web (file read)",  "—",         "web"),
    ("WEB_ROOT",    "FLAG_WEB_ROOT",    "web_sudo_tar",   "Privesc",          "root",      "web"),
    ("FILES_RECON", "FLAG_FILES_RECON", "smb_anon",       "Recon",          "invité",    "files"),
    ("DB_PIVOT",    "FLAG_DB_PIVOT",    "pcap_clear",     "Forensique",     "—",         "files"),
    ("DB_ROOT",     "FLAG_DB_ROOT",     "stego_image",    "Stéganographie", "—",         "files"),
    ("FILES_RCE",   "FLAG_FILES_RCE",   "md5_rockyou",    "Crypto",           "s.morel",   "files"),
    ("FILES_ROOT",  "FLAG_FILES_ROOT",  "cron_writable",  "Privesc",        "root",      "files"),
    ("WS_ROOT",     "FLAG_WS_ROOT",     "bof_ret2win",    "Pwn",            "root",      "admin"),
    ("FINAL",       "FLAG_FINAL",       "reverse_xor",    "Reverse",        "root",      "admin"),
]

STEP_BY_KEY = {s[0]: s for s in STEPS}


def derive_flag(step_key, token):
    """AMSI{<slug>_<jeton>} — déterministe ; None si étape inconnue."""
    step = STEP_BY_KEY.get((step_key or "").strip().upper())
    if not step or not token:
        return None
    return "AMSI{%s_%s}" % (step[2], token)


def all_flags(token):
    """Dictionnaire {env_var: valeur} des 10 flags, pour le provisioning."""
    return {env: "AMSI{%s_%s}" % (slug, token)
            for (_key, env, slug, _cat, _u, _m) in STEPS}


def public_steps():
    """Étapes pour l'UI : catégorie + utilisateur cible + machine (aucun indice)."""
    return [{"key": k, "category": cat, "user": u, "machine": m}
            for (k, _e, _slug, cat, u, m) in STEPS]
