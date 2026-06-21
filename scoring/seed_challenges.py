#!/usr/bin/env python3
"""
Seed idempotent des 10 challenges du lab DÉCOUVERTE « Licornia Parc » dans CTFd.

Calqué sur le seed de référence (/root/challmsi-ref/scoring/scripts/seed_challenges.py)
→ même mécanique : 10 challenges `dynamic` (500 pts dégressifs), flag de type `ctflab`
(dynamique par équipe, validé par le plugin), enchaînés via les *requirements* CTFd.

Différences DÉCOUVERTE :
  - Libellé = "<catégorie> · <utilisateur> @ <machine>" (on montre la CATÉGORIE pour
    guider des M1, mais AUCUN indice technique).
  - Catégorie CTFd = la machine (web / files / admin).
  - Chaînage en SPINE + BONUS : le tronc obligatoire débloque linéairement
    (WEB_RCE → WEB_ROOT → FILES_RECON → FILES_RCE → FILES_ROOT → WS_ROOT → FINAL) ;
    les 3 bonus (WEB_REVERSE=OSINT, DB_PIVOT=Forensique, DB_ROOT=Stégano) se
    débloquent mais NE bloquent personne (couverture de catégories sans cul-de-sac).

Idempotent : challenges retrouvés par leur clef d'étape (contenu du flag `ctflab`)
→ renommables sans doublon ni perte de solves.

Usage :
    python3 seed_challenges.py <ctfd_url> <admin_user> <admin_password>
"""

import json
import re
import sys
import urllib.request
import urllib.parse
import urllib.error
import http.cookiejar

INITIAL, DECAY, MINIMUM = 500, 20, 100

MISSION = (
    "## Licornia Parc — mission (découverte M1)\n\n"
    "Test d'intrusion **autorisé** sur un environnement **isolé et volontairement "
    "vulnérable**. Le parc expose un site vitrine en **DMZ** ; le réseau interne "
    "(**LAN**) héberge un partage de fichiers et le poste d'une administratrice.\n\n"
    "**Objectif :** partir du site public, compromettre `web`, **pivoter** vers le "
    "LAN, puis enchaîner jusqu'à la prise du domaine. Chaque flag `AMSI{…}` jalonne "
    "le chemin ; les flags du **tronc** débloquent l'étape suivante.\n\n"
    "**Point d'entrée :** déployez votre instance (« Mon Lab »), puis attaquez l'URL "
    "fournie. **Une Kali et bonne chance.**\n\n"
    "**Première cible :** `www-data` sur `web`."
)

# key | catégorie CTFd (machine) | catégorie pédago | utilisateur | machine | prérequis | description
CHALLENGES = [
    ("WEB_RCE",     "web",   "Web",            "www-data",  "web",   None,          MISSION),
    ("WEB_REVERSE", "web",   "OSINT",          "—",         "web",   "WEB_RCE",     ""),  # bonus
    ("WEB_ROOT",    "web",   "Privesc",        "root",      "web",   "WEB_RCE",     ""),
    ("FILES_RECON", "files", "Recon",          "invité",    "files", "WEB_ROOT",    ""),
    ("DB_PIVOT",    "files", "Forensique",     "—",         "files", "FILES_RECON", ""),  # bonus
    ("DB_ROOT",     "files", "Stéganographie", "—",         "files", "FILES_RECON", ""),  # bonus
    ("FILES_RCE",   "files", "Crypto",         "a.pommier", "files", "FILES_RECON", ""),
    ("FILES_ROOT",  "files", "Privesc",        "root",      "files", "FILES_RCE",   ""),
    ("WS_ROOT",     "admin", "Pwn",            "root",      "admin", "FILES_ROOT",  ""),
    ("FINAL",       "admin", "Reverse",        "root",      "admin", "WS_ROOT",     ""),
]


class CTFd:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cj = http.cookiejar.CookieJar()
        self.op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cj))
        self.nonce = None

    def _get(self, path):
        return self.op.open(self.base + path, timeout=15).read().decode()

    def _nonce(self, html):
        m = re.search(r"'csrfNonce':\s*\"([0-9a-f]+)\"", html) \
            or re.search(r'name="nonce"[^>]*value="([^"]+)"', html)
        return m.group(1) if m else None

    def login(self, user, pw):
        nonce = self._nonce(self._get("/login"))
        data = urllib.parse.urlencode(
            {"name": user, "password": pw, "nonce": nonce}).encode()
        self.op.open(self.base + "/login", data=data, timeout=15)
        self.nonce = self._nonce(self._get("/challenges"))

    def api(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + "/api/v1" + path, data=data,
                                     method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("CSRF-Token", self.nonce)
        try:
            return json.loads(self.op.open(req, timeout=15).read().decode())
        except urllib.error.HTTPError as e:
            return json.loads(e.read().decode() or "{}")


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        sys.exit(1)
    url, user, pw = sys.argv[1:4]
    c = CTFd(url)
    c.login(user, pw)
    if not c.nonce:
        print("[!] login échoué (identifiants admin ?).")
        sys.exit(2)

    # Index des challenges ctflab existants, PAR CLEF D'ÉTAPE (contenu du flag).
    existing = {}
    for ch in c.api("GET", "/challenges?view=admin").get("data", []):
        for f in c.api("GET", "/challenges/%d/flags" % ch["id"]).get("data", []):
            if f.get("type") == "ctflab":
                existing[(f.get("content") or "").strip().upper()] = ch["id"]

    by_key = {}
    for key, cat, pedago, tgt_user, machine, _prereq, desc in CHALLENGES:
        name = "%s · %s @ %s" % (pedago, tgt_user, machine)
        if key in existing:
            cid = existing[key]
            c.api("PATCH", "/challenges/%d" % cid,
                  {"name": name, "category": cat, "description": desc})
            print("~  maj   #%d  %-30s (%s)" % (cid, name, cat))
        else:
            r = c.api("POST", "/challenges", {
                "name": name, "category": cat, "description": desc,
                "type": "dynamic", "initial": INITIAL, "decay": DECAY,
                "minimum": MINIMUM, "function": "logarithmic", "state": "visible",
            })
            cid = r.get("data", {}).get("id")
            if not cid:
                print("[!] échec création", name, ":", r)
                continue
            c.api("POST", "/flags",
                  {"challenge_id": cid, "content": key, "type": "ctflab", "data": ""})
            print("+  créé  #%d  %s" % (cid, name))
        by_key[key] = cid

    # Chaînage : déblocage séquentiel (spine + bonus). Aucun texte, juste la dépendance.
    for key, _cat, _p, _u, _m, prereq, _d in CHALLENGES:
        if prereq and key in by_key and prereq in by_key:
            c.api("PATCH", "/challenges/%d" % by_key[key],
                  {"requirements": {"prerequisites": [by_key[prereq]]}})
    print("Terminé : %d challenges « catégorie · utilisateur @ machine », enchaînés "
          "(spine + 3 bonus), sans indice." % len(CHALLENGES))


if __name__ == "__main__":
    main()
