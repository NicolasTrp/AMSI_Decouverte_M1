# Scoring — lab découverte « Licornia Parc »

Deux façons de scorer, du plus simple au plus intégré. **Aucune ne modifie le
launcher ni le plugin CTFd de référence** : le lab respecte le même *contrat*
(mêmes noms de services, mêmes variables d'env, un seul service publié).

---

## Mode A — autonome (recommandé pour un TP simple)

Flags **statiques** lus depuis `.env` + validation automatique. Ni CTFd ni launcher.

```bash
make up           # build + démarre l'infra (172.31.x en autonome)
make test         # invariants réseau (verify-firewall.sh) — 12 OK attendus
make test-chain   # rejoue toute la chaîne d'attaque (verify-chain.sh) — 20 OK attendus
```

Les 10 flags sont ceux du `.env` (par défaut `AMSI{..._dev}`). Pour un événement,
éditez les `FLAG_*` du `.env` avant `make up`. La correction se fait à l'œil (les
joueurs soumettent leurs `AMSI{...}`) ou avec un CTFd « flag statique » classique.

---

## Mode B — plugin CTFd `ctflab` (multi-équipes, flags par équipe)

Réutilise **tel quel** le launcher générique et le plugin de référence
(`/root/challmsi-ref/scoring/`). Le plugin reste l'**autorité des flags** : un
jeton hex unique par équipe, 10 flags dérivés `AMSI{<slug>_<jeton>}`, **poussés**
au launcher qui les écrit dans l'instance.

### Pourquoi ça se branche SANS rien modifier

| Exigence du launcher/plugin | Statut dans ce lab |
|---|---|
| Services `web`/`firewall`/`files`/`workstation` | ✅ présents (mêmes noms) |
| Service `db` (listé dans `SERVICES`) | absent → simplement ignoré par `compose up` ; les 2 flags `FLAG_DB_*` sont matérialisés sur `files` |
| Variables `.env` (subnets, IP, `WEB_PUBLISH_*`, secrets) | ✅ noms **identiques** → `ensure_env()` paramètre tout |
| Un seul service publié (`web`) | ✅ seul `web` a `ports:` |
| 10 variables `FLAG_*` lues par les entrypoints | ✅ identiques (`steps.py`) |
| Secrets « bakés » à NE PAS randomiser | ✅ le launcher ne régénère QUE `JWT_SECRET/AGENT_HMAC_KEY/MACHINE_ID/DB_*_PASSWORD/SMB_PASSWORD/LDAP_BIND_PW` ; il laisse `ADMIN_MASTER_PW` (XOR du reverse) et `A_POMMIER_PW` (hash MD5 + base64 + SMB) **intacts** depuis `.env.example` → la chaîne reste cohérente par équipe |

> Vérifié dans `launcher.py:ensure_env()` : les valeurs dont dépendent les exploits
> (`ADMIN_MASTER_PW=twilight-sparkle-42`, `A_POMMIER_PW=applejack`) viennent de
> `.env.example` et ne sont jamais réécrites. C'est ce qui rend le lab découverte
> « plug-and-play » avec le launcher existant.

### Lancer une instance de launcher DÉDIÉE à ce lab

Le launcher est générique : on en lance une **2ᵉ instance** pointée sur ce lab,
avec un état/port/écoute **dédiés** (aucune collision avec le lab avancé) :

```bash
cd /root/challmsi-ref/scoring/launcher        # on réutilise le launcher de référence
export CTFLAB_LAB_DIR=/root/lab-ctf-decouverte-m1     # ← CE lab (compose + services + .env.example)
export CTFLAB_STATE_DIR=/root/challmsi-ref/scoring/lab-instances-dec   # état dédié (slots/.env par équipe)
export CTFLAB_PORT_BASE=32000                 # plage de ports hôte dédiée (≠ 31000 de l'avancé)
export CTFLAB_LISTEN_PORT=7071                # écoute dédiée (≠ 7070 de l'avancé)
export CTFLAB_HOST_IP=192.168.1.60            # IP annoncée aux équipes
export CTFLAB_CONTROL_TOKEN=...               # jeton Bearer partagé avec le plugin
python3 launcher.py
```

Dans CTFd, le plugin `ctflab` est configuré avec `CTFLAB_CONTROL_URL=http://<ip>:7071`.

### Images partagées + plafonds (optionnel mais conseillé)

```bash
./scoring/prebuild.sh        # build des images ctflab-dec-* (tags DÉDIÉS, 0 collision)
```

Pour que le launcher réutilise ces images (au lieu de rebuild par équipe) **et**
applique les plafonds mémoire/CPU, il faut qu'il charge `scoring/overrides.yml` de
ce lab. Le launcher de référence lit son override à côté de `launcher.py`
(`OVERRIDE = HERE/overrides.yml`). Deux options :

- **B1 — sans override (le plus simple)** : ne rien faire. Le launcher build les
  images par équipe depuis les `build:` du compose. Premier déploiement plus lent,
  mais zéro configuration.
- **B2 — override dédié (déploiements rapides)** : copier le launcher (1 fichier,
  générique) dans ce repo à côté de notre override, puis le lancer depuis là :
  ```bash
  mkdir -p /root/lab-ctf-decouverte-m1/scoring/launcher
  cp /root/challmsi-ref/scoring/launcher/launcher.py /root/lab-ctf-decouverte-m1/scoring/launcher/
  cp /root/lab-ctf-decouverte-m1/scoring/overrides.yml /root/lab-ctf-decouverte-m1/scoring/launcher/
  cd /root/lab-ctf-decouverte-m1/scoring/launcher && python3 launcher.py   # mêmes CTFLAB_* que ci-dessus
  ```

### ⚠️ Caveat sous-réseaux (à connaître)

Le launcher de référence **fixe en dur** la base `172.30.<100+2·slot>` pour les
subnets par équipe. Avec un `CTFLAB_STATE_DIR` dédié, les slots de ce lab repartent
à 0 → ils calculeraient les **mêmes** subnets `172.30.100+/172.30.101+` que le lab
avancé. **Tant que les deux familles de labs ne tournent pas en même temps sur le
même hôte**, aucun souci. Sinon, trois parades :
1. n'exécuter qu'une famille de lab à la fois sur l'hôte (cas le plus courant) ;
2. pré-réserver des slots disjoints (dossiers `team-*/meta.json` factices) ;
3. (le plus propre) patcher la base de subnet dans la copie B2 du launcher
   (ex. `172.32.` pour la découverte).

---

## Seed des challenges CTFd

```bash
python3 scoring/seed_challenges.py http://<ctfd>:8000 <admin_user> <admin_password>
```

Crée 10 challenges `dynamic` (flag `ctflab`, dynamique par équipe), libellés
« **catégorie · utilisateur @ machine** », enchaînés en **spine + 3 bonus** :

```
  WEB_RCE ─┬─► WEB_ROOT ─► FILES_RECON ─┬─► FILES_RCE ─► FILES_ROOT ─► WS_ROOT ─► FINAL   (spine)
           │                            ├─► DB_PIVOT   (bonus Forensique)
           └─► WEB_REVERSE (bonus OSINT)└─► DB_ROOT    (bonus Stégano)
```

Idempotent (retrouve les challenges par clef d'étape) → relançable sans doublon.

## Fichiers

| Fichier | Rôle |
|---|---|
| `steps.py`            | les 10 étapes (clefs + env `FLAG_*` figés, slug/catégorie découverte) |
| `seed_challenges.py`  | seed idempotent des 10 challenges CTFd (spine + bonus) |
| `overrides.yml`       | images partagées `ctflab-dec-*` + plafonds mem/cpu (pas de `db`) |
| `prebuild.sh`         | build des images `ctflab-dec-*` |
| `README.md`           | ce fichier |
