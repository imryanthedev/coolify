# Coolify — mises à jour des paquets VPS et protections supply chain

**Date :** 7 novembre 2026 (révision 2, relue et vérifiée le même jour)  
**Dépôt analysé :** `coollabsio/coolify`, fork `imryanthedev/coolify`  
**Commit analysé :** `29aa42b98` (`main`, 6 novembre 2026). `upstream/main` n’a pas bougé depuis (vérifié par `git fetch upstream` le 7 novembre) ; `upstream/next` est à `c8497912b`.  
**Dernière release stable :** `v4.6.0` (2 novembre 2026). `release.json` : `stable = 4.6.0`, `preview = 4.5.3`.  
**Portée :** patching des paquets OS des serveurs gérés (apt, dnf, zypper, pacman, apk), protections supply chain associées, et supply chain de Coolify lui-même.

> Analyse statique en lecture seule : code, historique Git, GitHub. Aucun test sur une instance réelle. Les points non vérifiés sont marqués **UNVERIFIED**.
>
> Les fichiers du patching (`CheckUpdates`, `UpdatePackage`, `ConfigureAutomaticSecurityUpdates`, `ServerPatchCheckJob`) sont **identiques entre `v4.6.0` et `main`** (`git diff v4.6.0 29aa42b98` vide sur ces fichiers). L’analyse vaut donc aussi pour la stable.

---

## 1. Résumé exécutif

Coolify sait **détecter** les mises à jour de paquets d’un serveur, les **notifier**, et les **installer** de deux façons :

1. **manuellement** (tout, ou paquet par paquet sauf sur Arch) ;
2. **automatiquement**, pour les **mises à jour de sécurité** seulement, en configurant `unattended-upgrades` (apt) ou `dnf-automatic` (dnf). C’est l’OS qui installe, pas Coolify.

Les protections réellement présentes sont **celles du gestionnaire de paquets** (signatures des dépôts), plus quelques garde-fous Coolify :

- auto-update **opt-in** et limitée aux origines de sécurité ;
- paquets `hold` (apt), pins (apk) et phased updates Ubuntu **affichés à part** et non proposés à l’update unitaire ;
- avertissements sur les paquets risqués (Docker, kernel, systemd/glibc/openssh) ;
- audit log des actions lancées depuis l’UI ;
- compteur sécurité et « reboot required ».

Il **n’y a pas** :

- d’âge minimum de release (cooldown) ;
- d’exclusion ou d’allowlist de paquets gérée par Coolify pour l’auto-update ;
- de retour d’information sur ce qu’a fait `unattended-upgrades` / `dnf-automatic` ;
- de vérification de checksum ou de signature des artefacts de Coolify (scripts CDN, images par tag) ;
- de scan CVE des paquets de l’hôte, ni en stable ni sur `main` (PR #12482 ouverte vers `next`) ;
- d’intégration socket.dev, ni de Dependabot/Renovate.

**Corrections majeures par rapport à la version 1 de ce document :**

- Les **phased updates Ubuntu ne retardent pas les mises à jour de sécurité** : Ubuntu ne les phase jamais. Elles ne protègent donc pas le chemin d’auto-update.
- **Désactiver** l’auto-update dans Coolify **n’arrête pas forcément** les mises à jour automatiques : sur apt, Coolify retire seulement son fichier ; la configuration de la distribution reprend la main (sur Ubuntu, en général, sécurité automatique activée).
- **dnf et zypper ont une date native** : les advisories (`updateinfo`) ont une date de publication. La phrase « pas de date de publication native dans apt/dnf » était fausse pour dnf.
- Les « notifications d’auto-update » de v4.7 (#12472) concernent la **mise à jour de Coolify lui-même**, pas `unattended-upgrades`.
- Les GitHub Actions sont **verrouillées par SHA** via `.github/workflows/actions.lock`. La CI n’est donc pas à « ❌ » sur tout.
- La cible des PR dépend du type de changement : **bugfix → `main`**, feature → `next` (`CONTRIBUTING.md`).

**Conclusion :** un cooldown est faisable mais doit être pensé par gestionnaire. Pour dnf/zypper, la date d’advisory existe. Pour apt, il faut un « première vue par Coolify » (ou une source externe comme Launchpad pour Ubuntu). L’application réaliste passe par des pins apt par version, générés avant `unattended-upgrades`. socket.dev ne couvre **pas** les paquets OS ; il peut servir à la CI du dépôt Coolify (npm ; Composer à confirmer).

---

## 2. Ce que fait le code aujourd’hui

### 2.1 Trois mécanismes distincts

| Mécanisme | Rôle | Installe ? | Fréquence par défaut |
|---|---|---|---|
| **Patch check** (`ServerPatchCheckJob` → `CheckUpdates`) | Détecter, classer, notifier | Non (mais lance `apt-get update` / `apk update`, qui rafraîchissent les index) | Hebdomadaire, dimanche, heure stable par serveur entre 04:00 et 23:59 |
| **Auto security updates** (`ConfigureAutomaticSecurityUpdates`) | Configurer l’OS une fois, au moment du toggle | Oui, **par l’OS** | Quotidienne, à l’heure choisie, sans délai aléatoire |
| **Update manuel** (`UpdatePackage`) | Installer tout ou un paquet | Oui, par Coolify en SSH | À la demande |

Le check et l’auto-update sont **indépendants** : le check peut être hebdomadaire alors que l’auto-update tourne tous les jours.

### 2.2 Le patch check

- Planification : `app/Jobs/ServerManagerJob.php:254-261` (dispatch) et `:290-300` (`patchCheckCron`).
  - Par défaut : `slot = id % 1200`, minute `slot % 60`, heure `4 + slot / 60`, le dimanche.
  - Fréquence personnalisée : preset (`daily`, `weekly`, `monthly`…) ou cron, au maximum une exécution par heure (`app/Livewire/Server/Security/Patches.php:225-238`).
- Détection : `app/Actions/Server/CheckUpdates.php:133`.
  - **apt** (`:207-217`) : `apt-get update -qq`, `apt list --upgradable`, `apt-mark showhold`, puis deux simulations `apt-get -s upgrade`, avec et sans `APT::Get::Always-Include-Phased-Updates=true` (`:34-36`). La différence donne les phased updates (`:473-490`).
  - **dnf** (`:201-206`) : `dnf repoquery --refresh --upgrades --latest-limit 1`, `rpm -qa` pour les versions installées, `dnf updateinfo list --security`.
  - **zypper** (`:197-200`) : `zypper -tx list-updates`, puis `zypper -x patch --dry-run --category security`.
  - **pacman** (`:58`, `:218-220`) : `checkupdates` si `checkupdates` **et** `fakeroot` existent, sinon une base temporaire. Jamais de `pacman -Sy` sur la base live.
  - **apk** (`:221-225`) : `apk update`, `apk list --upgradable`, puis `apk upgrade -s` pour repérer les paquets bloqués par un pin.
- Données produites par mise à jour : paquet, version actuelle, nouvelle version, architecture, dépôt, `security`, `risk`.
- Classification sécurité (`:257-273`) :
  - **apt** : vrai si la suite du candidat se termine par `-security` (`:263`). Cela couvre Debian `<codename>-security` et Ubuntu `-security`, `-apps-security`, `-infra-security`. **Nuance :** si le candidat vient de `-updates` avec une version plus récente que celle de `-security`, il n’est pas marqué sécurité, alors qu’il contient le correctif. De plus, Debian publie des correctifs de sécurité mineurs via les point releases (suite principale), donc sans `-security`.
  - **dnf / zypper** : vrai si le **nom** du paquet figure dans un advisory sécurité (`:264`). La correspondance porte sur le nom, pas la version. **Si la commande d’advisory échoue, le compteur vaut `0`, pas `null`** : les deux commandes finissent par `exit 0` et leur sortie est castée en chaîne (`:65`, `:73`, `:199`, `:205`), donc une sortie vide donne une liste vide. Le docblock de `addUpdateDetails()` (`:253`) promet pourtant `null`. Un échec se lit donc comme « aucune mise à jour de sécurité ».
  - **pacman / apk** : le compteur vaut `null` (inconnu) ; chaque paquet a `security = false`. L’UI doit donc lire « inconnu », pas « aucune ».
- `risk` : `docker`, `kernel`, `system` (`CheckUpdates.php:94-120`). Correspondance par motif glob.
- `reboot_required` (`:83-85`) : `/var/run/reboot-required`, `needrestart`, `dnf needs-restarting`, `zypper needs-rebooting`.
- `held_updates` avec raison `phased` ou `held` (`:457-465`). Ces paquets sont exclus de `total_updates`.
- Stockage (`app/Jobs/ServerPatchCheckJob.php:105-113`) : `server_settings.patch_check_result` (un seul JSON, **écrasé** à chaque check), `patch_check_error`, `patch_checked_at`. **En cas d’erreur, seuls `osId` et `package_manager` sont gardés** : la liste précédente est perdue. Aucune table d’historique, aucun champ « first seen » (recherche `first_seen|firstSeen|patch_history` : aucun résultat).
- Notification (`ServerPatchCheckJob.php:72-87`, `app/Notifications/Server/ServerPatchCheck.php:23-26`) : canaux activés pour `server_patch` (email, Discord, Slack, Telegram, Pushover, webhook).
  - Mises à jour disponibles : seulement si le check n’est **pas manuel** et `total_updates > 0`.
  - Erreur : seulement au **passage** de « OK » à « erreur », manuel ou non. Un serveur qui reste en erreur ne renotifie pas.

**Limite :** le check ne fait que constater.

### 2.3 L’installation manuelle

`app/Actions/Server/UpdatePackage.php:84-101` :

| Gestionnaire | Mise à jour de tous les paquets | Mise à jour d’un paquet |
|---|---|---|
| apt | `apt-get update -qq` puis `apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade` | `apt-get … install --only-upgrade <pkg>` |
| dnf | `dnf upgrade -y` | `dnf upgrade -y <pkg>` |
| zypper | `zypper --non-interactive update` | `zypper --non-interactive update <pkg>` |
| pacman | `pacman -Syu --noconfirm` | refusé (`CheckUpdates::FULL_UPGRADE_ONLY`) |
| apk | `apk update` puis `apk upgrade` | `apk upgrade <pkg>` |

Garde-fous :

- confirmation à taper dans l’UI (`Update All Packages`, nom du serveur pour le reboot) ;
- avertissement sur le nombre de paquets risqués ;
- nom de paquet validé par regex `^[a-zA-Z0-9._+:-]+$` puis `escapeshellarg` (`UpdatePackage.php:37-43`) ;
- update unitaire autorisée seulement pour un paquet présent dans `updates` du dernier check (`Patches.php:109-114`), donc **pas** pour un paquet `held` ou `phased` ;
- audit log `ui.server.packages_update_requested` puis `ui.server.packages_update_finished` (`app/Listeners/FinishServerPackagesUpdate.php:27-39`) ;
- nouveau check après l’update (`FinishServerPackagesUpdate.php:41`). C’est un check **manuel** : il ne notifie pas les mises à jour restantes.

**Sémantique apt (vérifiée dans la doc apt, non testée sur instance) :**

- `apt-get upgrade` n’installe jamais de nouveau paquet et n’en retire aucun. Une mise à jour qui exige un nouveau paquet est « kept back ». C’est le cas classique des méta-paquets kernel (`linux-generic`, `linux-image-amd64`…), qui dépendent d’un nouveau paquet `linux-image-<version>`. « Update all » ne les installe donc pas, alors que le check les affiche dans `updates` : les deux simulations utilisent `apt-get upgrade`, donc ces paquets n’apparaissent ni dans l’une ni dans l’autre, et la différence ne les classe pas en `phased`. **UNVERIFIED sur instance** : vérifier avec une VM Ubuntu au moment d’un nouveau kernel.
- À noter : `apt upgrade` (sans `-get`) installe les nouvelles dépendances par défaut ; `apt-get upgrade` non. Coolify utilise `apt-get`.
- `apt-get install --only-upgrade <pkg>` : `--only-upgrade` empêche seulement d’installer `<pkg>` s’il est absent. Les **dépendances** de la nouvelle version **peuvent être installées**, et le résolveur peut proposer des retraits en cas de conflit (`-y` accepte, sauf paquets essentiels). Cliquer « update » sur un méta-paquet kernel l’installe donc vraiment.
- Les deux commandes respectent `apt-mark hold` et les pins. `install` explicite **contourne le phasing** (doc Ubuntu), mais l’UI ne propose pas les paquets `phased` à l’update unitaire.

### 2.4 L’auto-update sécurité

`app/Actions/Server/ConfigureAutomaticSecurityUpdates.php`. La configuration n’est poussée **qu’au toggle** ou au changement d’heure (`Patches.php:154-156`, `:178-201`). Coolify ne la revérifie jamais ensuite. Il faut avoir lancé un check avant, pour connaître le gestionnaire (`Patches.php:206-209`).

- **apt (Debian/Ubuntu)** :
  - installe `unattended-upgrades` s’il manque (`:105`) ;
  - écrit `/etc/apt/apt.conf.d/52coolify-unattended-upgrades` (`:73-90`) : `APT::Periodic::Update-Package-Lists "1"`, `APT::Periodic::Unattended-Upgrade "1"` ;
  - `#clear` vide `Allowed-Origins` et `Origins-Pattern` définis avant (fichier `50unattended-upgrades`), puis ne garde que Debian `<codename>-security` (label `Debian-Security`), Ubuntu `<codename>-security`, Ubuntu Pro ESM apps et infra ;
  - ne touche **pas** à `Unattended-Upgrade::Package-Blacklist`, `Automatic-Reboot`, `Mail`, etc. Les valeurs de la distribution ou de l’admin s’appliquent toujours ;
  - drop-in `/etc/systemd/system/apt-daily-upgrade.timer.d/coolify.conf` (`:92-95`) : `OnCalendar=*-*-* HH:MM`, `RandomizedDelaySec=0`. Le `apt-daily.timer` (téléchargement) garde son horaire ;
  - `systemctl enable --now apt-daily.timer apt-daily-upgrade.timer` (`:111`).
- **dnf (RHEL/Fedora)** (`:132-150`) :
  - `dnf install -y dnf-automatic` ;
  - supprime puis réécrit `upgrade_type = security` et `apply_updates = yes` sous `[commands]` de `/etc/dnf/automatic.conf` ;
  - drop-in sur `dnf5-automatic.timer` (dnf5) ou `dnf-automatic.timer` (dnf4), puis `enable --now`.
  - **UNVERIFIED** : sur une distribution sans métadonnées `updateinfo` (CentOS Stream notamment), `upgrade_type = security` n’installerait rien. À tester.
- **Non supporté** : zypper, pacman, apk (`:42`).
- **Reboot** : Coolify n’active pas de reboot automatique. Si la distribution ou l’admin a mis `Unattended-Upgrade::Automatic-Reboot "true"`, il reste actif. Sinon, « Reboot required » apparaît au prochain check.
- **Nouvelles dépendances** : contrairement à « Update all », `unattended-upgrades` peut installer les nouvelles dépendances d’un paquet autorisé (cas des kernels Ubuntu). **UNVERIFIED sur instance.**
- **Pas de retour d’information** : aucun code ne lit `/var/log/unattended-upgrades/`, le journal de `dnf-automatic` ou `/var/log/dpkg.log` (recherche `unattended|dnf-automatic` dans `app/` : seulement l’action de configuration et l’UI). Un échec n’est visible qu’au prochain check, et seulement indirectement (paquets toujours en attente).

**Désactivation — à corriger :**

- **apt** (`:118-124`) : supprime le fichier Coolify et le drop-in, puis `daemon-reload`. Les timers **restent actifs**, `unattended-upgrades` reste installé, et la configuration de la distribution reprend la main. Sur Ubuntu, `20auto-upgrades` et `50unattended-upgrades` activent en général déjà les mises à jour de sécurité : **« off » dans Coolify veut alors dire « retour au défaut Ubuntu », pas « aucune auto-update »**. Sur Debian, le résultat dépend de la présence de `20auto-upgrades` (**UNVERIFIED**). L’UI affiche pourtant « turned off ».
- **dnf** (`:155-162`) : désactive le timer (si l’unité existe dans `/usr/lib/systemd/system`) et retire le drop-in. `automatic.conf` garde `upgrade_type = security` et `apply_updates = yes`. Sans timer, c’est sans effet immédiat, mais l’état initial n’est pas restauré : un `systemctl enable` manuel ou un `dnf-automatic` lancé à la main installera.

### 2.5 Versions concernées

- Le patching est sorti en **v4.5.0** (23 octobre 2026). Release notes : « Added server patching (beta) with automatic security updates per server, reboot and risky package warnings, and patch status in the server list ».
- Il est toujours marqué **beta** dans l’UI (`resources/views/livewire/server/security/patches.blade.php:34`).
- Stable : **v4.6.0**. `main` contient **v4.7** (PR #12478, mergée le 6 novembre 2026, 160 commits depuis `v4.6.0`) mais pas de tag ni de release ; `release.json` pointe `4.6.0`.

---

## 3. Protections supply chain existantes

| Contrôle | État | Couvre | Ne couvre pas |
|---|---|---|---|
| Signature des dépôts (GPG apt/dnf/zypper/pacman, clés apk) | ✅ hérité de l’OS | Miroir compromis, altération en transit | Paquet malveillant signé par le dépôt officiel ; dépôt tiers ajouté par l’admin |
| Auto-update limitée aux origines sécurité | ✅ | Réduit le volume auto-installé | Un paquet malveillant dans `-security` |
| Opt-in | ✅ côté Coolify | Off par défaut dans Coolify | L’auto-update déjà activée par la distribution (Ubuntu) |
| Confirmation manuelle | ✅ | Update all, reboot | — |
| Phased updates Ubuntu | ⚠️ subi | Délai de déploiement des mises à jour **non sécurité** sur Ubuntu | **Les mises à jour sécurité (jamais phasées)**, Debian, dnf, zypper, pacman, apk |
| `apt-mark hold` / pins apk | ✅ respecté et affiché | Paquets bloqués par l’admin | Gestion depuis Coolify |
| Avertissement paquets risqués | ✅ UI | Docker, kernel, système | L’auto-update n’exclut pas ces paquets |
| Audit log | ✅ | Actions UI (update, reboot, réglages) | Ce qu’a installé l’OS |
| Notification du check | ✅ | Mises à jour disponibles, passage en erreur | Succès/échec de `unattended-upgrades` / `dnf-automatic` |
| Reboot requis | ✅ affiché | Après kernel/libs | — |
| Scan CVE hôte | 🟡 PR #12482 ouverte (`next`) | Visibilité Syft/Grype | Prévention, âge minimum |
| Scan CVE images | 🟡 sur `main` (v4.7, #12377), non publié | Images de conteneurs, deploy gate, KEV/EPSS via la base Grype | Paquets de l’hôte |
| GitHub Actions verrouillées | ✅ `.github/workflows/actions.lock` (SHA par action, `gh actions-lock`) | Tag d’action déplacé | Vulnérabilités des dépendances PHP/JS |
| Dependabot / Renovate / `composer audit` / socket.dev | ❌ | — | — |

### 3.1 Le point clé : l’auto-update est déléguée à l’OS

Quand l’auto sécurité est active, **`unattended-upgrades` / `dnf-automatic` décide** des paquets. Coolify :

- ne voit pas la liste installée ;
- n’applique ni cooldown, ni exclusion, ni règle par paquet ;
- ne récupère pas le résultat ;
- ne vérifie pas que sa configuration est toujours en place.

C’est robuste (fonctionne même si Coolify est arrêté). C’est aussi ce qui rend un cooldown non trivial : il faut soit **contraindre l’outil OS** (pins, blacklist, exclude), soit **reprendre l’exécution**.

### 3.2 La supply chain de Coolify lui-même

À distinguer des paquets du VPS :

- **Scripts et fichiers CDN** : `install.sh` télécharge `docker-compose.yml`, `docker-compose.prod.yml`, `.env.production`, `upgrade.sh` depuis `$CDN` (`scripts/install.sh:889-899`) ; `upgrade.sh` fait de même (`scripts/upgrade.sh:123-133`). **Aucun checksum ni signature** (recherche `sha256|cosign|gpg|checksum` dans les deux scripts : seulement la clé GPG du dépôt Docker, `install.sh:724`). Seul TLS protège le transfert.
- **Docker** : `install_docker()` exécute `curl -fsSL https://get.docker.com | sh` (`scripts/install.sh:707`). La discussion #5503 (2025) visait alors le script Rancher. Réponse d’un membre de l’équipe (`peaklabs-dev`) : faire confiance au script et au CDN Coolify, script Docker officiel jugé fiable, projet futur d’installeur en Go. Le script appelé a changé depuis ; la discussion reste ouverte.
- **Images Coolify** : tirées par tag (`docker-compose.prod.yml:8` et `:12`, `coollabsio/coolify:${LATEST_IMAGE}`), pas par digest. Même chose pour le helper (`upstream.json:2-4`, version seule).
- **Images épinglées par digest** : scanners Syft/Grype/regctl/alpine (`config/constants.php:89-96`), `rclone` (`config/constants.php:26`), `sentinel-host` (`upstream.json:8-10`).
- **Build CI** : attestation de provenance (`provenance: mode=max`) et SBOM (`sbom: true`) dans `.github/workflows/build.yaml:106-107`. **Aucune vérification** de ces attestations à l’installation ou à l’upgrade.
- **Contre-exemple interne** : `InstallSysbox` vérifie un SHA256 avant installation (`app/Actions/Server/InstallSysbox.php:136-137`). Le même principe n’est pas appliqué aux artefacts CDN.
- **Mise à jour automatique de Coolify** : retry en cas de rate limit et fréquence répartie par instance (commit `12fd9e448`, dans `v4.5.0`, ferme #11890). Notifications de démarrage, d’échec et de fin en v4.7 (#12472, non publié).

---

## 4. Ce qui manque

1. **Pas d’âge minimum.** Le check écrase `patch_check_result` et le vide en cas d’erreur. Pas d’historique « première vue » par paquet et version.
2. **Pas d’exclusion.** Impossible de dire depuis Coolify « ne jamais auto-installer docker-ce/containerd/kernel ». Contournement manuel possible aujourd’hui : `Unattended-Upgrade::Package-Blacklist` dans un autre fichier `apt.conf.d` (Coolify ne le vide pas), ou `exclude` dans dnf.
3. **Pas de staging ni d’approbation.** « Update all » exécute directement. Le check simule, mais il n’y a pas de « préparer puis approuver ».
4. **Pas de retour sur l’auto-update.** Ni succès, ni échec, ni liste installée.
5. **« Off » trompeur** sur apt (voir 2.4) et état non restauré sur dnf.
6. **Pas de détection de dérive.** Si l’admin ou un paquet modifie la config, Coolify ne le voit pas.
7. **Pas de rollback.** Coolify ne peut pas revenir à une version précédente.
8. **Pas de scan CVE de l’hôte** (PR #12482 non mergée).
9. **Pas de protection contre un paquet malveillant signé.** La signature protège contre un miroir compromis, pas contre un mainteneur ou un build compromis. Nuance utile : dans le cas xz (2024), la version piégée a été repérée avant d’atteindre Debian stable et les versions stables d’Ubuntu. Le délai entre « unstable/testing » et « stable/-security » joue déjà le rôle de cooldown sur ces distributions ; un cooldown supplémentaire a surtout de la valeur sur les dépôts **tiers** (Docker, NodeSource…) et les distributions rolling.
10. **Détail apt** : le check affiche des mises à jour (méta-paquets kernel) que « Update all » ne peut pas installer, sans l’expliquer.
11. **Détail apt** : la classification sécurité ignore un candidat `-updates` qui contient un correctif de sécurité.
12. **Détail dnf/zypper** : un échec de la requête d’advisory affiche `0` mise à jour de sécurité au lieu de « inconnu » (voir 2.2).

---

## 5. Ce qui est prévu ou en cours (statut au 7 novembre 2026)

| Élément | Statut vérifié | Lien avec le sujet |
|---|---|---|
| **v4.7** (PR #12478) | Mergée dans `main` le 6 nov. ; pas de tag ni release ; `release.json` = 4.6.0 | Scan d’images (#12377), pinning des clés SSH hôtes, notifications d’auto-update **de Coolify** (#12472) |
| **PR #12377** | Mergée dans `next` le 6 nov., incluse dans v4.7 | Scan CVE des images, KEV/EPSS via Grype, recommandations de version d’image « seulement après scan » (une forme de gate, pour les images uniquement) |
| **PR #12482** (`andrasbacsai`) | Ouverte, base `next`, `MERGEABLE`, mise à jour le 6 nov. | Scan CVE des paquets OS de l’hôte (Syft/Grype sur une copie des bases dpkg/rpm/apk/pacman), table `server_host_scans`, scan après update et « Scan now ». **Déplace le patching sur sa propre page `/security/patches`** : toute PR UI sur le patching doit partir de là. Détection a posteriori, pas prévention |
| **PR #11791** | Fermée sans merge le 17 sept. | « stable/RC channel and patch-only auto updates » de Coolify. Les canaux ont été livrés par #12359 (mergée dans `next` le 1er nov.) ; le « patch-only » n’existe pas |
| **Issue #11890** | Fermée le 15 oct. par `12fd9e448` | Auto-update **de Coolify** qui échouait (rate limit ghcr.io) ; retry et fréquence répartie |

Discussions proches (toutes vérifiées) :

- **#5503** (Improvement Requests, ouverte) : supply chain de l’installeur (voir 3.2).
- **#8353** (Improvement Requests, ouverte, 0 réponse) : installer automatiquement les mises à jour serveur **et redémarrer**. C’est l’inverse d’un cooldown : la demande existe pour plus d’automatisation.
- **#9538** (Q&A, ouverte) : faut-il attendre quelques jours avant de mettre à jour **Coolify** ? Une seule réponse, d’un contributeur : oui, quelques jours, sauf correctif de sécurité majeur. Ce n’est pas une position de l’équipe.
- **#7578** (Improvement Requests, fermée) : prévenir avant de mettre à jour Traefik avec les paquets serveur.
- UX du patching : #11846, #11860, #8818 (ouvertes), #10630 (fermée).

Aucune issue ou discussion trouvée sur un âge minimum de paquet OS ou sur socket.dev. Termes cherchés en v1 : `minimum release age`, `cooldown`, `quarantine`, `socket.dev`, `supply chain`, `malicious package`, `staged rollout`, `phased updates`. Une discussion peut exister sous une autre formulation.

---

## 6. Faisabilité d’un « minimum release age »

### 6.1 Quelle date utiliser ?

| Gestionnaire | Date native disponible ? | Source réaliste |
|---|---|---|
| **dnf** | **Oui** pour les paquets couverts par un advisory : date d’émission dans `updateinfo` (dnf5 l’affiche dans `dnf advisory list`). Sinon `BUILDTIME` du RPM (date de build, pas de publication) | Advisory, sinon « première vue » |
| **zypper** | **Oui** pour les patchs (date d’émission du patch) | Patch, sinon « première vue » |
| **apt Ubuntu** | Pas dans l’index `Packages`. Date de publication par pocket disponible via l’API Launchpad (**UNVERIFIED** pour l’usage à grande échelle) | « Première vue » ; Launchpad en option |
| **apt Debian** | Pas dans l’index. `snapshot.debian.org` permet de retrouver la première apparition | « Première vue » |
| **apt, dépôts tiers** (Docker, etc.) | Non | « Première vue » |
| **pacman / apk** | Non (date de build seulement) | Déconseillé (voir 6.3) |

« Première vue par Coolify » a une erreur égale à l’intervalle d’observation : avec un check hebdomadaire, jusqu’à 7 jours. Un cooldown de quelques jours exige un **check quotidien** (ou un job d’observation léger) tant que l’option est active.

### 6.2 Comment l’appliquer

| Mécanisme | Granularité | Utilisable pour un cooldown ? |
|---|---|---|
| **Pin apt** (`Package: x:any` / `Pin: version 1.2-3` / `Pin-Priority: -1`) | Par version | **Oui** : bloque exactement la version trop récente, `unattended-upgrades` le respecte. Sans `:any` (ou un pin par architecture), le pin ne vise que l’architecture native (apt_preferences(5)) |
| `Unattended-Upgrade::Package-Blacklist` | Par nom (regex) | Pour les **exclusions**, pas pour un âge (bloque toutes les versions) |
| `dnf versionlock` (plugin) | Par version | Possible, mais plugin à installer ; un verrou empêche aussi une version plus récente |
| `exclude` dans `[base]` de `automatic.conf` | Par nom/motif | Pour les exclusions dnf |
| Snapshot de dépôt (`snapshot.debian.org`, `snapshot.ubuntu.com`) | Tout le dépôt à une date | Âge réel, mais change les sources, lourd, retarde aussi la sécurité |
| Exécution par Coolify (`apt-get install pkg=version`) | Par version | Oui, mais Coolify devient responsable des échecs, des reboots et de son indisponibilité |

### 6.3 Options d’implémentation

#### Option A — Observation seule (petite PR, sans changement de comportement)

- Table `server_package_observations` : `server_id`, `package_manager`, `package`, `architecture`, `version`, `first_seen_at`, `last_seen_at`, `security`, `advisory_issued_at` (nullable).
- Remplie par `ServerPatchCheckJob` après un check réussi. Rien n’est écrit en cas d’erreur.
- Affichage « disponible depuis X jours » sur la page Patches (après #12482).
- La table doit être déclarée dans `ServerTransferCoverage` (le test `tests/Unit/ServerTransfer/ServerTransferCoverageTest.php` vérifie la couverture des données d’un serveur) et purgée quand une version disparaît.

C’est le prérequis du reste.

#### Option B — Cooldown via l’outil OS (recommandé pour apt)

Un script poussé par Coolify, en `ExecStartPre` (étapes 1 à 3) et `ExecStartPost` (étape 5) sur `apt-daily-upgrade.service`, ou bien un service dédié qui encadre l’appel :

1. lit la liste des candidats ;
2. maintient un état local `paquet+version → première vue` (indépendant de Coolify) ;
3. écrit un fichier de pins `Pin-Priority: -1` pour **toutes** les versions installables plus récentes que la version installée et plus jeunes que N jours, pas seulement le candidat (`apt-cache madison` / `apt-cache policy`). Sinon : si `-updates` a 1.2 et `-security` 1.1, le candidat est 1.2, mais `unattended-upgrades` se rabat sur 1.1 (origine autorisée), qui contournerait le cooldown ;
4. laisse `unattended-upgrades` tourner normalement ;
5. après le service (`ExecStartPost`), écrit un résumé (installés, reportés, exclus) à partir de `/var/log/unattended-upgrades/` ou `/var/log/dpkg.log`, que le check suivant lit. Un `ExecStartPre` seul ne peut pas connaître le résultat.

Les pins sont **laissés en place** et régénérés à chaque exécution : les retirer après coup ouvrirait une fenêtre où un `apt upgrade` manuel ignorerait le cooldown. L’UI doit les afficher pour éviter la confusion avec des pins de l’admin (fichier dédié).

**Conflit avec les pins existants :** pour une version donnée, apt applique le **premier** enregistrement spécifique qui correspond, et lit `preferences.d` dans l’ordre alphabétique (apt_preferences(5)). Un pin de l’admin lu avant le fichier Coolify peut donc annuler le `-1`. Il faut nommer le fichier pour qu’il soit lu en premier (ex. `/etc/apt/preferences.d/00-coolify-cooldown`), puis **vérifier la priorité effective** avec `apt-cache policy <pkg>` après génération. Si une version à bloquer n’a pas la priorité `-1`, le comportement sûr est de ne pas lancer `unattended-upgrades` pour ce paquet (Package-Blacklist temporaire) et de le signaler.

Pour dnf : `exclude` régénéré dans `automatic.conf`, ou versionlock. Pour dnf/zypper, la date d’advisory peut remplacer la « première vue ».

Avantages : garde la robustesse de l’OS, fonctionne si Coolify est arrêté. Inconvénients : script à maintenir et tester sur chaque distribution.

#### Option C — Prise en charge complète par Coolify

Coolify calcule la liste éligible et exécute `apt-get install --only-upgrade pkg=version …` ou `dnf upgrade -y pkg-version …`. Avantages : exclusions, cooldown, notifications et journal unifiés. Inconvénients : rien ne tourne si Coolify est arrêté, et `install` peut ajouter des dépendances.

**Recommandation :** A, puis B pour apt et dnf. Pas de cooldown sur pacman : un `pacman -Syu` retardé ou partiel n’est pas supporté par Arch (le code le rappelle, `CheckUpdates.php:15-20`). Pour apk, ne pas l’activer sans tests.

### 6.4 Points à trancher en Discussion

- **Sécurité vs cooldown** : retarder un correctif de sécurité augmente l’exposition. Proposition : cooldown à 0 par défaut ; si activé, appliqué d’abord aux dépôts **tiers** et aux mises à jour non sécurité ; pour `-security`, un délai court optionnel (ex. 1–2 jours).
- Exclusions par défaut des paquets `docker` de l’auto-update (redémarre les conteneurs) ?
- Que faire si l’observation n’a pas tourné depuis N jours (Coolify arrêté) : bloquer, ou laisser passer ?
- Digest quotidien : paquets en attente, installés, échecs.
- Corriger la sémantique de « off » sur apt (voir PR 1 ci-dessous).

---

## 7. Faisabilité de socket.dev

**Pas adapté aux paquets OS.** Socket analyse les dépendances des écosystèmes de code (npm, PyPI, Go, Maven, RubyGems, NuGet, Cargo…). Il n’analyse pas les paquets `.deb` ou `.rpm` des dépôts Debian/RHEL. Le brancher sur Coolify ne protégerait **pas** les mises à jour du VPS.

Où il peut servir :

- **Dépôt Coolify** : dépendances JS (`package.json`, lockfile). **Composer : UNVERIFIED.** Les annonces de Socket parlent d’un support PHP/Composer, mais la page de support des écosystèmes l’indiquait encore « planned » lors de la vérification. Même incertitude pour les GitHub Actions. À confirmer sur <https://docs.socket.dev/docs/language-support> avant de le proposer.
- **Applications des utilisateurs** : autre produit (scan de code), hors patch management.

Pour les paquets de l’hôte, les outils réalistes :

- **Syft/Grype** (#12482) : CVE des paquets installés ; la base Grype inclut déjà les signaux KEV et EPSS utilisés par le scan d’images (`app/Services/ImageScan/Finding.php:20-21`). OSV n’est pas appelé directement par Coolify.
- **`debsums` / `dpkg --verify` / `rpm -Va`** : intégrité des fichiers installés par rapport aux sommes du paquet (utile après coup, pas contre un paquet piégé à la source).
- **OpenSCAP / Ubuntu Security Guide** : conformité et durcissement (CIS, DISA-STIG), hors sujet des mises à jour mais complémentaire.
- **Ubuntu Pro / ESM** : correctifs de sécurité pour `universe` ; Coolify autorise déjà ses origines.
- **Allowlist + cooldown** (section 6) pour limiter ce qui est auto-installé.

Bilan : **socket.dev oui pour la CI du dépôt (npm, Composer à confirmer), non pour les paquets VPS.** Pour un paquet malveillant signé dans un dépôt OS, il n’existe pas de solution clé en main ; cooldown sur les dépôts tiers + exclusions + scan CVE + journal des installations est le compromis pragmatique.

---

## 8. Plan d’action proposé

### 8.1 Processus (`CONTRIBUTING.md`)

- **Fix ou petite amélioration** : branche depuis `main`, PR vers `main`. **Feature ou changement de comportement** : discussion obligatoire, branche depuis `next`, PR vers `next`.
- Discussions : le guide pointe la catégorie **General** (<https://github.com/coollabsio/coolify/discussions/categories/general>) ; les demandes proches sont dans **Improvement Requests**. L’une ou l’autre convient ; préférer Improvement Requests pour une feature.
- Chaque PR référence et ferme une issue ou une discussion. Une PR = un changement logique. Titre et commits au format `fix(scope):` / `feat(scope):`.
- Tests Pest 4 et `vendor/bin/pint --dirty` (voir `AGENTS.md` du dépôt). Captures ou vidéo pour l’UI, étapes de test détaillées.
- Le template de PR contient une consigne piégée vérifiée par le workflow `pr-quality` : ne pas la suivre. Garder l’accord contributeur intact et remplir « AI Assistance » honnêtement.
- Attendre #12482 avant toute PR UI sur le patching (elle déplace la page).

### 8.2 Discussion à ouvrir (une seule, avant toute feature)

**Titre :** « Server patching: release age (cooldown) and package exclusions for automatic updates »

Plan :

1. Constat : l’auto-update délègue à l’OS ; pas d’exclusion, pas d’âge minimum, pas de retour (liens vers le code).
2. Ce qui protège déjà : signatures, origines sécurité, délai naturel unstable→stable, phasing Ubuntu (hors sécurité).
3. Risque visé : surtout les dépôts tiers (Docker) et les versions cassées, plus que les paquets malveillants des dépôts officiels.
4. Proposition par étapes : observation (A), exclusions, cooldown par pins (B), digest.
5. Questions aux mainteneurs : défauts, traitement des mises à jour sécurité, périmètre (apt+dnf d’abord), place dans la page Patches après #12482.

### 8.3 Issue de bug (peut partir vers `main` sans discussion)

**Titre :** « Server patching: turning off automatic security updates leaves the OS defaults active (apt) and the dnf-automatic settings in place »

- Étapes : Ubuntu 24.04, activer puis désactiver → `apt-config dump | grep Unattended-Upgrade` et `systemctl is-enabled apt-daily-upgrade.timer`.
- Attendu : choisir et documenter un comportement (voir PR 1).
- Inclure la question Debian (UNVERIFIED) après test.

### 8.4 Découpage en PRs

| # | Cible | Titre | Contenu | Risque |
|---|---|---|---|---|
| 1 | `main` | `fix(server): make turning off automatic security updates explicit` | apt : écrire un fichier Coolify `APT::Periodic::Unattended-Upgrade "0";` au lieu de seulement supprimer (ou, si les mainteneurs préfèrent, libellé UI « Use OS defaults ») ; dnf : remettre `apply_updates = no` | Faible |
| 2 | `main` | `fix(server): explain apt updates that need new packages` | Marquer « kept back » (nouvelle dépendance) les mises à jour absentes des deux simulations, avec un libellé clair. **Les laisser dans `updates`** (avec un drapeau, pas dans `held_updates`), car `Patches::updatePackage()` (`:109-114`) exige cette présence et l’update unitaire est le seul moyen de les installer depuis l’UI. Séparer « installable par Update all » de « installable seul » | Faible |
| 3 | `next` | `feat(server): record when each package update was first seen` | Option A + date d’advisory dnf/zypper, affichage « disponible depuis » | Faible |
| 4 | `next` | `feat(server): exclude packages from automatic security updates` | Liste d’exclusions → `Package-Blacklist` (apt), `exclude` (dnf) ; exclusions Docker proposées | Moyen |
| 5 | `next` | `feat(server): report what automatic security updates installed` | Lecture de `/var/log/unattended-upgrades/` ou `dpkg.log`, journal `dnf-automatic`, notification succès/échec, détection de dérive de config | Faible à moyen |
| 6 | `next` | `feat(server): minimum release age for automatic security updates` | Option B (pins apt par version, exclude/versionlock dnf), réglage `min_age_days` | Moyen |
| 7 | discussion séparée | Supply chain de Coolify | Checksums ou signatures des fichiers CDN, images par digest, vérification des attestations, Dependabot/Renovate + `composer audit` | Moyen, hors sujet patching |

### 8.5 Critères d’acceptation

**PR 1 (fix off)**

- Après « off » sur Ubuntu, `apt-config dump` donne `APT::Periodic::Unattended-Upgrade "0"` (ou l’UI dit explicitement que les défauts de l’OS s’appliquent).
- Après « off » sur dnf, `automatic.conf` contient `apply_updates = no` et le timer est désactivé.
- Réactiver remet exactement la configuration actuelle.
- Tests Pest sur `ConfigureAutomaticSecurityUpdates::commands()` pour apt et dnf, on et off.

**PR 2 (kept back)**

- Un méta-paquet kernel qui exige un nouveau paquet apparaît avec une raison distincte, hors du compteur « installable par Update all ».
- Il reste installable par l’update unitaire (bouton présent, `updatePackage()` l’accepte).
- Les paquets `phased` et `held` sont toujours classés comme avant.
- Tests unitaires sur des sorties de simulation `apt-get -s upgrade` réelles (Ubuntu 22.04 et 24.04).

**PR 3 (observation)**

- Une version vue pour la première fois a `first_seen_at` = date du check ; un check suivant ne la change pas, met à jour `last_seen_at`.
- Un check en erreur n’écrit rien.
- Une version installée ou remplacée est purgée.
- Couverture dans `ServerTransferCoverage` ; test existant vert.
- Aucun changement de notification ni d’installation.

**PR 6 (cooldown)**

- Avec `min_age_days = 0`, la configuration générée est identique à l’actuelle.
- Une version plus jeune que N jours n’est pas installée par `unattended-upgrades` ; elle l’est après N jours sans action de Coolify.
- Les paquets exclus ne sont jamais auto-installés.
- Les pins Coolify sont dans un fichier dédié, régénérés à chaque exécution, supprimés à la désactivation.
- L’UI explique pourquoi un paquet attend, et jusqu’à quand.
- Tests : apt et dnf, sécurité et non-sécurité, observation absente depuis N jours.
- Décisions (installé / reporté / exclu) dans l’audit log ou le digest.

---

## 9. Références

### Code (commit `29aa42b98`)

- `app/Actions/Server/CheckUpdates.php` (`:34-36`, `:94`, `:133`, `:207-217`, `:257-273`, `:473-490`)
- `app/Actions/Server/UpdatePackage.php` (`:37-43`, `:84-101`)
- `app/Actions/Server/ConfigureAutomaticSecurityUpdates.php` (`:73-124`, `:132-162`)
- `app/Jobs/ServerPatchCheckJob.php` (`:72-87`, `:105-113`)
- `app/Jobs/ServerManagerJob.php` (`:254-261`, `:290-300`)
- `app/Livewire/Server/Security/Patches.php` (`:109-114`, `:154-156`, `:178-238`)
- `app/Listeners/FinishServerPackagesUpdate.php` (`:27-41`)
- `app/Notifications/Server/ServerPatchCheck.php` (`:23-26`)
- `resources/views/livewire/server/security/patches.blade.php`
- `scripts/install.sh` (`:707`, `:724`, `:889-899`), `scripts/upgrade.sh` (`:123-133`)
- `config/constants.php` (`:26`, `:89-96`), `upstream.json`, `docker-compose.prod.yml` (`:8`, `:12`)
- `.github/workflows/build.yaml` (`:106-107`), `.github/workflows/actions.lock`
- `app/Actions/Server/InstallSysbox.php` (`:136-137`)
- `CONTRIBUTING.md`, `AGENTS.md`

### GitHub

- Releases : [v4.5.0](https://github.com/coollabsio/coolify/releases/tag/v4.5.0), [v4.6.0](https://github.com/coollabsio/coolify/releases/tag/v4.6.0)
- PR : [#12482](https://github.com/coollabsio/coolify/pull/12482), [#12377](https://github.com/coollabsio/coolify/pull/12377), [#12478](https://github.com/coollabsio/coolify/pull/12478), [#12472](https://github.com/coollabsio/coolify/pull/12472), [#11791](https://github.com/coollabsio/coolify/pull/11791), [#12359](https://github.com/coollabsio/coolify/pull/12359)
- Discussions : [#5503](https://github.com/coollabsio/coolify/discussions/5503), [#8353](https://github.com/coollabsio/coolify/discussions/8353), [#9538](https://github.com/coollabsio/coolify/discussions/9538), [#7578](https://github.com/coollabsio/coolify/discussions/7578), #11846, #11860, #10630, #8818
- Issue : [#11890](https://github.com/coollabsio/coolify/issues/11890)

### Documentation externe

- Ubuntu, apt et phased updates : <https://ubuntu.com/server/docs/explanation/software/about-apt-upgrade-and-phased-updates/> (« security updates are never phased » ; `apt install` contourne le phasing)
- `apt-get(8)`, `apt_preferences(5)` : <https://manpages.debian.org/apt-get>, <https://manpages.debian.org/apt_preferences>
- unattended-upgrades : <https://github.com/mvo5/unattended-upgrades>
- dnf-automatic : <https://dnf.readthedocs.io/en/latest/automatic.html>, <https://dnf5.readthedocs.io/en/latest/dnf5_plugins/automatic.8.html>
- Arch, partial upgrades : <https://wiki.archlinux.org/title/System_maintenance#Partial_upgrades_are_unsupported>
- Socket, écosystèmes : <https://docs.socket.dev/docs/language-support>

---

## 10. Limites et points non vérifiés

- Aucun test sur instance. Les comportements apt/dnf viennent de la doc et du code.
- **UNVERIFIED** :
  - affichage réel des méta-paquets kernel « kept back » dans le check (2.3) ;
  - installation de nouvelles dépendances par `unattended-upgrades` (2.4) ;
  - comportement après « off » sur Debian (dépend de `20auto-upgrades`) ;
  - `upgrade_type = security` sur CentOS Stream (pas d’`updateinfo`) ;
  - support Composer et GitHub Actions par socket.dev ;
  - utilisation de l’API Launchpad comme source de date à grande échelle.
- La recherche d’issues et de discussions dépend des mots-clés.
- Le statut des PR et releases change vite : revérifier `release.json`, les tags et #12482 avant d’agir.

### Historique

- **Révision 1** (7 nov. 2026) : première analyse.
- **Révision 2** (7 nov. 2026) : vérification ligne à ligne. Corrigé : phasing et sécurité, sémantique de « off » sur apt, dates d’advisory dnf/zypper, portée de #12472, `actions.lock`, cible `main`/`next`, catégorie de discussion, canal Pushover, numéros de ligne (`constants.php:26`, `upstream.json:8-10`), perte du résultat en cas d’erreur. Ajouté : plan d’action, critères d’acceptation, points UNVERIFIED.
- **Révision 3** (7 nov. 2026) : après revue CodeRabbit. Corrigé : compteur sécurité dnf/zypper à `0` (pas `null`) en cas d’échec ; pins apt sur toutes les versions installables, avec `:any`, ordre de lecture et vérification de la priorité effective ; résumé produit après l’installation ; PR 2 garde l’update unitaire des paquets kept back.
