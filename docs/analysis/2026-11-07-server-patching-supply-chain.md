# Coolify — mises à jour des paquets VPS et protections supply chain

**Date :** 7 novembre 2026  
**Dépôt analysé :** `coollabsio/coolify`, fork `imryanthedev/coolify`  
**Commit analysé :** `29aa42b98` (`main`, 6 novembre 2026)  
**Dernière release stable :** `v4.6.0` (2 novembre 2026)  
**Portée :** patching des paquets du système d’exploitation des serveurs gérés (apt, dnf, zypper, pacman, apk), protections supply chain associées, et supply chain de Coolify lui-même.

> Analyse en lecture seule. Aucune modification n’a été apportée au dépôt ni à l’instance.

---

## 1. Résumé exécutif

Coolify sait aujourd’hui **détecter** les mises à jour de paquets d’un serveur, les **notifier**, et les **installer** de deux façons :

1. **manuellement** (tout ou paquet par paquet) ;
2. **automatiquement**, mais uniquement pour les **mises à jour de sécurité**, via `unattended-upgrades` (apt) ou `dnf-automatic` (dnf).

Les protections supply chain réellement présentes sont **celles du gestionnaire de paquets** (signatures GPG des dépôts), plus quelques garde-fous Coolify :

- mises à jour automatiques **opt-in** et **sécurité uniquement** ;
- respect des **phased updates** Ubuntu et des paquets `hold`/pinned ;
- avertissements sur les paquets risqués (Docker, kernel, systemd/glibc/openssh) ;
- audit log des actions ;
- détection des mises à jour disponibles, avec compteur sécurité et reboot requis.

Il **n’y a pas** :

- d’âge minimum de release / cooldown ;
- d’exclusion ou d’allowlist de paquets pour l’auto-update ;
- de vérification d’intégrité ou de signature des artefacts de mise à jour de Coolify (CDN, images Docker) ;
- de scan CVE des paquets de l’hôte dans la stable (une PR est ouverte) ;
- d’intégration socket.dev.

**Ce qui est prévu / en cours :**

- `v4.7` (mergée sur `main`, non publiée) : scan CVE des images de conteneurs, SSH host key pinning, notifications d’auto-update.
- **PR #12482** (ouverte) : scan CVE des paquets OS de l’hôte avec Syft/Grype, page « Host Vulnerabilities ». C’est de la **visibilité**, pas de la prévention.
- **Aucune issue ni discussion dédiée** à un âge minimum ou à socket.dev pour les paquets VPS.

**Conclusion :** un cooldown est faisable, mais il n’existe pas de date de publication native par paquet dans apt/dnf. La solution réaliste est un **âge « première vue par Coolify »**, avec un job d’observation quotidien et soit des pins apt dynamiques, soit une prise en charge de l’installation par Coolify. socket.dev n’est **pas adapté aux paquets APT** ; il peut en revanche servir à la CI du dépôt Coolify.

---

## 2. Ce que fait le code aujourd’hui

### 2.1 Deux mécanismes distincts

| Mécanisme | Rôle | Installe ? | Fréquence par défaut |
|---|---|---|---|
| **Patch check** (`ServerPatchCheckJob`) | Détecter les mises à jour, les classer, notifier | Non | Hebdomadaire, dimanche, heure stable par serveur entre 04:00 et 23:59 |
| **Auto security updates** (`ConfigureAutomaticSecurityUpdates`) | Configurer l’OS pour installer les correctifs sécurité | Oui, par l’OS | Quotidienne, à l’heure choisie (fuseau du serveur) |
| **Update manuel** (`UpdatePackage`) | Installer tout ou un paquet | Oui, par Coolify en SSH | À la demande |

Le check et l’auto-update sont **indépendants** : le check peut être hebdomadaire alors que l’auto-update tourne tous les jours.

### 2.2 Le patch check

- Planification : `app/Jobs/ServerManagerJob.php:254` et `:290`.
  - Par défaut : dimanche, entre 04:00 et 23:59, avec un décalage stable par serveur (`id % (20 * 60)`).
  - Fréquence personnalisée : preset `daily`, `weekly`, `monthly`, ou expression cron, avec un maximum d’un run par heure (`app/Livewire/Server/Security/Patches.php:225`).
- Détection : `app/Actions/Server/CheckUpdates.php:133`.
  - **apt** : `apt-get update`, `apt list --upgradable`, puis deux simulations (`apt-get -s upgrade` avec et sans `APT::Get::Always-Include-Phased-Updates=true`) pour identifier les phased updates, plus `apt-mark showhold`.
  - **dnf** : `dnf repoquery --upgrades --latest-limit 1`, `rpm -qa` pour les versions installées, `dnf updateinfo list --security`.
  - **zypper** : `zypper -tx list-updates`, puis dry-run `zypper patch --dry-run --category security`.
  - **pacman** : `checkupdates` si disponible, sinon base temporaire (pas de `pacman -Sy` sur la base live).
  - **apk** : `apk update`, `apk list --upgradable`, simulation `apk upgrade -s` pour les pins.
- Données produites :
  - paquet, version actuelle, nouvelle version, architecture, dépôt ;
  - `security` (apt : dépôt `-security` ; dnf/zypper : avis sécurité ; pacman/apk : inconnu) ;
  - `risk` : `docker`, `kernel`, `system` (`CheckUpdates.php:94`) ;
  - `reboot_required` ;
  - `held_updates` avec raison `phased` ou `held`.
- Stockage : `server_settings.patch_check_result` (un seul JSON, écrasé à chaque check), `patch_check_error`, `patch_checked_at`.
- Notification : `ServerPatchCheck` (email, Discord, Slack, Telegram, webhook) si `total_updates > 0` et check non manuel. Un check manuel ne notifie pas les mises à jour, seulement les erreurs.

**Limite importante :** le check n’installe rien. Il ne fait que constater.

### 2.3 L’installation manuelle

`app/Actions/Server/UpdatePackage.php:84` :

| Gestionnaire | Mise à jour de tous les paquets | Mise à jour d’un paquet |
|---|---|---|
| apt | `apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade` | `apt-get ... install --only-upgrade <pkg>` |
| dnf | `dnf upgrade -y` | `dnf upgrade -y <pkg>` |
| zypper | `zypper --non-interactive update` | `zypper --non-interactive update <pkg>` |
| pacman | `pacman -Syu --noconfirm` | interdit (full upgrade only) |
| apk | `apk upgrade` | `apk upgrade <pkg>` |

Garde-fous :

- confirmation à taper dans l’UI ;
- avertissement sur le nombre de paquets risqués ;
- validation du nom de paquet (regex + `escapeshellarg`) ;
- audit log `ui.server.packages_update_finished` ;
- nouveau check après l’update (`app/Listeners/FinishServerPackagesUpdate.php:41`).

**Détail apt :** « Update all » utilise `apt-get upgrade`, pas `dist-upgrade`/`full-upgrade`. Les paquets qui nécessitent l’installation d’un nouveau paquet (typiquement les méta-paquets kernel) sont « kept back » et ne sont pas installés. Le check les affiche pourtant comme disponibles. À l’inverse, l’update d’un paquet unique utilise `apt-get install --only-upgrade`, qui peut installer de nouvelles dépendances.

### 2.4 L’auto-update sécurité

`app/Actions/Server/ConfigureAutomaticSecurityUpdates.php` :

- **apt (Debian/Ubuntu)** :
  - installe `unattended-upgrades` si absent ;
  - écrit `/etc/apt/apt.conf.d/52coolify-unattended-upgrades` ;
  - `#clear` supprime les origines des fichiers distro ;
  - ne garde que les origines de sécurité : Debian `<codename>-security`, Ubuntu `<codename>-security`, Ubuntu Pro ESM apps/infra ;
  - drop-in `/etc/systemd/system/apt-daily-upgrade.timer.d/coolify.conf` pour l’heure, avec `RandomizedDelaySec=0` ;
  - active `apt-daily.timer` et `apt-daily-upgrade.timer`.
- **dnf (RHEL/Fedora)** :
  - installe `dnf-automatic` ;
  - modifie `/etc/dnf/automatic.conf` : `upgrade_type = security`, `apply_updates = yes` ;
  - drop-in sur `dnf-automatic.timer` (dnf4) ou `dnf5-automatic.timer` (dnf5) ;
  - active le timer.
- **Non supporté** : zypper, pacman, apk.
- **Pas de redémarrage automatique** : le kernel peut être installé, mais le serveur n’est pas rebooté ; Coolify affiche « Reboot required » au prochain check.
- **Pas de notification du résultat** : si `unattended-upgrades` échoue, Coolify ne le sait pas avant le prochain patch check (une semaine par défaut).
- **Désactivation dnf incomplète** : le timer est désactivé et le drop-in retiré, mais `automatic.conf` garde `upgrade_type=security` et `apply_updates=yes`.

### 2.5 Versions concernées

- La fonctionnalité « server patching » est sortie en **v4.5.0** (release notes : « Added server patching (beta) with automatic security updates per server »).
- Elle est encore marquée **beta** dans l’UI.
- La dernière stable est **v4.6.0**.
- `main` contient la **v4.7** mergée (PR #12478) mais non publiée : `release.json` pointe encore `4.6.0`.

---

## 3. Protections supply chain existantes

| Contrôle | État | Couvre | Ne couvre pas |
|---|---|---|---|
| Signature GPG des dépôts | ✅ hérité | apt/dnf/zypper/pacman/apk vérifient métadonnées et paquets | Un paquet malveillant publié dans un dépôt officiel |
| Mises à jour sécurité uniquement | ✅ | Réduit la surface en auto | Les paquets malveillants dans `-security` |
| Opt-in | ✅ | Auto off par défaut | — |
| Confirmation manuelle | ✅ | Update all / reboot | — |
| Phased updates Ubuntu | ✅ subi | Délai de rollout natif Ubuntu | Debian, dnf, zypper, pacman, apk |
| `apt-mark hold` / pins apk | ✅ respecté | Paquets volontairement bloqués | — |
| Avertissement paquets risqués | ✅ | Docker, kernel, systemd/glibc/openssh | L’auto sécurité n’exclut pas ces paquets |
| Audit | ✅ | Qui a lancé quoi, résultat | Le résultat de l’auto-update OS |
| Notification du check | ✅ | Mises à jour disponibles, erreurs | Succès/échec de `unattended-upgrades` |
| Reboot requis | ✅ affiché | Après kernel/system | Pas de reboot automatique |
| Scan CVE hôte | 🟡 PR #12482 | Visibilité Syft/Grype | Prévention, âge minimum |
| Scan CVE images | 🟡 v4.7 non publiée | Images de conteneurs, deploy gate | Paquets de l’hôte |
| socket.dev | ❌ | — | — |
| CI dépendances | ❌ | — | Pas de Dependabot/Renovate/audit |

### 3.1 Le point clé : l’auto-update est déléguée à l’OS

Quand l’auto sécurité est active, **c’est `unattended-upgrades`/`dnf-automatic` qui décide** des paquets. Coolify :

- ne voit pas la liste installée ;
- ne peut pas appliquer de cooldown, d’exclusion ou de règle par paquet ;
- ne récupère pas le résultat.

C’est robuste (ça tourne même si Coolify est down), mais c’est ce qui rend un « minimum release age » non trivial : il faut soit contraindre l’outil OS, soit reprendre l’exécution.

### 3.2 Le supply chain de Coolify lui-même

À distinguer des paquets du VPS :

- **Scripts CDN** : `install.sh`, `upgrade.sh`, `docker-compose*.yml`, `.env.production` sont téléchargés depuis `cdn.coollabs.io` **sans checksum ni signature** (`scripts/install.sh:889`, `scripts/upgrade.sh:126`). TLS uniquement.
- **Docker** : `install.sh` exécute encore `curl -fsSL https://get.docker.com | sh` (`scripts/install.sh:707`). Discussion #5503 : le maintainer assume la confiance dans le CDN et Docker, avec un projet futur d’installeur en Go.
- **Images Coolify/helper/Traefik** : tirées **par tag** (`docker-compose.prod.yml:8`), pas par digest.
- **Images pinned par digest** : scanners Syft/Grype/regctl (`config/constants.php:92`), `rclone` (`config/constants.php:22`), `sentinel-host` (`upstream.json:8`).
- **Build CI** : provenance SLSA + SBOM (`provenance: mode=max`, `sbom: true`, `.github/workflows/build.yaml:106`), mais **aucun consommateur ne vérifie ces attestations** à l’upgrade.
- **Exemple inverse** : `InstallSysbox` vérifie bien un SHA256 (`app/Actions/Server/InstallSysbox.php:137`) ; ce n’est pas appliqué aux artefacts du CDN.

---

## 4. Ce qui manque

1. **Pas d’âge minimum.** Le check écrase le dernier résultat (`server_settings.patch_check_result`), donc pas d’historique « première fois vue » par paquet/version. Un cooldown nécessite une nouvelle table ou un JSON historique.
2. **Pas d’exclusion.** Impossible de dire « ne jamais auto-updater docker.io/containerd/kernel » ou « seulement ces paquets ».
3. **Pas de staging/approbation.** L’update manuel « all » exécute directement ; le check est une simulation, mais il n’y a pas de « préparer puis approuver ».
4. **Pas de visibilité sur l’auto-update.** Pas de notification de succès/échec, pas de liste de ce qui a été installé par `unattended-upgrades`.
5. **Pas de rollback.** Une mise à jour qui casse un service ne peut pas être annulée par Coolify.
6. **Pas de scan CVE de l’hôte dans la stable.** PR #12482 ouverte, pas releasée.
7. **Pas de protection contre les paquets malveillants.** Le GPG protège contre un miroir compromis, pas contre un mainteneur qui publie un paquet malveillant dans le dépôt officiel (type xz). Aucun âge minimum, aucune réputation, aucune allowlist.
8. **Détail apt** : « Update all » ne peut pas installer les paquets qui nécessitent de nouvelles dépendances (kernel meta). Le check les affiche pourtant.
9. **Détail dnf** : la désactivation ne restaure pas `automatic.conf`.

---

## 5. Ce qui est prévu / en cours

- **v4.7** (mergée sur `main`, pas publiée) : scan de vulnérabilités des images de conteneurs (#12377), SSH host key pinning, notifications d’auto-update de Coolify, etc.
- **PR #12482** (ouverte, base `next`, mergeable, par le maintainer) : scan CVE des paquets OS de l’hôte avec Syft/Grype, page « Host Vulnerabilities », scan après update et « Scan now ». Détection a posteriori, pas prévention.
- **PR #11791** (fermée, non mergée) : « stable/RC channel and patch-only auto updates » pour Coolify lui-même. La partie canaux a été livrée autrement (#12359) ; le « patch-only » n’est pas dans `main`.
- **Aucune issue/discussion dédiée** à un âge minimum ou à socket.dev. Recherches effectuées : `minimum release age`, `cooldown`, `quarantine`, `socket.dev`, `supply chain`, `malicious package`, `staged rollout`, `phased updates`.
- Discussions proches :
  - **#5503** : supply chain de l’installeur (réponse maintainer : confiance CDN/Docker, futur installeur Go) ;
  - **#8353** : « Allow servers to automatically update » (0 réponse) ;
  - **#9538** : les utilisateurs demandent s’ils doivent attendre quelques jours avant d’updater Coolify (réponse communautaire : oui, quelques jours) ;
  - **#7578** : avertir avant de mettre à jour Traefik avec les paquets serveur (fermée) ;
  - **#11890** : auto-update qui échouait sans retry (corrigé : retry/backoff + fréquence aléatoire par instance).

**Conclusion :** il n’y a pas de plan produit existant pour un cooldown ou socket.dev. Pour ce comportement, il faut ouvrir une Discussion (obligatoire pour une feature selon `CONTRIBUTING.md`), puis une issue et une PR vers `next`.

---

## 6. Faisabilité d’un « minimum release age »

### 6.1 Le problème de la sémantique

Il n’existe pas de « date de publication » native par paquet dans apt/dnf. Trois approches :

| Approche | Principe | Avantages | Inconvénients |
|---|---|---|---|
| **Première vue par Coolify** | Enregistrer la première fois qu’une version apparaît, installer après N jours | Portable (apt, dnf, zypper, apk, pacman) | Dépend de la fréquence d’observation ; nécessite un job quotidien |
| **Snapshot de dépôt** | Épingler les sources à une date (`snapshot.debian.org`, `snapshot.ubuntu.com`) | Âge réel | Lourd, change les sources, peut retarder les correctifs |
| **Phased updates Ubuntu** | N’installer qu’à 100 % de rollout | Déjà natif | Ubuntu uniquement, pas un âge |

Avec un check hebdomadaire, un cooldown de 7 jours n’a pas de sens : il faut un job d’observation **quotidien** (sans notification) ou imposer un check quotidien quand le cooldown est actif.

### 6.2 Trois options d’implémentation

#### Option A — MVP observation seule (petit PR, faible risque)

- Nouvelle table `server_package_observations` : `server_id`, `package`, `version`, `first_seen_at`, `last_seen_at`, `security`.
- Remplie par `ServerPatchCheckJob` (sans notification supplémentaire).
- Afficher « disponible depuis X jours » sur la page Patches.
- Aucun changement de comportement.

C’est le prérequis de tout le reste.

#### Option B — Cooldown via wrapper OS (recommandé pour apt)

Un script + timer systemd poussé par Coolify :

1. `apt-get update` ;
2. maintient un JSON local `version → first_seen` ;
3. écrit des pins apt (`Pin-Priority: -1`) pour les versions trop récentes ;
4. lance `unattended-upgrades` ;
5. retire les pins ;
6. écrit un journal que Coolify lit pour notifier.

Avantages : garde la robustesse de `unattended-upgrades` et le fonctionnement même si Coolify est down.  
Inconvénients : script supplémentaire à maintenir, pins apt à gérer proprement.

#### Option C — Prise en charge complète par Coolify (plus de contrôle, plus de surface)

Coolify calcule la liste éligible et exécute :

```bash
apt-get install --only-upgrade pkg1=version1 pkg2=version2
# ou
dnf upgrade -y pkg1 pkg2
```

via son scheduler ou un timer poussé. Avantages : exclusion, cooldown, notifications, journal unifié. Inconvénients : gérer les échecs, les redémarrages, et le cas où Coolify est indisponible.

**Recommandation :** commencer par l’option A (données + UI), puis l’option B pour apt/dnf. Éviter un cooldown global sur Arch : un `pacman -Syu` retardé peut provoquer un partial upgrade non supporté.

### 6.3 Points de conception à trancher

- Cooldown par défaut à 0 (comportement actuel) ou 2–7 jours ?
- Sécurité uniquement ou toutes les mises à jour ?
- Paquets risqués (docker/kernel) : exclusion par défaut de l’auto, ou confirmation ?
- Notification : digest quotidien des paquets « en attente de cooldown » et des échecs.
- Que faire si le check n’a pas tourné depuis N jours (Coolify down) ?

---

## 7. Faisabilité de socket.dev

**Pas adapté aux paquets APT/Ubuntu.** Socket.dev analyse les dépendances de code (npm, PyPI, Go, RubyGems, NuGet, Maven, GitHub Actions…) pour détecter malware/typosquatting. Il n’y a pas d’équivalent pour les paquets système Debian/RHEL. Le brancher sur Coolify ne protégerait donc **pas** les mises à jour du VPS.

Là où socket.dev peut servir :

- sur le **dépôt Coolify** lui-même, pour les dépendances JS (`package.json`, `bun.lock`) et éventuellement les GitHub Actions ; le support de Composer est à vérifier, il n’est pas garanti ;
- sur les dépôts des **applications des utilisateurs**, mais c’est un autre produit (scan de code), pas le patch management du serveur.

Pour les paquets de l’hôte, les équivalents réalistes sont :

- **Grype/Syft** (déjà dans #12482) pour les CVE ;
- **OSV / CISA KEV** pour les signaux d’exploitation (déjà utilisés par l’image scan) ;
- **`debsums` / `rpm -Va`** pour l’intégrité des fichiers installés ;
- **OpenSCAP / Ubuntu Security Guide** pour le hardening et les contrôles CIS ;
- **allowlist + cooldown** pour limiter les paquets auto-installés ;
- **Ubuntu Pro / ESM** pour les correctifs sécurité des paquets universe.

Donc : **socket.dev = oui pour la CI du repo Coolify, non pour les paquets VPS.** Si l’objectif est « détecter un paquet malveillant dans APT », il n’y a pas de solution clé en main ; le cooldown + allowlist + scan CVE + intégrité est le compromis pragmatique.

---

## 8. Proposition de ticket + PR

Le process Coolify est strict (`CONTRIBUTING.md`) :

1. **Discussion obligatoire** pour toute feature ou changement de comportement, dans **Improvement Requests** :  
   <https://github.com/coollabsio/coolify/discussions/categories/improvement-requests>
2. Ensuite une **issue** avec le comportement attendu, les cas d’erreur, et les tests envisagés.
3. PR vers **`next`** (pas `main`), un seul changement logique par PR, avec tests Pest, `vendor/bin/pint`, et capture/vidéo pour l’UI.
4. Le template de PR contient une consigne de mot-clé piégée que le workflow `pr-quality` bloque explicitement. Ne pas la suivre. Remplir la section « AI Assistance » honnêtement.

### Découpage recommandé

| PR | Contenu | Risque |
|---|---|---|
| **PR 1 — observation** | Migration `server_package_observations`, first-seen/last-seen dans `ServerPatchCheckJob`, affichage « disponible depuis X jours », tests | Faible |
| **PR 2 — cooldown auto** | Réglage `min_age_days` (0 = off) + `excluded_packages`, génération du wrapper/pins apt, tests de commandes et d’éligibilité | Moyen |
| **PR 3 — notifications** | Résultat de l’auto-update (succès/échec, paquets installés, paquets en attente), parsing `unattended-upgrades`/`dnf-automatic` | Faible |
| **PR 4 — supply chain Coolify** | Checksums/signatures des artefacts CDN, pins par digest dans `versions.json`/compose, vérification cosign, Dependabot/Renovate + `composer audit`/`npm audit` + socket.dev GitHub App | Moyen |

### Critères d’acceptation pour la PR 2

- Un paquet dont la version est vue pour la première fois depuis moins de `min_age_days` n’est pas installé par l’auto-update.
- Le comportement est inchangé si `min_age_days = 0`.
- Les paquets exclus ne sont jamais installés automatiquement.
- L’UI explique pourquoi un paquet est en attente.
- Les tests couvrent apt et dnf, les paquets sécurité/non-sécurité, et le cas où le check n’a pas tourné.
- L’audit log enregistre les décisions (installé / reporté / exclu).

---

## 9. Références

### Code

- `app/Actions/Server/CheckUpdates.php`
- `app/Actions/Server/UpdatePackage.php`
- `app/Actions/Server/ConfigureAutomaticSecurityUpdates.php`
- `app/Jobs/ServerPatchCheckJob.php`
- `app/Jobs/ServerManagerJob.php`
- `app/Livewire/Server/Security/Patches.php`
- `resources/views/livewire/server/security/patches.blade.php`
- `app/Listeners/FinishServerPackagesUpdate.php`
- `scripts/install.sh`, `scripts/upgrade.sh`
- `config/constants.php`, `upstream.json`, `docker-compose.prod.yml`, `docker/production/Dockerfile`
- `.github/workflows/build.yaml`

### GitHub

- Release v4.5.0 : <https://github.com/coollabsio/coolify/releases/tag/v4.5.0>
- Release v4.6.0 : <https://github.com/coollabsio/coolify/releases/tag/v4.6.0>
- PR host scan : <https://github.com/coollabsio/coolify/pull/12482>
- PR image scan : <https://github.com/coollabsio/coolify/pull/12377>
- PR v4.7 : <https://github.com/coollabsio/coolify/pull/12478>
- PR patch-only auto updates (fermée) : <https://github.com/coollabsio/coolify/pull/11791>
- PR update channels : <https://github.com/coollabsio/coolify/pull/12359>
- Discussion supply chain installeur : <https://github.com/coollabsio/coolify/discussions/5503>
- Discussion auto-update serveurs : <https://github.com/coollabsio/coolify/discussions/8353>
- Discussion « attendre quelques jours » : <https://github.com/coollabsio/coolify/discussions/9538>
- Discussion Traefik vs paquets : <https://github.com/coollabsio/coolify/discussions/7578>
- Issue retry auto-update : <https://github.com/coollabsio/coolify/issues/11890>
- Discussions UI patching : #11846, #11860, #10630, #8818

---

## 10. Limites de cette analyse

- Analyse statique du code et des discussions publiques ; pas de test sur une instance réelle.
- Les comportements d’apt/dnf peuvent varier selon la version du gestionnaire de paquets et la distribution.
- Les issues/discussions ont été recherchées avec plusieurs mots-clés ; une discussion peut exister sous une formulation différente.
- Le statut des PR et releases évolue vite : vérifier `release.json` et les tags avant d’agir.
