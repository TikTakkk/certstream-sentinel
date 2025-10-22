# 🛰️ certstream-sentinel
Silent multi-threaded CertStream scanner basé sur CertStream — découvre automatiquement des domaines et sous-domaines, puis détecte les fichiers sensibles exposés (.env, .git/config, phpinfo.php). Optimisé pour la stabilité, la mémoire et les longues exécutions continues.

# BUY API REVERSE
**https://t.me/tomaMA212** 

# 🛰️ certstream-sentinel

**certstream-sentinel** est un scanner silencieux basé sur **CertStream**, conçu pour découvrir automatiquement des domaines en temps réel à partir des certificats SSL/TLS.  
Il recherche ensuite des sous-domaines, teste la présence de fichiers sensibles (`.env`, `.git/config`, `phpinfo.php`) et enregistre les résultats trouvés.

> ⚠️ **Utilisation légale uniquement.**  
> N’exécutez ce programme que sur des cibles dont vous avez l’autorisation. L’auteur décline toute responsabilité en cas d’abus.

---

## 🚀 Fonctionnalités principales

- 🔁 Connexion en temps réel à **CertStream** (`wss://certstream.calidog.io/`)
- 🌐 Découverte automatique de **domaines et sous-domaines**
- 🧠 Détection de fichiers sensibles exposés :
  - `.env`
  - `.git/config`
  - `phpinfo.php`
- 🧩 **Multithreadé** (300 workers par défaut)
- 🔇 **Mode silencieux** par défaut : une seule ligne de progression affichée
- ♻️ Gestion de la mémoire :
  - Purge automatique de la cache `seen`
  - File d’attente bornée (évite l’OOM)
  - Garbage Collector déclenché périodiquement
- 🔌 **Reconnexion automatique** à CertStream
- ✅ **Arrêt propre** (flush & fermeture des fichiers)

---

## 📂 Fichiers et répertoires générés

| Répertoire | Contenu |
|-------------|----------|
| `domaine/` | Liste des domaines scannés (`domaine.txt`) |
| `vulnerable_env/` | URLs contenant un `.env` exposé |
| `vulnerable_git/` | URLs contenant un `.git/config` exposé |
| `vulnerable_phpinfo/` | URLs de `phpinfo.php` détectées |

---

## ⚙️ Prérequis

- Go 1.20 ou version supérieure  
- Connexion Internet (WebSocket + API sous-domaines)  
- Linux / macOS / Windows compatible Go  

---

## 🛠️ Installation

```bash
git clone https://github.com/TikTakkk/certstream-sentinel.git
cd certstream-sentinel
go build -o certstream-sentinel main.go
