# Dépendances Linux pour Backfirewall

## Dépendances système requises

### 1. Node.js et npm
- **Node.js** : Version 18 ou supérieure (recommandé : 20.x)
- **npm** : Inclus avec Node.js

#### Installation sur Debian/Ubuntu :
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
```

#### Installation sur CentOS/RHEL :
```bash
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo yum install -y nodejs
```

### 2. systemd
- **systemd** : Nécessaire pour le service de démarrage automatique
- Généralement déjà installé sur les distributions Linux modernes

#### Vérification :
```bash
systemctl --version
```

#### Installation si manquant (rare) :
```bash
# Debian/Ubuntu
sudo apt-get install systemd

# CentOS/RHEL
sudo yum install systemd
```

### 3. Commandes système
Les commandes suivantes doivent être disponibles :

- **df** : Pour l'utilisation du disque (généralement dans `coreutils`)
- **systemctl** : Pour la gestion du service (inclus avec systemd)

#### Installation si manquant :
```bash
# Debian/Ubuntu
sudo apt-get install coreutils

# CentOS/RHEL
sudo yum install coreutils
```

### 4. Fichiers système Linux
L'application lit les fichiers suivants (généralement présents sur tous les systèmes Linux) :

- `/proc/stat` : Statistiques CPU
- `/proc/net/dev` : Statistiques réseau
- `/etc/os-release` : Informations sur le système d'exploitation
- `/etc/debian_version` : Version Debian (si applicable)

Ces fichiers sont généralement disponibles par défaut sur les systèmes Linux.

## Dépendances Node.js

Les dépendances Node.js sont installées automatiquement avec `npm install` :

### Dépendances de production :
- `express` : Framework web
- `axios` : Client HTTP
- `dotenv` : Gestion des variables d'environnement

### Dépendances de développement :
- `typescript` : Compilateur TypeScript
- `@types/node` : Types TypeScript pour Node.js
- `@types/express` : Types TypeScript pour Express
- `ts-node-dev` : Outil de développement

## Installation complète

Pour installer toutes les dépendances système sur Debian/Ubuntu :

```bash
# Mettre à jour les paquets
sudo apt-get update

# Installer Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# Vérifier l'installation
node --version
npm --version
```

Pour CentOS/RHEL :

```bash
# Installer Node.js 20.x
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo yum install -y nodejs

# Vérifier l'installation
node --version
npm --version
```

## Vérification des prérequis

Exécutez ces commandes pour vérifier que tout est installé :

```bash
# Vérifier Node.js
node --version  # Doit être >= 18.0.0

# Vérifier npm
npm --version

# Vérifier systemd
systemctl --version

# Vérifier df
df --version

# Vérifier les fichiers système
test -f /proc/stat && echo "✓ /proc/stat existe"
test -f /proc/net/dev && echo "✓ /proc/net/dev existe"
test -f /etc/os-release && echo "✓ /etc/os-release existe"
```

## Notes

- L'application fonctionne sur **tous les systèmes Linux** avec systemd
- Les fonctionnalités réseau (bande passante) fonctionnent uniquement sur Linux (pas Windows)
- Le service systemd nécessite des privilèges root ou sudo pour l'installation

