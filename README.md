# EasilyRescue 🚑

**Outil de continuité d'activité pour le DPI Easily**

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python 3.8+](https://img.shields.io/badge/Python-3.8+-green.svg)

## 📋 Description

EasilyRescue est une application de continuité d'activité (PCA) pour les services utilisant le logiciel DPI **Easily** des Hospices Civils de Lyon (HCL).

En cas d'indisponibilité du DPI, l'application automatise :
- ✅ La récupération des archives depuis un serveur SFTP
- ✅ La décompression et l'indexation des fichiers
- ✅ La génération d'un rapport HTML interactif pour consulter les documents patients

## 🚀 Fonctionnalités

- **Connexion SFTP sécurisée** : Support mot de passe ou clé SSH privée
- **Téléchargement parallèle** : Récupération optimisée des archives
- **Vérification d'intégrité** : Validation SHA256 de chaque fichier
- **Mode "téléchargement propre"** : Cache temporaire pour garantir la cohérence des données
- **Décompression parallèle** : Traitement rapide des archives ZIP
- **Rapport HTML dynamique** : Interface web avec recherche, tri et filtrage
- **Journalisation détaillée** : Logs complets pour audit et dépannage

## ⚙️ Installation

### Prérequis
- Python 3.8+
- Git

### Dépendances

EasilyRescue utilise uniquement des bibliothèques Python standard et externes minimales :

#### Bibliothèques standard (incluses avec Python)
- `json` - Manipulation des données JSON et JSONC
- `re` - Expressions régulières pour nettoyage des commentaires
- `logging` - Journalisation des événements
- `pathlib` - Gestion multi-plateforme des chemins
- `typing` - Annotations de types
- `zipfile` - Décompression des archives ZIP
- `datetime` - Gestion des dates et timestamps
- `os` - Interaction système d'exploitation
- `time` - Mesure des temps d'exécution
- `hashlib` - Calcul des checksums SHA256
- `concurrent.futures` - Exécution parallèle des tâches
- `tempfile` - Création de fichiers temporaires sécurisés
- `shutil` - Opérations sur fichiers/dossiers
- `sys` - Interaction avec l'interpréteur Python
- `webbrowser` - Ouverture automatique du rapport HTML
- `html` - Échappement des caractères spéciaux

#### Bibliothèques externes à installer
| Paquet | Version | Utilité |
|--------|---------|---------|
| **paramiko** | ≥2.7.0 | Implémentation SFTP pour connexion et transfert sécurisé |
| **tqdm** | ≥4.50.0 | Barres de progression intelligentes et esthétiques |

### Étapes d'installation

```bash
# 1. Cloner le repository
git clone https://github.com/votre-username/EasilyRescue.git
cd EasilyRescue

# 2. Créer un environnement virtuel (recommandé)
python -m venv venv

# Activer l'environnement virtuel
# Sur Linux/macOS:
source venv/bin/activate

# Sur Windows:
venv\Scripts\activate

# 3. Installer les dépendances externes
pip install paramiko tqdm

# Optionnel : vérifier l'installation
pip list

# 4. Configurer l'application
cp config.example.jsonc config.jsonc
# Éditer config.jsonc avec vos paramètres SFTP
```

### Vérification de l'installation

```bash
# Vérifier que Python est correctement configuré
python --version  # Doit afficher Python 3.8+

# Tester l'import des dépendances
python -c "import paramiko; import tqdm; print('✅ Dépendances OK')"
```

## 🔧 Configuration

### Fichier `config.jsonc`

1. **Copier depuis le template** :
   ```bash
   cp config.example.jsonc config.jsonc
   ```

2. **Remplir les paramètres SFTP** :
   ```jsonc
   {
       "sftp": {
           "hostname": "votre_serveur.com",
           "username": "votre_utilisateur",
           "password": "votre_mot_de_passe",
           // OU utiliser une clé SSH privée
           "private_key_path": "~/.ssh/id_rsa"
       }
   }
   ```

### 🔐 Sécurité

- ⚠️ **Ne jamais commiter** `config.jsonc` sur Git
- ✅ Utiliser `config.example.jsonc` comme template
- ✅ Le fichier `config.jsonc` est dans `.gitignore`

## 🚀 Utilisation

```bash
# Lancer l'application
python EasilyRescue.py

# L'application va :
# 1. Lire la configuration
# 2. Se connecter au serveur SFTP
# 3. Télécharger les archives
# 4. Décompresser les fichiers
# 5. Générer le rapport HTML (index.html)
# 6. Ouvrir automatiquement dans le navigateur
```

## 📊 Structure du projet

```
EasilyRescue/
├── EasilyRescue.py          # Code principal
├── config.example.jsonc     # Template de configuration (à copier)
├── config.jsonc             # Configuration personnelle (ne pas commiter)
├── index.html               # Rapport généré (ne pas commiter)
├── logs/                    # Journaux d'exécution (ne pas commiter)
├── data/                    # Données téléchargées (ne pas commiter)
├── .gitignore               # Règles de sécurité Git
└── README.md                # Cette documentation
```

## 📋 Fichiers envoyés sur GitHub

| Fichier | Statut | Description |
|---------|--------|-------------|
| `EasilyRescue.py` | ✅ Envoyé | Code source |
| `config.example.jsonc` | ✅ Envoyé | Template configuration |
| `.gitignore` | ✅ Envoyé | Règles de sécurité |
| `README.md` | ✅ Envoyé | Documentation |
| `config.jsonc` | ❌ Exclu | Secrets (dans .gitignore) |
| `logs/` | ❌ Exclu | Journaux système |
| `data/` | ❌ Exclu | Données volumineuses |
| `index.html` | ❌ Exclu | Rapport généré |

## 🔍 Dépannage

### Les données ne se téléchargent pas
- Vérifiez la connexion SFTP dans `config.jsonc`
- Vérifiez que le serveur est accessible
- Consultez les logs dans `logs/`

### Erreur de décompression
- Vérifiez l'intégrité des fichiers ZIP
- Assurez-vous d'avoir suffisamment d'espace disque

## 📝 Logs

Les journaux d'exécution sont disponibles dans le dossier `logs/` :
```
logs/
├── main_2026_02_09.log
├── main_2026_02_10.log
└── main_2026_02_11.log
```

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👤 Auteur

- **Bertrand Kuzbinski** - Designer/Développeur

## 🤝 Contribution

Les contributions sont bienvenues ! N'hésitez pas à :
1. Fork le repository
2. Créer une branche pour votre feature (`git checkout -b feature/ma-feature`)
3. Commiter vos changements (`git commit -m 'Ajout de ma feature'`)
4. Pousser vers la branche (`git push origin feature/ma-feature`)
5. Ouvrir une Pull Request

## 📞 Support

Pour toute question ou problème, veuillez :
- Ouvrir une issue sur GitHub
- Vérifier les logs dans le dossier `logs/`

---

**Dernière mise à jour** : 11 février 2026
# EasilyRescue
