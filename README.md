# 📝 Notes

Application de prise de notes auto-hébergée, simple et moderne.

## Fonctionnalités

- 🔐 **Authentification** par mot de passe avec JWT
- 👥 **Multi-utilisateurs** — chaque utilisateur a ses propres notes et dossiers
- 📁 **Dossiers et sous-dossiers** — arborescence imbriquée illimitée
- 🖼️ **Images** — drag & drop, copier-coller, redimensionnement
- ✏️ **Éditeur WYSIWYG** — gras, italique, souligné, couleurs, titres, citations, listes
- ☑️ **Checklists** — listes de tâches avec cases à cocher
- 🔗 **Liens** — auto-détection des URLs, insertion de liens (Ctrl+K)
- 🔍 **Recherche full-text** — indexation FTS5 SQLite pour une recherche rapide
- 🗑️ **Corbeille** — suppression douce avec restauration, purge auto à 30 jours
- 🔒 **Chiffrement** — AES (Fernet) optionnel des notes au repos
- 📌 **Épinglage** de notes importantes
- 🌙 **Thème** sombre / clair (auto-détection)
- 💾 **Sauvegarde automatique** en temps réel
- 📱 **PWA** — installable comme app native sur mobile et desktop
- ⌨️ **Raccourcis** — Ctrl+N (nouvelle note), Ctrl+K (lien), Ctrl+B/I/U

## Déploiement

```bash
# 1. Modifier le mot de passe dans docker-compose.yml
# 2. Optionnel : générer une clé de chiffrement
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# 3. Lancer
docker compose up -d
```

Accessible sur `http://localhost:8080`.

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `USERNAME` | `admin` | Identifiant admin initial |
| `PASSWORD` | `admin` | Mot de passe admin initial |
| `SECRET_KEY` | auto | Clé de signature JWT |
| `ENCRYPTION_KEY` | *(vide)* | Clé Fernet pour chiffrer les notes (optionnel) |
| `TOKEN_EXPIRY_HOURS` | `72` | Durée de validité de la session |
| `TRASH_RETENTION_DAYS` | `30` | Purge automatique de la corbeille |

## Chiffrement

Le chiffrement est **optionnel** et activé uniquement si `ENCRYPTION_KEY` est défini.

- Algorithme : AES-128 via Fernet (cryptography)
- Les notes sont chiffrées au repos dans la base SQLite
- Les images ne sont **pas** chiffrées (stockées en fichiers)
- ⚠️ **Conservez précieusement votre clé** : sans elle, les notes sont irrécupérables

## Multi-utilisateurs

- Le premier utilisateur créé est **administrateur**
- Les admins peuvent créer/supprimer des utilisateurs via le bouton 👥
- Chaque utilisateur a ses propres notes, dossiers et corbeille
- La suppression d'un utilisateur supprime toutes ses données

## Reverse Proxy (BunkerWeb / Nginx)

```nginx
location / {
    proxy_pass http://notes:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 20M;
}
```

## Données

Volume `./data` :
- `notes.db` — base SQLite (notes, dossiers, utilisateurs, index FTS5)
- `uploads/` — images uploadées

## Stack technique

- **Backend** : Python FastAPI + SQLite + FTS5 + cryptography
- **Frontend** : Vanilla JS (zéro dépendance), WYSIWYG contenteditable
- **Container** : ~80 MB (python:3.12-slim)
- **PWA** : Service Worker + manifest.json
