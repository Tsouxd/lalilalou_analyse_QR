# Étape 1: Partir d'une image de base officielle Python
# On utilise une version "slim" pour qu'elle soit plus légère et rapide à déployer.
FROM python:3.9-slim

# Étape 2: Installer les dépendances SYSTÈME (Linux)
# C'est la ligne la plus importante, qui corrige votre erreur "Unable to find zbar".
# - libzbar0 : Le "moteur" C requis par pyzbar.
# - libgl1-mesa-glx : Une dépendance graphique souvent requise par opencv-python.
RUN apt-get update && apt-get install -y \
    libzbar0 \
    libgl1-mesa-glx \
    && rm -rf /var/lib/apt/lists/*

# Étape 3: Définir le répertoire de travail dans le conteneur
# Toutes les commandes suivantes s'exécuteront dans ce dossier.
WORKDIR /app

# Étape 4: Copier et installer les dépendances PYTHON
# On copie d'abord SEULEMENT le fichier requirements.txt pour optimiser le cache de Docker.
COPY requirements.txt .
# On installe les librairies listées dans le fichier.
RUN pip install --no-cache-dir -r requirements.txt

# Étape 5: Copier le reste du code de votre application
# On copie app.py, les dossiers templates/, etc., dans le conteneur.
COPY . .

# Étape 6: La commande pour démarrer votre application en production
# On utilise Gunicorn, un serveur web robuste pour Flask.
# - Render demande d'utiliser le port 10000.
# - app:app signifie "dans le fichier app.py, lance l'objet nommé app".
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:10000", "app:app"]