# Étape 1: Image de base Python slim
FROM python:3.9-slim

# Étape 2: Installation des dépendances système corrigées
# On remplace libgl1-mesa-glx par libgl1 et on ajoute libglib2.0-0 (souvent requis par OpenCV)
RUN apt-get update && apt-get install -y \
    libzbar0 \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Étape 3: Répertoire de travail
WORKDIR /app

# Étape 4: Installation des dépendances Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Étape 5: Copie du code
COPY . .

# Étape 6: Lancement avec Gunicorn
# Note : Render utilise souvent le port 10000 par défaut
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:10000", "app:app"]