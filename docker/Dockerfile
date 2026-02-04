# ------------------------------
# QuantumGuard Dockerfile
# ------------------------------

# Base image
FROM python:3.11-slim AS backend

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python dependencies
COPY requirements.txt ./

# Install Python dependencies
RUN python -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy main Python files (repo root)
COPY quantumguard.py ./
COPY self_learning.py ./
COPY utils.py ./

# Copy Python & project folders
COPY app ./app
COPY scanner ./scanner
COPY simulator ./simulator
COPY scripts ./scripts
COPY hardening ./hardening
COPY terraform ./terraform
COPY k8s ./k8s

# Copy dashboard (inside docker folder)
COPY docker/dashboard ./dashboard

# Expose Flask port
EXPOSE 5000

# Flask environment
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Start Flask app
CMD ["flask", "run"]
