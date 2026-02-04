# ===============================
# QuantumGuard Dockerfile
# ===============================

# Base Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies
COPY ../requirements.txt ./
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy main Python files from repo root
COPY ../quantumguard.py ./
COPY ../self_learning.py ./
COPY ../utils.py ./

# Copy folders from repo root
COPY ../app ./app
COPY ../scanner ./scanner
COPY ../simulator ./simulator
COPY ../scripts ./scripts
COPY ../hardening ./hardening
COPY ../terraform ./terraform
COPY ../k8s ./k8s

# Copy dashboard folder from docker/
COPY ./dashboard ./dashboard

# Expose Flask default port
EXPOSE 5000

# Set Flask environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Default command
CMD ["flask", "run"]
