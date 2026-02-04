# Use Python slim as base
FROM python:3.11-slim AS build

# Set workdir
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python deps
COPY requirements.txt ./
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# =========================
# Runtime image
# =========================
FROM python:3.11-slim AS runtime

# Set workdir
WORKDIR /app

# Copy venv from build stage (optional, or install again)
# COPY --from=build /opt/venv /opt/venv

# Copy all Python scripts and folders
COPY utils.py ./
COPY docker/quantumguard.py ./
COPY docker/self_learning.py ./

COPY app/ ./app/
COPY docker/dashboard/ ./dashboard/
COPY scanner/ ./scanner/
COPY simulator/ ./simulator/
COPY hardening/ ./hardening/
COPY scripts/ ./scripts/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/

# Expose Flask port (adjust if needed)
EXPOSE 5000

# Default command
CMD ["python", "quantumguard.py"]
