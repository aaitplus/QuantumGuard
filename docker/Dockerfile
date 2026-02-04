# =========================
# QuantumGuard Dockerfile
# Build from repo root
# =========================

# -------------------------
# Base Python Image
# -------------------------
FROM python:3.11-slim AS build

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        libffi-dev \
        libssl-dev \
        pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies in a venv
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# -------------------------
# Runtime Image
# -------------------------
FROM python:3.11-slim AS runtime

# Set working directory
WORKDIR /app

# Copy virtual environment from build stage
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# -------------------------
# Copy all app code
# -------------------------
COPY utils.py ./utils.py
COPY quantumguard.py ./quantumguard.py
COPY self_learning.py ./self_learning.py

COPY app/ ./app/
COPY scanner/ ./scanner/
COPY simulator/ ./simulator/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/

# Copy dashboard folder
COPY docker/dashboard/ ./dashboard/

# -------------------------
# Expose port for Flask (if used)
# -------------------------
EXPOSE 5000

# -------------------------
# Default command
# -------------------------
CMD ["python", "quantumguard.py"]
