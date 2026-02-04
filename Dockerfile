# =========================
# Stage 1: Build Python Environment
# =========================
FROM python:3.11-slim AS build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libffi-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set workdir for build stage
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN python -m venv /opt/venv
RUN /opt/venv/bin/pip install --upgrade pip
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# =========================
# Stage 2: Runtime Image
# =========================
FROM python:3.11-slim AS runtime

# Set workdir for runtime
WORKDIR /app

# Copy Python venv from build
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY quantumguard.py .
COPY self_learning.py .
COPY utils.py .

# Copy directories
COPY app/ ./app/
COPY docker/dashboard/ ./dashboard/
COPY hardening/ ./hardening/
COPY k8s/ ./k8s/
COPY scanner/ ./scanner/
COPY simulator/ ./simulator/
COPY scripts/ ./scripts/
COPY terraform/ ./terraform/

# Expose Flask port for dashboard if needed
EXPOSE 5000

# Default command
CMD ["python", "quantumguard.py"]
