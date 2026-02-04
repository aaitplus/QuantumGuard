# =========================
# Build Stage
# =========================
FROM python:3.11-slim AS build

WORKDIR /app

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install in virtualenv
COPY requirements.txt .
RUN python -m venv /opt/venv
RUN /opt/venv/bin/pip install --upgrade pip
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# =========================
# Runtime Stage
# =========================
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy Python virtual environment
COPY --from=build /opt/venv /opt/venv

# Copy app source files
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/
COPY scanner/ ./scanner/
COPY simulator/ ./simulator/
COPY hardening/ ./hardening/
COPY docker/quantumguard.py ./quantumguard.py
COPY docker/self_learning.py ./self_learning.py

# Copy dashboard folder
COPY docker/dashboard/ ./dashboard/

# Copy utils
COPY utils.py ./

# Expose Flask port
EXPOSE 5000

# Set Python environment
ENV PATH="/opt/venv/bin:$PATH"

# Default command
CMD ["python", "quantumguard.py"]
