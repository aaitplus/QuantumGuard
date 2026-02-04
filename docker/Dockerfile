# ------------------------------
# QuantumGuard Dockerfile
# ------------------------------

# Use Python slim image
FROM python:3.11-slim AS build

# Set work directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy Python requirements
COPY ../requirements.txt ./

# Install Python packages
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------------
# Runtime image
# ------------------------------
FROM python:3.11-slim

WORKDIR /app

# Copy Python virtualenv from build stage
COPY --from=build /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=build /usr/local/bin /usr/local/bin

# Copy source code
COPY ../quantumguard.py ./
COPY ../self_learning.py ./
COPY ../utils.py ./

COPY ../app ./app
COPY ../hardening ./hardening
COPY ../scanner ./scanner
COPY ../simulator ./simulator
COPY ../scripts ./scripts
COPY ../terraform ./terraform
COPY ../k8s ./k8s

# Copy dashboard folder
COPY ./dashboard ./dashboard

# Expose Flask port
EXPOSE 5000

# Flask environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Start Flask app
CMD ["flask", "run"]
