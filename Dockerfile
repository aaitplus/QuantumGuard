# ------------------------------
# QuantumGuard Production Dockerfile
# ------------------------------

# ------------------------------
# Stage 1: Build Python dependencies
# ------------------------------
FROM python:3.11-slim AS build

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements file
COPY requirements.txt .

# Create virtual environment and install Python dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------------
# Stage 2: Runtime image
# ------------------------------
FROM python:3.11-slim AS runtime

# Set working directory
WORKDIR /app

# Copy installed packages from build stage
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY app/ ./app/
COPY simulator/ ./simulator/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/
COPY utils.py ./
COPY self_learning.py ./
COPY quantumguard.py ./

# Copy the dashboard folder (make sure this exists in repo root!)
COPY dashboard/ ./dashboard/

# Expose Flask port
EXPOSE 5000

# Create a non-root user for security
RUN useradd -m quantumguard
USER quantumguard

# Install Gunicorn for production Flask server
RUN pip install gunicorn

# Set Flask app environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_ENV=production

# Start Flask app with Gunicorn
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5000", "dashboard.app:app"]
