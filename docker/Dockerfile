# ------------------------------
# QuantumGuard Production Dockerfile
# ------------------------------

# ------------------------------
# Stage 1: Build Python dependencies
# ------------------------------
FROM python:3.11-slim AS build

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# ------------------------------
# Stage 2: Runtime image
# ------------------------------
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy Python dependencies from build stage
COPY --from=build /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# ------------------------------
# Copy application files safely
# ------------------------------
COPY app/ ./app/
COPY simulator/ ./simulator/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/

# Copy single files only if they exist
RUN if [ -f "utils.py" ]; then cp utils.py ./; fi
RUN if [ -f "self_learning.py" ]; then cp self_learning.py ./; fi
RUN if [ -f "quantumguard.py" ]; then cp quantumguard.py ./; fi

# Copy dashboard folder only if it exists
RUN if [ -d "dashboard" ]; then cp -r dashboard ./dashboard; fi

# Expose Flask port
EXPOSE 5000

# ------------------------------
# Security: non-root user
# ------------------------------
RUN useradd -m quantumguard
USER quantumguard

# Install Gunicorn for production Flask server
RUN pip install gunicorn

# Set Flask environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_ENV=production

# Start Flask app with Gunicorn
CMD ["gunicorn", "--workers", "3", "--bind", "0.0.0.0:5000", "dashboard.app:app"]
