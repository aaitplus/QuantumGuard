# Use Python
FROM python:3.11-slim

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential git libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies
COPY ../requirements.txt ./
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy source files from repo root via relative paths
COPY ../quantumguard.py ./
COPY ../self_learning.py ./
COPY ../utils.py ./

# Copy project folders
COPY ../app ./app
COPY ../scanner ./scanner
COPY ../simulator ./simulator
COPY ../scripts ./scripts
COPY ../hardening ./hardening
COPY ../terraform ./terraform
COPY ../k8s ./k8s

# Copy dashboard from docker/dashboard
COPY ./dashboard ./dashboard

# Expose Flask default port
EXPOSE 5000
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

CMD ["flask", "run"]
