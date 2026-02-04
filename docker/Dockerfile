# ------------------------------
# QuantumGuard Dockerfile
# ------------------------------

FROM python:3.11-alpine AS backend

# Install system dependencies
RUN apk add --no-cache bash git build-base libffi-dev

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy main Python files (inside docker folder)
COPY docker/quantumguard.py ./
COPY docker/self_learning.py ./
COPY utils.py ./

# Copy application folders
COPY app ./app
COPY scanner ./scanner
COPY simulator ./simulator
COPY scripts ./scripts
COPY hardening ./hardening
COPY terraform ./terraform
COPY k8s ./k8s

# Copy dashboard folder
COPY docker/dashboard ./dashboard

# Expose Flask port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Start the Flask app
CMD ["flask", "run"]
