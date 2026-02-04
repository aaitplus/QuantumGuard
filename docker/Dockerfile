# ------------------------------
# QuantumGuard Dockerfile
# ------------------------------

# Stage 1: Build Python dependencies
FROM python:3.11-alpine AS backend

# Install system dependencies
RUN apk add --no-cache bash git build-base libffi-dev

# Set working directory
WORKDIR /app

# Copy Python requirement files
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Python source code
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

# Copy the dashboard Flask app
COPY dashboard/ ./dashboard/

# Expose Flask default port
EXPOSE 5000

# Set environment variables
ENV FLASK_APP=dashboard/app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_ENV=production

# Start the Flask app
CMD ["flask", "run"]
