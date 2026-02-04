# QuantumGuard Dockerfile (fully corrected)
# Build Angular dashboard and Python backend

# ------------------------------
# Stage 1: Build Angular dashboard
FROM node:20-alpine AS frontend-builder

RUN apk add --no-cache bash git python3 make g++

WORKDIR /app

# Copy only dashboard folder
COPY dashboard/ ./dashboard/

# Install dependencies and build
RUN cd dashboard && npm install && npm run build --configuration production

# ------------------------------
# Stage 2: Python backend
FROM python:3.11-alpine AS backend

RUN apk add --no-cache bash git python3 make g++ build-base

WORKDIR /app

# Copy all Python backend files from repo root
COPY requirements.txt .
COPY app/ ./app/
COPY simulator/ ./simulator/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/
COPY utils.py .
COPY self_learning.py .
COPY quantumguard.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy Angular dashboard build from frontend stage
COPY --from=frontend-builder /app/dashboard/dist/dashboard ./dashboard/dist/dashboard

# Expose backend port
EXPOSE 8000

# Default command
CMD ["python", "quantumguard.py"]
