# QuantumGuard Multi-stage Dockerfile
# ------------------------------
# Stage 1: Build environment (Python + Angular dashboard)
FROM node:20-alpine AS frontend-builder

# Install build dependencies
RUN apk add --no-cache bash git python3 make g++ curl

# Set working directory
WORKDIR /app

# Copy repo files into build context
COPY package*.json .
COPY dashboard/ ./dashboard/

# Install frontend dependencies
RUN cd dashboard && npm install

# Build Angular dashboard
RUN cd dashboard && npm run build --configuration production

# ------------------------------
# Stage 2: Python environment for backend
FROM python:3.11-alpine AS backend

# Install system dependencies
RUN apk add --no-cache bash git python3 make g++ build-base curl

# Set working directory
WORKDIR /app

# Copy Python files and backend folders
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

# Copy built Angular dashboard from frontend stage
COPY --from=frontend-builder /app/dashboard/dist/dashboard ./dashboard/dist/dashboard

# Expose port for QuantumGuard backend
EXPOSE 8000

# Default command to run QuantumGuard
CMD ["python", "quantumguard.py"]
