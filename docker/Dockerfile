# QuantumGuard Dockerfile
# Build and run the cyberpunk dashboard + QuantumGuard app

# ------------------------------
# Stage 1: Build Python Dependencies
# ------------------------------
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache bash git make g++

# Set working directory
WORKDIR /app

# Copy Python requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all app source code
COPY app/ ./app
COPY simulator/ ./simulator
COPY scanner/ ./scanner
COPY dashboard/ ./dashboard
COPY scripts/ ./scripts
COPY hardening/ ./hardening
COPY terraform/ ./terraform
COPY k8s/ ./k8s
COPY utils.py .
COPY self_learning.py .
COPY quantumguard.py .

# ------------------------------
# Stage 2: Production image
# ------------------------------
FROM python:3.11-alpine

# Install runtime dependencies
RUN apk add --no-cache bash git

WORKDIR /app

# Copy built app from builder
COPY --from=builder /app /app

# Expose port for the dashboard
EXPOSE 5000

# Default command
CMD ["python", "quantumguard.py"]
