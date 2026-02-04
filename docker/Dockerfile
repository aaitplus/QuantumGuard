# QuantumGuard Application Dockerfile
# Multi-stage build for Angular frontend + Python backend

# -------------------------
# Builder stage
# -------------------------
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++ bash git

# Set working directory
WORKDIR /app

# Copy frontend source
COPY frontend/ ./frontend/
COPY package*.json ./

# Install frontend dependencies
RUN cd frontend && npm install

# Build frontend
RUN cd frontend && npm run build:frontend

# -------------------------
# Production stage
# -------------------------
FROM python:3.11-alpine AS production

# Install system dependencies
RUN apk update && apk add --no-cache bash dumb-init su-exec

# Set working directory
WORKDIR /app

# Copy backend code
COPY . .

# Copy built frontend from builder
COPY --from=builder /app/frontend/dist ./frontend/dist

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Expose application port
EXPOSE 8000

# Switch to non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Start the application
CMD ["python", "quantumguard.py"]
