# ------------------------------
# Stage 1: Backend (Python)
# ------------------------------
FROM python:3.11-alpine AS backend

# Install required packages
RUN apk add --no-cache bash git python3 make g++ nodejs npm

WORKDIR /app

# Copy Python dependencies
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all backend files
COPY app/ ./app/
COPY simulator/ ./simulator/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/
COPY quantumguard.py self_learning.py utils.py ./

# ------------------------------
# Stage 2: Frontend Builder (Angular Dashboard)
# ------------------------------
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Copy dashboard package files
COPY dashboard/package*.json ./dashboard/
WORKDIR /app/dashboard

# Install frontend dependencies
RUN npm install

# Copy frontend source
COPY dashboard/ ./dashboard/

# Build frontend
RUN npm run build -- --configuration production

# ------------------------------
# Stage 3: Production Image
# ------------------------------
FROM python:3.11-alpine AS production

# Install minimal dependencies
RUN apk add --no-cache bash python3 nodejs npm

WORKDIR /app

# Copy backend from builder
COPY --from=backend /app /app

# Copy built dashboard from frontend builder
COPY --from=frontend-builder /app/dashboard/dist /app/dashboard/dist

# Set environment variables if needed
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python3", "quantumguard.py"]
