# ------------------------------
# Builder stage
# ------------------------------
FROM python:3.11-alpine AS builder

RUN apk add --no-cache bash git make g++ nodejs npm

WORKDIR /app

# Copy Python requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all necessary repo folders/files
COPY app/ ./app/
COPY dashboard/ ./dashboard/
COPY simulator/ ./simulator/
COPY scanner/ ./scanner/
COPY scripts/ ./scripts/
COPY hardening/ ./hardening/
COPY terraform/ ./terraform/
COPY k8s/ ./k8s/
COPY utils.py .
COPY self_learning.py .
COPY quantumguard.py .

# Optional: Build Angular dashboard if exists
WORKDIR /app/dashboard
RUN npm install
RUN npm run build --prod

# ------------------------------
# Production stage
# ------------------------------
FROM python:3.11-alpine

RUN apk add --no-cache bash git nodejs npm

WORKDIR /app
COPY --from=builder /app /app

EXPOSE 5000
CMD ["python", "quantumguard.py"]
