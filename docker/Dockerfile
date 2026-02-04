# ------------------------------
# Stage 1: Build backend (Python)
# ------------------------------
FROM python:3.11-alpine AS backend

# Install required build tools
RUN apk add --no-cache bash git make g++ 

# Set working directory
WORKDIR /app

# Copy Python dependencies
COPY ../requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source code
COPY ../app/ ./app/
COPY ../scanner/ ./scanner/
COPY ../simulator/ ./simulator/
COPY ../scripts/ ./scripts/
COPY ../hardening/ ./hardening/
COPY ../terraform/ ./terraform/
COPY ../k8s/ ./k8s/
COPY ../quantumguard.py ./
COPY ../self_learning.py ./
COPY ../utils.py ./

# Optional: expose port if needed (example: Flask API)
# EXPOSE 5000

# ------------------------------
# Stage 2: Build frontend dashboard (if applicable)
# ------------------------------
FROM node:20-alpine AS frontend-builder

# Install tools
RUN apk add --no-cache bash git python3 make g++

WORKDIR /dashboard

# Copy dashboard folder
COPY ../dashboard/ ./

# Install frontend dependencies
RUN npm install

# Build Angular dashboard
RUN npx ng build --configuration production

# ------------------------------
# Stage 3: Production image
# ------------------------------
FROM python:3.11-alpine AS production

# Set working directory
WORKDIR /app

# Copy backend from builder
COPY --from=backend /app /app

# Copy dashboard build output if exists
COPY --from=frontend-builder /dashboard/dist /app/dashboard/dist

# Optional: expose ports
# EXPOSE 5000

# Set default command
CMD ["python", "quantumguard.py"]
