# QuantumGuard Dockerfile - Multi-stage build

# =========================
# Builder Stage
# =========================
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache bash git python3 make g++

# Set working directory
WORKDIR /app

# Copy package files first for caching
COPY package*.json ./

# Install root-level dependencies (if any)
RUN npm install

# Copy all source code from repo root
COPY dashboard ./dashboard
COPY server ./server
COPY app ./app

# Install dependencies inside all subfolders
WORKDIR /app/dashboard
RUN npm install
RUN npm run build

# =========================
# Production Stage
# =========================
FROM node:20-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache dumb-init su-exec

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S quantum -u 1001 -G nodejs

# Set working directory
WORKDIR /app

# Copy built dashboard from builder
COPY --from=builder /app/dashboard/dist ./dashboard/dist

# Copy server and app folders (source code)
COPY --from=builder /app/server ./server
COPY --from=builder /app/app ./app

# Copy package files for production
COPY --from=builder /app/package*.json ./

# Switch to non-root user
USER quantum

# Expose dashboard port
EXPOSE 4200

# Default command to start server
CMD ["node", "server/index.js"]
