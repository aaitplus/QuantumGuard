# QuantumGuard Application Dockerfile
# Multi-stage build for QuantumGuard app

# ----------------------
# Builder Stage
# ----------------------
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache bash git python3 make g++

# Set working directory
WORKDIR /app

# Copy package.json files first for caching dependencies
COPY ../package*.json ./

# Copy all source code from repo root
COPY ../frontend ./frontend
COPY ../server ./server
COPY ../app ./app

# Install dependencies
RUN npm install

# Build the application (frontend + server)
RUN npm run build

# ----------------------
# Production Stage
# ----------------------
FROM node:20-alpine AS production

# Install security updates and create non-root user
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init su-exec && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy built app and dependencies from builder stage
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/frontend ./frontend
COPY --from=builder /app/server ./server
COPY --from=builder /app/app ./app
COPY --from=builder /app/package*.json ./

# Switch to non-root user
USER nextjs

# Expose app port
EXPOSE 3000

# Start the application
CMD ["npm", "start"]
