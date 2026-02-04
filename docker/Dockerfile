# QuantumGuard Multi-Stage Dockerfile
# Base images: Node.js 20 for frontend/backend, Python 3.11 for production utils if needed

# -------------------------
# Builder stage (Node.js)
# -------------------------
FROM node:20-alpine AS builder

# Install build tools
RUN apk add --no-cache bash git python3 make g++

# Set working directory
WORKDIR /app

# Copy project files into build context
COPY package*.json ./
COPY frontend/ ./frontend/
COPY server/ ./server/
COPY app/ ./app/

# Install all dependencies
RUN npm install

# Build frontend
RUN cd frontend && npm run build && cd ..

# -------------------------
# Production stage
# -------------------------
FROM node:20-alpine AS production

# Install runtime tools
RUN apk add --no-cache dumb-init su-exec bash python3

# Create non-root user
RUN addgroup -g 1001 -S nodejs \
 && adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy built files and node_modules from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/frontend/dist ./frontend/dist
COPY --from=builder /app/server ./server
COPY --from=builder /app/app ./app
COPY --from=builder /app/package*.json ./

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/status', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start server
CMD ["node", "server/index.js"]
