# QuantumGuard Application Dockerfile
# Multi-stage build for OWASP Juice Shop with cyberpunk theme

# Build stage
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git python3 make g++

# Set working directory
WORKDIR /app

# Clone OWASP Juice Shop
RUN git clone https://github.com/juice-shop/juice-shop.git .

# Install dependencies
RUN npm install

# Build the application
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install security updates and create non-root user
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init su-exec && \
    addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=nextjs:nodejs /app/.next ./.next
COPY --from=builder --chown=nextjs:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=nextjs:nodejs /app/package.json ./package.json
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

# Copy custom cyberpunk theme
COPY --chown=nextjs:nodejs app/custom-theme.css ./public/custom-theme.css

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "require('http').get('http://localhost:3000/api/status', (res) => { process.exit(res.statusCode === 200 ? 0 : 1) })"

# Start the application
CMD ["npm", "start"]
