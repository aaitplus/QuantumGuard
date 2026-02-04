# Dockerfile — builds the OWASP Juice Shop app for QuantumGuard

# -----------------------------
# Builder Stage
# -----------------------------
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git bash python3 make g++

# Set working directory
WORKDIR /app

# Clone the vulnerable Juice Shop app using your repo scripts
COPY app/ ./app/
RUN chmod +x app/clone.sh \
 && app/clone.sh

# Let the Juice Shop source live in /app/juice-shop
WORKDIR /app/juice-shop

# Install Node dependencies
RUN npm install

# Build the app (if your install script includes build steps)
# If there is no build script, this will simply prepare node_modules
RUN npm run build || true

# -----------------------------
# Production Stage
# -----------------------------
FROM node:20-alpine AS production

RUN apk update && apk add --no-cache dumb-init su-exec

WORKDIR /app

# Copy app sources & built node_modules
COPY --from=builder /app/juice-shop ./

# Expose app port
EXPOSE 3000

# Switch to non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

# Default command
CMD ["npm", "start"]
