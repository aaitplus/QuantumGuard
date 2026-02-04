# ==========================================
# QuantumGuard Dockerfile
# Repo-root build context REQUIRED
# ==========================================

########################
# Builder Stage
########################
FROM node:20-alpine AS builder

RUN apk add --no-cache bash git python3 make g++

WORKDIR /app

# Copy root package files
COPY package*.json ./

# Copy frontend & server
COPY dashboard ./dashboard
COPY server ./server

# Install dependencies
RUN npm install

# Build frontend if script exists
RUN npm run build --if-present

########################
# Production Stage
########################
FROM node:20-alpine

RUN apk add --no-cache dumb-init \
 && addgroup -S nodejs \
 && adduser -S nodeuser -G nodejs

WORKDIR /app

# Copy built output
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dashboard ./dashboard
COPY --from=builder /app/server ./server
COPY --from=builder /app/package*.json ./

USER nodeuser

EXPOSE 3000

CMD ["npm", "start"]
