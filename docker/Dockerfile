# QuantumGuard Dockerfile - builds only the frontend (dashboard)
# Use Node 20 for Angular 19+

# =========================
# Builder Stage
# =========================
FROM node:20-alpine AS builder

# Install build tools
RUN apk add --no-cache bash git python3 make g++

# Set working directory
WORKDIR /app

# Copy package files first (for caching)
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy only the dashboard folder (actual folder in repo)
COPY dashboard ./dashboard

# Build the Angular frontend
WORKDIR /app/dashboard
RUN npm install
RUN npm run build --configuration production

# =========================
# Production Stage
# =========================
FROM nginx:alpine

# Remove default Nginx static files
RUN rm -rf /usr/share/nginx/html/*

# Copy built Angular files from builder
COPY --from=builder /app/dashboard/dist/dashboard /usr/share/nginx/html

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]
