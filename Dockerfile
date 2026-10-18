# Multi-stage Dockerfile for APK Inspector
# Stage 1: Build NestJS application
FROM node:22-alpine AS builder

WORKDIR /app
COPY package*.json tsconfig*.json nest-cli.json ./
COPY prisma/ ./prisma/
RUN npm ci

COPY src/ ./src/
RUN npm run build

# Stage 2: Production runtime with Node.js and Python 3 + Androguard
FROM python:3.12-slim-bookworm

# Install Node.js 22 in Debian
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gnupg \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python static analysis dependencies
COPY engine/requirements.txt ./engine/
RUN pip install --no-cache-dir -r engine/requirements.txt

# Install production Node dependencies and generate Prisma client
COPY package*.json ./
COPY prisma/ ./prisma/
RUN npm ci --omit=dev

# Copy built application, engine scripts, web UI, and sample APKs
COPY --from=builder /app/dist ./dist
COPY engine/ ./engine/
COPY public/ ./public/
COPY sample_apks/ ./sample_apks/

# Ensure sample-test.apk is generated in public/ and sample_apks/
RUN python engine/create_test_apk.py public/sample-test.apk \
    && python engine/create_test_apk.py sample_apks/sample-test.apk

# Create working directories
RUN mkdir -p uploads reports sample_apks \
    && chmod -R 777 uploads reports sample_apks public

ENV PORT=3000
ENV NODE_ENV=production

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

CMD ["node", "dist/main.js"]
