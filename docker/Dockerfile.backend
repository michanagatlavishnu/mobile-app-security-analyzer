# ==============================================================
# Mobile App Security Analyzer - Backend Containerfile
# Hardened multi-runtime container: Node.js 20 LTS + Python 3.12
# Runs as non-privileged security operator (UID 10001)
# ==============================================================

FROM node:20-bookworm-slim

# Install Python 3 runtime and build essentials for cryptographic static analysis
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    dumb-init \
    && rm -rf /var/lib/apt/lists/*

# Setup virtual environment for Python analyzer dependencies
ENV VIRTUAL_ENV=/opt/venv
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install Python dependencies
RUN pip install --no-cache-dir cryptography

# Create non-root application group and user
RUN groupadd -g 10001 secops && \
    useradd -u 10001 -g secops -m -s /bin/bash appuser

WORKDIR /app

# Install Node.js production dependencies
COPY backend/package*.json ./backend/
WORKDIR /app/backend
RUN npm ci --only=production

# Copy application backend and static analysis engine
WORKDIR /app
COPY backend ./backend
COPY analyzer ./analyzer

# Create storage and report directories with proper permissions
RUN mkdir -p /app/backend/uploads /app/backend/reports && \
    chown -R appuser:secops /app

USER appuser
WORKDIR /app/backend

ENV NODE_ENV=production
ENV PORT=5000
ENV PYTHON_PATH=/opt/venv/bin/python3

EXPOSE 5000

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.js"]
