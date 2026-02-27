# ============================================================================
# SIGIL — Multi-stage Dockerfile
# by NOMARK
#
# Stage 1: Build the Rust CLI binary
# Stage 2: Build the Next.js dashboard
# Stage 3: Runtime image with API, CLI, and dashboard
# ============================================================================

# ── Stage 1: Build Rust CLI ──────────────────────────────────────────────────
FROM rust:1.76-slim AS rust-builder
WORKDIR /build
COPY cli/ ./
RUN cargo build --release

# ── Stage 2: Build Next.js Dashboard ────────────────────────────────────────
FROM node:20-slim AS dashboard-builder

WORKDIR /build

# Copy package manifests first for layer caching
COPY dashboard/package.json dashboard/package-lock.json* ./

RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts

# Copy source and build
COPY dashboard/ ./

# Set build-time environment variables
ENV NEXT_TELEMETRY_DISABLED=1
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}

RUN npm run build

# ── Stage 3: Runtime Image ──────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS runtime

LABEL maintainer="NOMARK <team@sigilsec.ai>"
LABEL description="Sigil — Automated Security Auditing for AI Agent Code"
LABEL org.opencontainers.image.source="https://github.com/NOMARJ/sigil"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    file \
    tini \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 sigil && \
    useradd --uid 1001 --gid sigil --shell /bin/bash --create-home sigil

WORKDIR /app

# ── Python API dependencies ─────────────────────────────────────────────────
COPY api/requirements.txt /app/api/requirements.txt
RUN pip install --no-cache-dir -r /app/api/requirements.txt

# ── Python Bot dependencies ────────────────────────────────────────────────
COPY bot/requirements.txt /app/bot/requirements.txt
RUN pip install --no-cache-dir -r /app/bot/requirements.txt

# ── Copy API source ─────────────────────────────────────────────────────────
COPY api/ /app/api/

# ── Copy Bot source ─────────────────────────────────────────────────────────
COPY bot/ /app/bot/

# ── Copy Rust CLI binary ────────────────────────────────────────────────────
COPY --from=rust-builder /build/target/release/sigil /usr/local/bin/sigil
RUN chmod +x /usr/local/bin/sigil

# ── Copy bash CLI as fallback ────────────────────────────────────────────────
COPY bin/sigil /usr/local/bin/sigil-bash
RUN chmod +x /usr/local/bin/sigil-bash

# ── Copy built dashboard ────────────────────────────────────────────────────
COPY --from=dashboard-builder /build/.next /app/dashboard/.next
COPY --from=dashboard-builder /build/public /app/dashboard/public
COPY --from=dashboard-builder /build/package.json /app/dashboard/package.json
COPY --from=dashboard-builder /build/node_modules /app/dashboard/node_modules
COPY --from=dashboard-builder /build/next.config.js* /app/dashboard/

# ── Create sigil data directories ───────────────────────────────────────────
RUN mkdir -p /home/sigil/.sigil/quarantine \
             /home/sigil/.sigil/approved \
             /home/sigil/.sigil/logs \
             /home/sigil/.sigil/reports && \
    chown -R sigil:sigil /home/sigil/.sigil /app

# ── Runtime env substitution script for dashboard API URL ─────────────────
RUN printf '#!/bin/sh\n\
if [ -n "$NEXT_PUBLIC_API_URL" ]; then\n\
  find /app/dashboard/.next -name "*.js" -exec sed -i "s|http://localhost:8000|$NEXT_PUBLIC_API_URL|g" {} +\n\
fi\n' > /app/substitute-env.sh && chmod +x /app/substitute-env.sh

# ── Multi-service entrypoint ──────────────────────────────────────────────
RUN printf '#!/bin/sh\n\
set -e\n\
/app/substitute-env.sh\n\
cd /app/dashboard && node server.js &\n\
exec uvicorn api.main:app --host 0.0.0.0 --port 8000\n' > /app/start.sh && chmod +x /app/start.sh

# ── Health check ─────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# ── Environment ──────────────────────────────────────────────────────────────
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV SIGIL_HOST=0.0.0.0
ENV SIGIL_PORT=8000

# Expose API and dashboard ports
EXPOSE 8000 3000

# Switch to non-root user
USER sigil

# Use tini for proper signal handling (PID 1 reaping)
ENTRYPOINT ["tini", "--"]

# Default: start both API and dashboard services
CMD ["/app/start.sh"]
