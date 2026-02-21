FROM python:3.11-slim-bookworm

LABEL maintainer="NOMARK <team@nomark.dev>"
LABEL description="Sigil API — FastAPI backend for security auditing"

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 sigil && \
    useradd --uid 1001 --gid sigil --shell /bin/bash --create-home sigil

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt ./api/requirements.txt
RUN pip install --no-cache-dir -r ./api/requirements.txt

# Copy application source
COPY . ./api/

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Environment
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV SIGIL_HOST=0.0.0.0
ENV SIGIL_PORT=8000

# Expose API port
EXPOSE 8000

# Change ownership to sigil user
RUN chown -R sigil:sigil /app

# Switch to non-root user
USER sigil

# Set Python path to include /app
ENV PYTHONPATH=/app

# Start API server
CMD ["python", "-m", "uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
