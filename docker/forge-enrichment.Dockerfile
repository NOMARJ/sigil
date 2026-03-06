# Dockerfile for Sigil Forge Enrichment Worker
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY . /app/

# Create non-root user
RUN useradd --create-home --shell /bin/bash sigil
RUN chown -R sigil:sigil /app
USER sigil

# Set environment variables
ENV PYTHONPATH=/app
ENV SIGIL_BOT_FORGE_ENRICHMENT_ENABLED=true
ENV SIGIL_BOT_FORGE_ENRICHMENT_BATCH_SIZE=10
ENV SIGIL_BOT_FORGE_ENRICHMENT_DELAY=1.0
ENV SIGIL_BOT_FORGE_ENRICHMENT_MAX_RECORDS=1000
ENV SIGIL_BOT_FORGE_ENRICHMENT_POLL_INTERVAL=300

# Health check
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD python -c "import asyncio; from api.database import db; asyncio.run(db.connect())" || exit 1

# Run the enrichment worker
CMD ["python", "scripts/start_forge_enrichment.py"]