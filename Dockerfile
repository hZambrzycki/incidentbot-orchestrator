# Dockerfile for Incident Bot
# Multi-stage build for smaller final image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 -s /bin/bash incidentbot

# Copy Python packages from builder
COPY --from=builder /root/.local /home/incidentbot/.local

# Copy application code
COPY --chown=incidentbot:incidentbot . .

# Create directories
RUN mkdir -p /var/log/incident-bot && \
    chown -R incidentbot:incidentbot /var/log/incident-bot

# Create directories
RUN mkdir -p /var/log/incident-bot /data && \
    chown -R incidentbot:incidentbot /var/log/incident-bot /data
# Switch to non-root user
USER incidentbot

# Add local packages to PATH
ENV PATH=/home/incidentbot/.local/bin:$PATH
ENV PYTHONPATH=/app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose port
EXPOSE 8000

# Run the application
CMD ["python", "-m", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
