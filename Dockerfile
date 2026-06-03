# syntax=docker/dockerfile:1
# Minimal, production-ready image for the solidity-audit-ai web UI + CLI.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install (web UI) dependencies first for better layer caching.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source.
COPY auditor ./auditor
COPY samples ./samples
COPY pyproject.toml README.md LICENSE ./

# Run as a non-root user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Container healthcheck hits the web UI's /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

# Default: serve the web UI. Override the entrypoint to use the CLI, e.g.:
#   docker run --rm -v "$PWD/contracts:/data" solidity-audit-ai \
#       python -m auditor.cli /data --format json
CMD ["uvicorn", "auditor.webapp:app", "--host", "0.0.0.0", "--port", "8000"]
