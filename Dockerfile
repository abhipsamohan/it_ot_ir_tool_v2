# ── Stage 1: build ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS base

WORKDIR /app

# Install dependencies first (layer-cached separately from source code)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Ensure runtime data directories exist inside the image
RUN mkdir -p data/alerts data/ot_context data/config

# ── Runtime configuration ────────────────────────────────────────────────────
ENV FLASK_ENV=production \
    PYTHONUNBUFFERED=1

EXPOSE 5000

# Run from repo root so relative paths (data/, engine/) resolve correctly
CMD ["python", "dashboard/app.py"]
