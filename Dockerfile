# ── Base image ─────────────────────────────────────────────────────────────────
# python:3.12-slim — minimal Debian base, no build tools or documentation.
# Pinning to 3.12-slim (not :latest) ensures reproducible builds across CI runs.
FROM python:3.12-slim

# ── Non-root user ──────────────────────────────────────────────────────────────
# Running as root inside a container broadens the blast radius of a compromise.
# appuser has no sudo rights and no write access outside /app.
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# ── Dependency layer (cached separately from code) ─────────────────────────────
# COPY requirements.txt first so Docker can cache the pip install layer.
# A code-only change reuses this cached layer — saving ~3 minutes per build.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application code ───────────────────────────────────────────────────────────
# Copy only the files the runtime needs — no tests, docs, or .env files.
COPY masking.py main.py ./

# ── Switch to non-root user ────────────────────────────────────────────────────
# Must come after pip install (which writes to system directories requiring root).
USER appuser

# ── Runtime config ─────────────────────────────────────────────────────────────
# Cloud Run injects PORT; uvicorn reads it from the environment via main.py.
EXPOSE 8080

# Exec form (not shell form) so SIGTERM reaches the Python process directly,
# not a shell wrapper — critical for the graceful shutdown handler.
CMD ["python", "main.py"]
