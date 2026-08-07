# ─────────────────────────────────────────────────────────────────────────────
# Eyxa EDR - Multi-stage Dockerfile
#
# Stage 1 (builder): node:20 image builds the React dashboard via Vite.
#   vite.config.ts already sets outDir: '../backend/static', so the compiled
#   SPA lands at /build/backend/static inside the build container.
#
# Stage 2 (runtime): python:3.11-slim runs the FastAPI backend which serves
#   both the API and the built React SPA from backend/static/.
#
# Port 8443 - HTTPS (dashboard + REST API + WebSocket)
# TLS      - Self-signed cert from backend/certs/ (SkipTlsVerify=1 on agent)
# DB       - Fresh SQLite created by init_db() on first boot.
#            Persisted via named Docker volume mounted at /app/backend/db/
# ─────────────────────────────────────────────────────────────────────────────

# ── Stage 1: Build React dashboard ───────────────────────────────────────────
FROM node:20-slim AS builder

WORKDIR /build

# Copy package files first for layer caching
COPY dashboard/package.json dashboard/package-lock.json ./dashboard/

# Install dependencies
RUN cd dashboard && npm ci

# Copy the full dashboard source + backend folder (Vite outputs into ../backend/static)
COPY dashboard/ ./dashboard/
COPY backend/   ./backend/

# Build - output goes to /build/backend/static per vite.config.ts outDir setting
RUN cd dashboard && npm run build


# ── Stage 2: Python runtime ───────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

# Copy backend source
COPY backend/ ./backend/

# Overwrite static/ with the freshly built SPA from Stage 1
COPY --from=builder /build/backend/static ./backend/static/

# Install Python dependencies
RUN pip install --no-cache-dir -r backend/requirements.txt

# Ensure the db directory exists so the volume mount works correctly
# (init_db() creates the actual .db file on first boot)
RUN mkdir -p backend/db

WORKDIR /app/backend

EXPOSE 8443

# Start uvicorn on plain HTTP - Codespaces/reverse-proxy handles TLS externally.
# When running locally with the agent, TLS is terminated here; in Codespaces the
# proxy layer provides HTTPS so we must NOT double-wrap with SSL.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8443", "--log-level", "info"]
