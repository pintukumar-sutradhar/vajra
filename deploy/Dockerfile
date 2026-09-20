# VAJRA — single container image for the API and the worker.
#
# Build:   docker build -f deploy/Dockerfile -t vajra .
# Run:     VAJRA_MODE=api    => API + webapp (default)
#          VAJRA_MODE=worker => scan worker(s)
#   docker compose -f deploy/compose.yml up -d --build
#
# The API binds 0.0.0.0 inside the container so the published port works;
# put the published port behind a TLS-terminating reverse proxy in an
# on-premise deployment (see docs/DEPLOYMENT.md).

# ------------------------------------------------------------------- webapp
FROM node:20-alpine AS web
WORKDIR /src
COPY webapp/package.json webapp/package-lock.json ./
RUN npm ci
COPY webapp/ ./
RUN npm run build

# ------------------------------------------------------------ runtime image
FROM python:3.12-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app

COPY server/requirements.txt /app/server/requirements.txt
RUN pip install --no-cache-dir -r /app/server/requirements.txt \
 && python -m playwright install --with-deps chromium

COPY . .
COPY --from=web /src/dist /app/webapp/dist
COPY deploy/docker-entry.sh /usr/local/bin/vajra-entry
RUN chmod +x /usr/local/bin/vajra-entry && mkdir -p /var/lib/vajra

EXPOSE 8000
VOLUME ["/var/lib/vajra"]
ENTRYPOINT ["vajra-entry"]