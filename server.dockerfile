# Stage 1: Build dependencies
FROM python:3.11-slim AS builder
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production runtime image
FROM python:3.11-slim AS runner

# Create a non-root system user for least privilege security
RUN groupadd -g 10001 mcpuser && \
    useradd -u 10000 -g mcpuser -m mcpuser

WORKDIR /app
COPY --from=builder /install /usr/local
COPY server.py requirements.txt .

# Explicitly strip/forbid mock fallbacks in production environments
ENV FORCE_MOCK_FALLBACK="false"
ENV MOCK_SECRETS_FILE=""

# Switch to non-root user
USER mcpuser:mcpuser

# Run server via stdio transport
ENTRYPOINT ["python", "server.py"]
