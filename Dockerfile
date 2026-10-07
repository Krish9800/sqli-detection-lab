# Multi-stage rootless production Dockerfile for SQLi Detection Lab
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir --upgrade pip build wheel \
    && pip wheel --no-cache-dir --no-deps --wheel-dir /build/wheels .

# Runtime Stage
FROM python:3.12-slim AS runner

WORKDIR /app

# Create non-privileged user and group
RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/sh -M appuser

COPY --from=builder /build/wheels /wheels
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

ENTRYPOINT ["uvicorn", "sqlilab.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
