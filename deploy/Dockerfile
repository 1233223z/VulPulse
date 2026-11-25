# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5

WORKDIR /build

COPY pyproject.toml README.md ./
COPY vulpulse ./vulpulse

RUN pip wheel --wheel-dir /wheels .


FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5

RUN groupadd --system vulpulse \
    && useradd --system --create-home --gid vulpulse vulpulse

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels vulpulse \
    && rm -rf /wheels \
    && mkdir -p /app/data \
    && chown -R vulpulse:vulpulse /app

USER vulpulse

EXPOSE 8000

LABEL org.opencontainers.image.title="VulPulse" \
      org.opencontainers.image.description="Open-source vulnerability intelligence platform" \
      org.opencontainers.image.source="https://github.com/1233223z/VulPulse" \
      org.opencontainers.image.licenses="MIT"

CMD ["vulpulse", "serve", "--host", "0.0.0.0", "--port", "8000"]
