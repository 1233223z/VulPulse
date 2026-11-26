# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

# python:3.12-slim, OCI image index digest as of 2026-11-26.
FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5

WORKDIR /build

COPY pyproject.toml README.md ./
COPY vulpulse ./vulpulse

RUN pip wheel --no-deps --wheel-dir /wheels .


FROM python:3.12-slim@sha256:191083cdf6c7bda8c76158983163ead5d5cf7b77cf3033e805bb0f5296f51b4b AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PIP_RETRIES=5

RUN groupadd --system vulpulse \
    && useradd --system --create-home --gid vulpulse vulpulse

WORKDIR /app

COPY requirements.txt /tmp/requirements.txt
COPY --from=builder /wheels /wheels
RUN pip install --require-hashes -r /tmp/requirements.txt \
    && pip install --no-index --no-deps /wheels/vulpulse-*.whl \
    && rm -rf /wheels /tmp/requirements.txt \
    && mkdir -p /app/data \
    && chown -R vulpulse:vulpulse /app

USER vulpulse

EXPOSE 8000

LABEL org.opencontainers.image.title="VulPulse" \
      org.opencontainers.image.description="Open-source vulnerability intelligence platform" \
      org.opencontainers.image.source="https://github.com/1233223z/VulPulse" \
      org.opencontainers.image.licenses="MIT"

CMD ["vulpulse", "serve", "--host", "0.0.0.0", "--port", "8000"]
