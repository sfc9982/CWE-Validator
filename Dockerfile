FROM debian:bookworm-slim

ENV VIRTUAL_ENV=/opt/cwe-venv \
    PATH=/opt/cwe-venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /opt/cwe-witness

COPY scripts/setup.sh scripts/setup-packages.sh scripts/
RUN bash scripts/setup.sh --yes --system-only --mirror official \
    && rm -rf /var/lib/apt/lists/* .setup-state

COPY pyproject.toml uv.lock README.md README.zh-CN.md SETUP.md LICENSE ./
COPY src/ src/
COPY manifests/calibration/ manifests/calibration/
COPY tests/calibration/ tests/calibration/
RUN bash scripts/setup.sh --yes --skip-system --no-dev --skip-verify \
        --venv-dir /opt/cwe-venv --mirror official \
    && rm -rf .setup-state \
    && mkdir -p .cwe-witness \
    && chown 10001:10001 .cwe-witness

USER 10001:10001
ENTRYPOINT ["cweverify"]
CMD ["doctor"]
