FROM rust:1.96.1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        chromium \
        curl \
        python3 \
        python3-venv \
        unzip \
        pkg-config \
        libasound2 \
        libatk-bridge2.0-0 \
        libatk1.0-0 \
        libcairo2 \
        libcups2 \
        libdbus-1-3 \
        libdrm2 \
        libgbm1 \
        libglib2.0-0 \
        libgtk-3-0 \
        libnspr4 \
        libnss3 \
        libpango-1.0-0 \
        libx11-6 \
        libx11-xcb1 \
        libxcb1 \
        libxcomposite1 \
        libxdamage1 \
        libxext6 \
        libxfixes3 \
        libxkbcommon0 \
        libxrandr2 \
        fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/requirements-agent-bench.txt /tmp/requirements-agent-bench.txt
RUN python3 -m venv /opt/tempo-agent-bench \
    && /opt/tempo-agent-bench/bin/python -m pip install -r /tmp/requirements-agent-bench.txt

ENV PATH="/opt/tempo-agent-bench/bin:${PATH}"

WORKDIR /work
