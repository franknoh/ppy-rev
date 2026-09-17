# Reproducible reference environment: Python + uv, Ghidra headless, JDK, and
# the compilers used to build test fixtures.
FROM ubuntu:24.04

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD_DATE=20260817
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        ca-certificates \
        clang \
        curl \
        gcc \
        libc6-dev \
        openjdk-21-jdk-headless \
        python3.12 \
        unzip \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/ghidra.zip \
        "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip" \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm /tmp/ghidra.zip

COPY --from=ghcr.io/astral-sh/uv:0.11.15 /uv /uvx /usr/local/bin/

ARG DEV_UID=1000
RUN userdel --remove ubuntu 2>/dev/null; useradd --create-home --uid "${DEV_UID}" dev \
    && mkdir -p /work /opt/venv \
    && chown dev:dev /work /opt/venv

ENV PPY_REV_GHIDRA_HOME=/opt/ghidra \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy

USER dev
WORKDIR /work

COPY --chown=dev:dev pyproject.toml uv.lock .python-version README.md LICENSE ./
RUN uv sync --frozen --no-install-project

COPY --chown=dev:dev . .
RUN uv sync --frozen

CMD ["scripts/check.sh"]
