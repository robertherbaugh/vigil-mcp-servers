# Build from the repository root, so the workspace's common package is in the context:
#   docker build -f servers/wazuh5-bridge/Dockerfile -t vigil-wazuh5-bridge .
# Copied from servers/_template: PACKAGE, CMD and the port differ.

ARG PYTHON_IMAGE=python:3.13.18-slim-trixie

FROM ghcr.io/astral-sh/uv:0.13.10 AS uv

FROM ${PYTHON_IMAGE} AS build
ARG PACKAGE=vigil-wazuh5-bridge
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
COPY . .
# Only the one server and what it needs; no dev tools; exactly the versions in uv.lock.
RUN uv sync --frozen --no-dev --no-editable --package "${PACKAGE}"

FROM ${PYTHON_IMAGE}
# A fixed, unprivileged uid (runAsNonRoot can check it); no shell login, no home contents.
RUN groupadd --system --gid 10001 mcp && \
    useradd --system --uid 10001 --gid mcp --no-create-home --shell /usr/sbin/nologin mcp
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 METRICS_PORT=9108
USER 10001:10001
EXPOSE 9108
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"METRICS_PORT\"]}/healthz', timeout=2)"]
CMD ["vigil-wazuh5-bridge", "run"]
