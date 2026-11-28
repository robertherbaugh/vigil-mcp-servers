# Build from the repository root:
#   docker build -f servers/host-enroller/Dockerfile -t vigil-host-enroller .
# Copied from servers/_template, plus what the enroller serves to hosts: the step CLI (x86_64) and
# the responder kit (servers/stepca-ssh-responder/host) of this same commit.

ARG PYTHON_IMAGE=python:3.13.18-slim-trixie
ARG STEP_CLI_IMAGE=smallstep/step-cli:0.31.0@sha256:107e8497646c0e7c06cc5b6fd6fa13b5d2001909df6d7da3706b8541ed42bddf

FROM ghcr.io/astral-sh/uv:0.13.10 AS uv

# The step CLI for amd64 VMs, whatever the image's own architecture.
FROM --platform=linux/amd64 ${STEP_CLI_IMAGE} AS step

FROM ${PYTHON_IMAGE} AS build
ARG PACKAGE=vigil-host-enroller
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
COPY . .
RUN uv sync --frozen --no-dev --no-editable --package "${PACKAGE}"
# The kit's version is the responder package's version.
RUN mkdir -p /out/kit && cp servers/stepca-ssh-responder/host/* /out/kit/ && \
    sed -n 's/^version = "\(.*\)"/\1/p' servers/stepca-ssh-responder/pyproject.toml > /out/kit/VERSION && \
    test -s /out/kit/VERSION && chmod 0755 /out/kit/install.sh /out/kit/vigil-respond /out/kit/vigil-respond-nft

FROM ${PYTHON_IMAGE}
RUN groupadd --system --gid 10001 mcp && \
    useradd --system --uid 10001 --gid mcp --no-create-home --shell /usr/sbin/nologin mcp
COPY --from=build /app/.venv /app/.venv
COPY --from=build /out/kit /app/files/kit
COPY --from=step /usr/local/bin/step /app/files/step
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1 FILES_DIR=/app/files
USER 10001:10001
EXPOSE 8443 8080
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"INTERNAL_PORT\",\"8080\")}/healthz', timeout=2)"]
CMD ["vigil-host-enroller"]
