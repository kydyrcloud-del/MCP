FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev

# Run as non-root
RUN useradd --create-home app
USER app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1

# Container default: HTTP server for Azure Container Apps (ingress target port 8000,
# liveness/readiness probe: GET /health).
# For stdio instead: docker run -i --entrypoint dynatrace-mcp-python <image>
EXPOSE 8000
ENTRYPOINT ["dynatrace-mcp-python"]
CMD ["--http", "--host", "0.0.0.0", "--port", "8000"]
