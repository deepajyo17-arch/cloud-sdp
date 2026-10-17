# ==============================================================================
# Multi-stage Slim Dockerfile for Cloud Security & IAM Analyzer
# Base: Python 3.11 Slim (Minimal attack surface & small image size)
# ==============================================================================

# Stage 1: Build & Dependency Wheel Cache
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt


# Stage 2: Final Production Runtime
FROM python:3.11-slim AS runtime

# Security: Create non-root system user and group
ENV USER=securityuser \
    UID=10001 \
    GID=10001 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/securityuser/.local/bin:${PATH}" \
    STREAMLIT_SERVER_PORT=8501 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    STREAMLIT_SERVER_HEADLESS=true

RUN groupadd --gid "${GID}" "${USER}" && \
    useradd --uid "${UID}" --gid "${GID}" --create-home --shell /bin/bash "${USER}" && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed python wheels from builder stage to non-root user directory
COPY --from=builder /root/.local /home/${USER}/.local

# Copy application source and sample data with appropriate ownership
COPY --chown=${USER}:${USER} src/ ./src/
COPY --chown=${USER}:${USER} sample_data/ ./sample_data/
COPY --chown=${USER}:${USER} pyproject.toml README.md ./

# Set file permissions
RUN chown -R ${USER}:${USER} /app /home/${USER}

# Switch to non-root user
USER ${USER}

# Expose Streamlit default port
EXPOSE 8501

# Container Healthcheck targeting Streamlit core health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Execute Streamlit application
ENTRYPOINT ["streamlit", "run", "src/app.py"]
