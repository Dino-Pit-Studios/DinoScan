# DinoScan Docker Image
# Provides a containerized environment for running DinoScan analysis

FROM python:3.11-slim

# Set metadata
LABEL org.opencontainers.image.title="DinoScan"
LABEL org.opencontainers.image.description="Comprehensive AST-based Python code analysis toolkit"
LABEL org.opencontainers.image.version="2.0.0"
LABEL org.opencontainers.image.authors="DinoScan Development Team"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better Docker layer caching
COPY pyproject.toml poetry.lock* ./

# Install Poetry and dependencies
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction --no-ansi

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash dinoscan && \
    chown -R dinoscan:dinoscan /app
USER dinoscan

# Set up entry point
ENTRYPOINT ["python", "dinoscan_cli.py"]

# Default command shows help
CMD ["--help"]

# Usage examples:
# docker build -t dinoscan:latest .
# docker run --rm -v $(pwd):/workspace dinoscan:latest security /workspace
# docker run --rm -v $(pwd):/workspace dinoscan:latest all --format json /workspace