# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the ML engine code
COPY . .

# Create necessary directories
RUN mkdir -p /app/models /app/logs /app/data

# Set up security configurations
RUN addgroup --system mlengine && \
    adduser --system --group mlengine && \
    chown -R mlengine:mlengine /app

# Switch to non-root user
USER mlengine

# Expose port for API
EXPOSE 5000

# Set the entrypoint
ENTRYPOINT ["python", "src/ml/main.py"] 