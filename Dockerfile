# Dockerfile.railway
FROM python:3.9-slim

# Install system dependencies (Railway compatible)
RUN apt-get update && apt-get install -y \
    wireguard-tools \
    iptables \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /tmp/wireguard-paas/keys /tmp/wireguard

# Set environment variables for Railway
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=app.py
ENV PORT=8080

# Expose port (Railway will use PORT env var)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/status || exit 1

# Run the application
CMD ["python", "app.py"]