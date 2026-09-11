# DIODE / NET-DRISHTI Air-Gapped Threat Detection Enclave — Backend Container
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies (libpcap for network frame operations)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, trained models, configurations, and assets
COPY config.py main.py Procfile ./
COPY src/ ./src/
COPY models/ ./models/
COPY traffic/ ./traffic/
COPY dashboard/ ./dashboard/

# Expose default port
EXPOSE 8000

# Bind to all interfaces and read dynamic PORT
ENV HOST=0.0.0.0
ENV PORT=8000

# Launch FastAPI backend with WebSockets
CMD ["python3", "main.py", "--serve"]
