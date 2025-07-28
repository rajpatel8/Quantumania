FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application
COPY quantum_crypto_scanner/ ./quantum_crypto_scanner/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install -e .

# Create a non-root user
RUN useradd -m -u 1000 scanner
USER scanner

ENTRYPOINT ["quantum-crypto-scan"]