FROM python:3.11-slim

# Install system dependencies including build tools for enhanced features
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libxml2-dev \
    libxslt-dev \
    openjdk-11-jdk \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Set Java environment for sonar integration
ENV JAVA_HOME=/usr/lib/jvm/java-11-openjdk-amd64

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Try to install enhanced dependencies (optional)
RUN pip install --no-cache-dir pyyaml jinja2 click || echo "Some enhanced dependencies not available"

# Copy the application
COPY quantum_crypto_scanner/ ./quantum_crypto_scanner/
COPY setup.py .
COPY README.md .

# Install the package
RUN pip install -e .

# Create a non-root user
RUN useradd -m -u 1000 scanner
USER scanner

# Set default to enhanced mode
ENTRYPOINT ["quantum-crypto-scan"]
CMD ["--help"]