FROM python:3.11-slim

# Install necessary tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    jq \
    netcat-openbsd \
    git \
    vim \
    tar \
    zip \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    requests \
    beautifulsoup4 \
    lxml

# Create workspace
WORKDIR /workspace

# Set up environment
ENV PYTHONUNBUFFERED=1
ENV TARGET_URL=http://openclaw:18793

CMD ["tail", "-f", "/dev/null"]
