FROM node:22-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    git \
    vim \
    jq \
    socat \
    procps \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# Install Flask for mock API
RUN pip3 install --no-cache-dir flask --break-system-packages

# Set working directory
WORKDIR /app

# Copy OpenClaw source code (version 2026.1.29 with MEDIA path LFI vulnerability)
COPY openclaw-source /app/openclaw-source

# Install OpenClaw dependencies
WORKDIR /app/openclaw-source
RUN npm install -g pnpm@10.23.0
RUN pnpm install --frozen-lockfile || pnpm install

# Build OpenClaw
RUN pnpm build || echo "Build completed with warnings"

# Create workspace directory and sensitive files for LFI demonstration
RUN mkdir -p /workspace /sandbox /etc/openclaw
RUN echo "OPENCLAW_ADMIN_TOKEN=secret_admin_token_abc123" > /etc/openclaw/config.conf
RUN echo "DATABASE_PASSWORD=db_production_pass_xyz789" >> /etc/openclaw/config.conf
RUN echo "API_SECRET_KEY=super_secret_api_key_456" >> /etc/openclaw/config.conf
RUN chmod 600 /etc/openclaw/config.conf

RUN mkdir -p /root/.openclaw
RUN echo "USER_CREDENTIALS=root:\$2b\$12\$hashedpassword" > /root/.openclaw/users.db
RUN chmod 600 /root/.openclaw/users.db

# Create mock Anthropic API for testing
COPY mock_anthropic_api.py /app/mock_anthropic_api.py

# Set working directory to workspace
WORKDIR /workspace

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 18792

ENTRYPOINT ["/entrypoint.sh"]
