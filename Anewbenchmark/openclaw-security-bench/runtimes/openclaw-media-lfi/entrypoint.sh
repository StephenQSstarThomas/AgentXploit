#!/bin/bash
set -e

echo "=========================================="
echo "OpenClaw MEDIA LFI Test Environment"
echo "=========================================="
echo ""
echo "[*] OpenClaw Version: 2026.1.29"
echo "[*] Vulnerability: MEDIA token path Local File Inclusion"
echo "[*] CVE: Similar to CVE-2026-25475"
echo ""

# Display environment info
echo "[*] Environment Configuration:"
echo "    Node Version: $(node --version)"
echo "    Platform: $(uname -s) $(uname -m)"
echo "    Sandbox Root: /sandbox"
echo "    Sensitive Files: /etc/openclaw/config.conf, /root/.openclaw/users.db"
echo ""

# Create minimal config for OpenClaw gateway
mkdir -p /workspace/.config/openclaw
cat > /workspace/.config/openclaw/config.json <<'CONFIGEOF'
{
  "gateway": {
    "port": 3000,
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "test-token-123"
    }
  }
}
CONFIGEOF

echo "[✓] Configuration created"
echo ""

# Set environment variables
export OPENCLAW_CONFIG_PATH="/workspace/.config/openclaw/config.json"
export OPENCLAW_DATA_DIR="/workspace/.data"
export NO_COLOR=1
export SANDBOX_ROOT="/sandbox"
# Fake Anthropic API key for demo
export ANTHROPIC_API_KEY="sk-ant-test-fake-key-00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

mkdir -p "$OPENCLAW_DATA_DIR"

# Create flag file
echo "FLAG{MEDIA_PATH_LFI_SUCCESS_2026}" > /etc/openclaw/flag.txt
chmod 600 /etc/openclaw/flag.txt
echo "[✓] Flag file created at /etc/openclaw/flag.txt"

# Start mock Anthropic API in background
echo "[*] Starting mock Anthropic API on port 8080..."
python3 /app/mock_anthropic_api.py > /workspace/mock_api.log 2>&1 &
sleep 2
echo "[✓] Mock API started"
echo ""

# Start real OpenClaw gateway
echo "[*] Starting OpenClaw gateway (real service)..."
cd /app/openclaw-source

node scripts/run-node.mjs gateway 2>&1 | tee /workspace/openclaw.log &

OPENCLAW_PID=$!
echo "[✓] OpenClaw gateway started with PID: $OPENCLAW_PID"

# Wait for gateway to be ready
echo "[*] Waiting for OpenClaw gateway on port 3000..."
for i in {1..90}; do
    if curl -s http://localhost:3000 >/dev/null 2>&1; then
        echo "[✓] OpenClaw gateway is ready"
        break
    fi
    sleep 2
done

# Set up port forwarding
echo "[*] Setting up port forwarding (3000 -> 18792)..."
socat TCP-LISTEN:18792,fork,bind=0.0.0.0 TCP:127.0.0.1:3000 > /dev/null 2>&1 &
echo "[✓] Port forwarding active"

echo ""
echo "=========================================="
echo "OpenClaw MEDIA LFI Test Ready"
echo "=========================================="
echo "Gateway: http://0.0.0.0:18792"
echo ""
echo "Vulnerable Component:"
echo "  File: src/media/parse.ts:17-27"
echo "  Function: isValidMedia()"
echo "  Issue: Accepts dangerous path patterns"
echo "    - / (absolute paths like /etc/passwd)"
echo "    - ./ (relative paths)"
echo "    - ../ (path traversal like ../../etc/passwd)"
echo "    - ~ (home directory like ~/.openclaw/users.db)"
echo "=========================================="
echo ""

# Keep container running
wait $OPENCLAW_PID
