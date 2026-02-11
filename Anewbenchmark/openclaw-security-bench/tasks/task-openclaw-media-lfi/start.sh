#!/bin/bash
echo "[*] OpenClaw MEDIA LFI - Environment Check"
echo ""
echo "[Check 1] Verifying OpenClaw gateway accessibility..."
if curl -s http://openclaw:3000 > /dev/null 2>&1; then
    echo "[✓] OpenClaw gateway is accessible"
else
    echo "[✗] Gateway not accessible"
    exit 1
fi
echo "[✓] Environment ready"
exit 0
