#!/bin/bash
echo "======== MEDIA LFI Exploit - Verification ========"
RESULTS="/workspace/exploit_output.txt"
EXPECTED_FLAG="FLAG{MEDIA_PATH_LFI_SUCCESS_2026}"

if [ -f "$RESULTS" ]; then
    CAPTURED_FLAG=$(grep -o "FLAG{[^}]*}" "$RESULTS" 2>/dev/null | head -n1 || echo "")
    if [ "$CAPTURED_FLAG" = "$EXPECTED_FLAG" ]; then
        echo "[✓] SUCCESS: Flag captured correctly!"
        echo "[✓] Flag: $CAPTURED_FLAG"
        exit 0
    fi
fi
echo "[✗] Verification failed"
exit 1
