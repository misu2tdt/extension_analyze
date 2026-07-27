#!/bin/bash
set -e

CRX_PATH=${1:-/work/extension.crx}
OUTPUT_DIR=${2:-/work/output}
TIMEOUT=${3:-180}

echo "[Sandbox] === Starting analysis ==="
echo "[Sandbox] CRX: $CRX_PATH"
echo "[Sandbox] Output: $OUTPUT_DIR"
echo "[Sandbox] Timeout: ${TIMEOUT}s"

mkdir -p "$OUTPUT_DIR"
# Don output cu (tranh nham lan file tu lan chay truoc)
rm -rf "$OUTPUT_DIR"/* 2>/dev/null || true

# Serve honey pages qua HTTP server local (port 8888)
python3 -m http.server 8888 --directory /sandbox/honey_pages > /dev/null 2>&1 &
HTTP_PID=$!
echo "[Sandbox] Honey page server started (PID=$HTTP_PID)"
sleep 1

# Bat dau tcpdump (chay nen)
tcpdump -i any -w "$OUTPUT_DIR/capture.pcap" -U > /dev/null 2>&1 &
TCPDUMP_PID=$!
echo "[Sandbox] tcpdump started (PID=$TCPDUMP_PID)"
sleep 1

# Chay phan tich trong Xvfb (man hinh ao). timeout = luoi an toan cuoi cung.
set +e
xvfb-run -a --server-args="-screen 0 1280x720x24" \
    timeout "$TIMEOUT" python3 /sandbox/analyze.py \
        --crx "$CRX_PATH" \
        --output "$OUTPUT_DIR" \
        --timeout "$TIMEOUT"
ANALYZE_EXIT=$?
set -e

echo "[Sandbox] Analysis exit code: $ANALYZE_EXIT"

# Dung tcpdump bang SIGINT roi wait => pcap flush day du (tranh cat giua buffer)
kill -INT $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
kill $HTTP_PID 2>/dev/null || true

echo "[Sandbox] === Done ==="
ls -la "$OUTPUT_DIR"