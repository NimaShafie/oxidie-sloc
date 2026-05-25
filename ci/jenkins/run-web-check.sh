#!/usr/bin/env bash
# Web UI health check — start the oxide-sloc server, poll for HTTP 200, then stop it.
# BINARY is set by the Jenkinsfile environment{} block.
set -euo pipefail

"${BINARY}" serve &
SERVER_PID=$!

HTTP_CODE="000"
for _ in $(seq 1 30); do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:4317/ 2>/dev/null || echo "000")
    [ "${HTTP_CODE}" = "200" ] && break
    sleep 1
done

kill "${SERVER_PID}" 2>/dev/null || true
wait "${SERVER_PID}" 2>/dev/null || true

if [ "${HTTP_CODE}" != "200" ]; then
    echo "Web UI returned HTTP ${HTTP_CODE} — expected 200"
    exit 1
fi
echo "Web UI responded with HTTP 200 — OK"
