#!/usr/bin/env bash
# Sends one benign + one trigger-shape request to the monitor-mode sensor.
# Trigger = "Authorization: Basic" + 64 'A' + '=' (shape only; the mock is inert).
HOST="${1:-http://127.0.0.1:8097}"
A64=$(printf 'A%.0s' $(seq 1 64))
echo "--- benign (-u admin:secret)"
curl -s -o /dev/null -w "HTTP %{http_code}\n" -u admin:secret "$HOST/"
echo "--- trigger (Basic + 64xA + '=')"
curl -s -o /dev/null -w "HTTP %{http_code}  (monitor mode: must be 200, not 403)\n" \
  -H "Authorization: Basic ${A64}=" "$HOST/"
echo "--- sensor alert log (only the trigger should appear)"
docker compose -f "$(dirname "$0")/docker-compose.yml" exec -T sensor cat //var/log/j4s/alerts.jsonl
