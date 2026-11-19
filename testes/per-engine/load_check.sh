#!/usr/bin/env bash
# Git-Bash on Windows (also works on Linux). LOAD tier: does the ACTUAL shipped rule FILE load in the real engine?
# Separate from the regex matrix (run.sh). Read-only mounts; never edits regras/. Exit 1 if any engine fails to load.
#   YARA     : yara-python in detect4shell-per-engine (python:3.12-slim)        -> yara.compile(filepath=...)
#   nginx    : nginx:1.27-alpine  `nginx -t` with the shipped file include'd in http{}
#   Suricata : jasonish/suricata:8.0.8 (PINNED; was :latest)  `suricata -T -S <rules>`; asserts 0 failed, loaded == #alert lines
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && { pwd -W 2>/dev/null || pwd; })"
RULES="$(cd "$HERE/../.." && pwd)/regras"
docker build -q -t detect4shell-per-engine "$HERE" >/dev/null
D() { MSYS_NO_PATHCONV=1 docker run --rm -v "${REPO}:/repo:ro" "$@"; }

ROWS=(); FAIL=0
row() { ROWS+=("$(printf '%-9s | %-6s | %s' "$1" "$2" "$3")"); [ "$2" = "yes" ] || FAIL=1; }

# ---- YARA ----
out="$(D -w /repo/testes/per-engine detect4shell-per-engine python -B load_yara.py 2>&1)"; rc=$?
[ $rc -eq 0 ] && row YARA yes "$out" || row YARA NO "$(echo "$out" | tail -1)"

# ---- nginx ----
CONF='events {} http { include /repo/regras/nginx/detect4shell.conf; server { listen 8080; location / { return 200 ok; } } }'
out="$(D nginx:1.27-alpine sh -c "echo '$CONF' > /tmp/nginx.conf && nginx -t -c /tmp/nginx.conf" 2>&1)"; rc=$?
if [ $rc -eq 0 ] && echo "$out" | grep -q "syntax is ok" && echo "$out" | grep -q "test is successful"; then
  row nginx yes "$(echo "$out" | grep 'syntax is ok')"
else row nginx NO "$(echo "$out" | tail -2 | tr '\n' ' ')"; fi

# ---- Suricata ----
out="$(D --entrypoint suricata jasonish/suricata:8.0.8 -T -v -S /repo/regras/suricata/detect4shell.rules -l /tmp 2>&1)"; rc=$?
expected="$(grep -c '^alert' "$RULES/suricata/detect4shell.rules")"
sline="$(echo "$out" | grep -E 'rules successfully loaded' | sed 's/^.*detect: //')"
failed="$(echo "$sline" | grep -oE '[0-9]+ rules failed' | grep -oE '^[0-9]+')"
loaded="$(echo "$sline" | grep -oE '[0-9]+ rules successfully' | grep -oE '^[0-9]+')"
if [ $rc -eq 0 ] && [ "${failed:-x}" = "0" ] && [ "${loaded:-x}" = "$expected" ] && ! echo "$out" | grep -qE '^(Error|E:)|<Error>'; then
  row Suricata yes "$sline (expected $expected alert lines)"
else row Suricata NO "rc=$rc ${sline:-$(echo "$out" | grep -iE 'error' | head -3 | tr '\n' ' ')} (expected $expected)"; fi

echo "LOAD matrix (real engine binaries; shipped rule files)"
printf '%-9s | %-6s | %s\n' engine loads? detail
echo "----------------------------------------------------------------"
printf '%s\n' "${ROWS[@]}"
echo "----------------------------------------------------------------"
echo "LOAD FAILURES: $FAIL"
exit $FAIL
