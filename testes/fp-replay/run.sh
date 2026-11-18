#!/usr/bin/env bash
# Detect4Shell FP-replay — taxa de FP de PRODUCAO da forma canonica contra ~108k strings benignas
# reais (base64 valido std+url, JWTs, data-URIs, presigned URLs, hex, UUIDs, paths REST, SecLists).
# Offline e deterministico (seed). Motores fieis via Docker: pcre2 + google-re2.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
SL="$HERE/common.txt"
if [ ! -f "$SL" ]; then
  echo "[*] baixando SecLists common.txt (paths web reais; opcional)..."
  curl -fsSL -o "$SL" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    || echo "[!] download falhou — segue sem os paths do SecLists"
fi
# No Git-Bash (Windows): MSYS_NO_PATHCONV=1 e caminho absoluto C:/.. ou D:/..
exec docker run --rm \
  -v "$HERE/fp_replay.py:/v.py:ro" \
  ${SL:+-v "$SL:/seclists/common.txt:ro"} \
  python:3.12-slim sh -c "pip install -q google-re2 pcre2 2>/dev/null && python /v.py"
