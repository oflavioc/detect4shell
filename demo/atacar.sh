#!/usr/bin/env bash
# Detect4Shell demo — dispara a FORMA do gatilho Java4Shell (CVE-2026-114938) contra uma URL.
# O "payload" e a string Base64 malformada ja publica (A*64 + "="). Uso so em lab/localhost.
#   ./atacar.sh http://127.0.0.1:18080/     # direto no alvo (sem defesa)
#   ./atacar.sh http://127.0.0.1:8088/      # via edge nginx Detect4Shell (com defesa)
set -u
URL="${1:-http://127.0.0.1:18080/}"
TRIG="Basic $(printf 'A%.0s' $(seq 1 64))="
QS="SAMLResponse=$(printf 'A%.0s' $(seq 1 64))="
show(){ curl -s -m 6 -o /tmp/d4s_body -w "%{http_code}" "$@"; echo " | $(cat /tmp/d4s_body)"; }

echo "== alvo: $URL =="
echo -n "  benigno  (admin:secret)         -> HTTP "; show -u admin:secret           "$URL"
echo -n "  GATILHO  (Authorization Basic)  -> HTTP "; show -H "Authorization: $TRIG"  "$URL"
echo -n "  GATILHO  (query SAMLResponse)   -> HTTP "; show                            "${URL}?${QS}"
