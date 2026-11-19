#!/usr/bin/env bash
# Detect4Shell demo — dispara a FORMA do gatilho Java4Shell (CVE-2026-114938) contra uma URL.
# O "payload" e a string Base64 malformada ja publica (A*64 + "="). Uso so em lab/localhost.
#   ./atacar.sh http://127.0.0.1:18080/     # direto no alvo (sem defesa)
#   ./atacar.sh http://127.0.0.1:8088/      # via edge nginx Detect4Shell (com defesa)
set -u
URL="${1:-http://127.0.0.1:18080/}"

# Trava de lab (higiene, nao "seguranca"): por padrao so dispara contra LOOPBACK
# (127.0.0.1 e todo o 127.0.0.0/8, localhost, ::1, *.localhost). Para um alvo em outro
# host -- so em rede isolada e com autorizacao -- habilite com D4S_ALLOW_REMOTE=1.
_d4s_host="${URL#*://}"          # tira o esquema
_d4s_host="${_d4s_host##*@}"     # tira userinfo (user:pass@)
_d4s_host="${_d4s_host%%/*}"     # tira o caminho
case "$_d4s_host" in
  \[*\]*) _d4s_host="${_d4s_host#\[}"; _d4s_host="${_d4s_host%%\]*}" ;;  # IPv6 [::1]:porta -> ::1
  *:*)    _d4s_host="${_d4s_host%%:*}" ;;                               # host:porta -> host
esac
_d4s_host="$(printf '%s' "$_d4s_host" | tr '[:upper:]' '[:lower:]')"
case "$_d4s_host" in
  127.0.0.1|127.[0-9]*|localhost|*.localhost|::1|0:0:0:0:0:0:0:1) : ;;  # loopback: segue
  *)
    if [ "${D4S_ALLOW_REMOTE:-0}" != "1" ]; then
      echo "RECUSADO: alvo nao-loopback \"$_d4s_host\" ($URL)." >&2
      echo "  atacar.sh e ferramenta de LAB; por padrao so dispara contra loopback" >&2
      echo "  (127.0.0.1/8, localhost, ::1, *.localhost). Para outro host -- so em rede" >&2
      echo "  isolada e autorizado -- use o opt-in explicito:" >&2
      echo "     D4S_ALLOW_REMOTE=1 ./atacar.sh $URL" >&2
      exit 2
    fi
    echo "== alvo remoto HABILITADO via D4S_ALLOW_REMOTE=1 ==" >&2
    ;;
esac

TRIG="Basic $(printf 'A%.0s' $(seq 1 64))="
QS="SAMLResponse=$(printf 'A%.0s' $(seq 1 64))="
show(){ curl -s -m 6 -o /tmp/d4s_body -w "%{http_code}" "$@"; echo " | $(cat /tmp/d4s_body)"; }

echo "== alvo: $URL =="
echo -n "  benigno  (admin:secret)         -> HTTP "; show -u admin:secret           "$URL"
echo -n "  GATILHO  (Authorization Basic)  -> HTTP "; show -H "Authorization: $TRIG"  "$URL"
echo -n "  GATILHO  (query SAMLResponse)   -> HTTP "; show                            "${URL}?${QS}"
