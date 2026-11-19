#!/usr/bin/env bash
# Detect4Shell — tier ON-THE-WIRE. Prova que as regras DISPARAM em trafego de verdade (nao so
# que a regex casa / o arquivo carrega). Dois motores reais, via Docker:
#   (a) SURICATA  : replay de PCAP (handshake TCP + HTTP reassemblado) contra regras/suricata/
#                   detect4shell.rules -> gatilho dispara o sid; pcap benigno fica em silencio.
#   (b) MODSECURITY: request HTTP VIVO num nginx+ModSecurity carregando regras/modsecurity/
#                   detect4shell.conf -> gatilho no header Authorization = HTTP 403 (bloqueio via
#                   overlay de enforcement); benigno = 200; gatilho em arg = 200 + logado (o
#                   default ENVIADO e DETECTONLY/pass,log).
#
# LIMITE HONESTO: isto prova DETECCAO/BLOQUEIO no fio, NAO explorabilidade do CVE-2026-114938 nem
# que um host esteja vulneravel. O disparo do oob-write e heap-dependente/probabilistico (ANALISE.md).
# banner != regra != bug. Nada aqui substitui corrigir o JDK.
#
# Exige Docker. Sai !=0 em qualquer falha.  Uso:  bash testes/on-the-wire/run.sh
set -uo pipefail
# MSYS_NO_PATHCONV so e necessario INLINE nos `docker run` (paths-container tipo -v e -r). Se o
# orquestrador exportar a var globalmente (como no tier fp-replay), ela quebra o `curl -o` no
# Git-Bash (rc=23). Neutralizamos aqui e reativamos inline so onde o Docker precisa.
unset MSYS_NO_PATHCONV 2>/dev/null || true
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && { pwd -W 2>/dev/null || pwd; })"   # D:/... no Git-Bash
REPO="$(cd "$HERE/../.." && { pwd -W 2>/dev/null || pwd; })"
WORK="$HERE/.work"
MSEC="$HERE/modsecurity"
PORT=18088

# gatilho determinístico: 64 chars base64 (alfabeto padrão, não-'A') + '=' -> FORMA do Base64 malformado
TRIG='Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFy='
# base64 VÁLIDO (benigno): termina em '==' mas não é quad-alinhado antes do pad -> a regra NÃO casa
VALID='ZGV0ZWN0NHNoZWxsIGJlbmlnbiB2YWxpZCBiYXNlNjQgdG9rZW4gc2FtcGxlIHBhZA=='

cleanup() {
  ( cd "$MSEC" 2>/dev/null && MSYS_NO_PATHCONV=1 docker compose down -v >/dev/null 2>&1 ) || true
  rm -rf "$WORK" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ROWS=(); FAIL=0
row() { ROWS+=("$(printf '%-34s | %-4s | %s' "$1" "$2" "$3")"); [ "$2" = "PASS" ] || FAIL=1; }
summary() {
  echo; echo "===== ON-THE-WIRE SUMMARY ====="
  printf '%-34s | %-4s | %s\n' "check" "res" "detalhe"
  echo "--------------------------------------------------------------------------------"
  printf '%s\n' "${ROWS[@]}"
  echo "--------------------------------------------------------------------------------"
  [ "$FAIL" -eq 0 ] && echo "ON-THE-WIRE: PASS" || echo "ON-THE-WIRE: FAIL"
}

# ---- preflight ----
command -v docker >/dev/null 2>&1 || { echo "FATAL: docker nao encontrado (tier exige Docker)"; exit 2; }
docker info >/dev/null 2>&1          || { echo "FATAL: daemon Docker indisponivel"; exit 2; }
command -v curl   >/dev/null 2>&1 || { echo "FATAL: curl nao encontrado"; exit 2; }

rm -rf "$WORK"; mkdir -p "$WORK/pcaps" "$WORK/out_trig" "$WORK/out_uri" "$WORK/out_benign"

# ================= (a) SURICATA — replay de PCAP =================
echo ">>> [suricata] gerando pcaps (stdlib, em container python)..."
MSYS_NO_PATHCONV=1 docker run --rm \
  -v "$HERE/suricata/gen_pcaps.py:/gen.py:ro" -v "$WORK:/work" \
  python:3.12-slim python -I /gen.py /work/pcaps \
  || { echo "FATAL: geracao de pcap falhou"; summary; exit 1; }

suri() { # <pcap> <outdir>
  MSYS_NO_PATHCONV=1 docker run --rm \
    -v "$WORK/pcaps:/pcaps:ro" \
    -v "$REPO/regras/suricata/detect4shell.rules:/rules.rules:ro" \
    -v "$WORK/$2:/out" \
    --entrypoint suricata jasonish/suricata:8.0.8 \
    -r "/pcaps/$1" -S /rules.rules -l /out -k none >/dev/null 2>&1
}
echo ">>> [suricata] replay: trigger / trigger_uri / benign ..."
suri trigger.pcap     out_trig
suri trigger_uri.pcap out_uri
suri benign.pcap      out_benign

n=$(grep -c '2026114950' "$WORK/out_trig/fast.log" 2>/dev/null); n=${n:-0}
[ "$n" -ge 1 ] && row "suricata header trigger (sid 50)" PASS "sid 2026114950 disparou no http.header" \
                || row "suricata header trigger (sid 50)" FAIL "sid 2026114950 NAO disparou"

n=$(grep -c '2026114951' "$WORK/out_uri/fast.log" 2>/dev/null); n=${n:-0}
[ "$n" -ge 1 ] && row "suricata uri trigger (sid 51)" PASS "sid 2026114951 disparou no http.uri" \
                || row "suricata uri trigger (sid 51)" FAIL "sid 2026114951 NAO disparou"

if grep -q '20261149' "$WORK/out_benign/fast.log" 2>/dev/null; then
  row "suricata benign silencio" FAIL "FALSO-POSITIVO: base64 valido disparou alerta"
else
  row "suricata benign silencio" PASS "0 alertas detect4shell em trafego benigno"
fi

# ================= (b) MODSECURITY — request vivo =================
echo ">>> [modsec] subindo stack WAF(ModSecurity)->backend ..."
( cd "$MSEC" && MSYS_NO_PATHCONV=1 docker compose up -d --build ) >"$WORK/compose-up.log" 2>&1
if [ $? -ne 0 ]; then
  row "modsec stack up" FAIL "docker compose up falhou (ver log abaixo)"
  tail -25 "$WORK/compose-up.log" 2>/dev/null
  summary; exit 1
fi

ready=0; secs=0
for i in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://127.0.0.1:$PORT/healthz" 2>/dev/null || echo 000)
  if [ "$code" = "200" ]; then ready=1; secs=$i; break; fi
  sleep 1
done
[ "$ready" = "1" ] && row "modsec stack readiness" PASS "healthz 200 em ${secs}s" \
                    || row "modsec stack readiness" FAIL "WAF nao respondeu healthz 200"

hc() { curl -s -o /dev/null -w '%{http_code}' --max-time 6 "$@" 2>/dev/null || echo 000; }

c=$(hc -H "Authorization: Basic $TRIG" "http://127.0.0.1:$PORT/login")
[ "$c" = "403" ] && row "modsec header trigger -> 403" PASS "BLOQUEOU (overlay deny na regra 2026114950)" \
                  || row "modsec header trigger -> 403" FAIL "esperava 403, veio $c"

c=$(hc -H "Authorization: Basic $VALID" "http://127.0.0.1:$PORT/app")
[ "$c" = "200" ] && row "modsec benign -> 200" PASS "passou ao backend (sem FP)" \
                  || row "modsec benign -> 200" FAIL "esperava 200, veio $c"

c=$(hc "http://127.0.0.1:$PORT/r?data=$TRIG&n=1")
[ "$c" = "200" ] && row "modsec arg detect-only -> 200" PASS "shipped pass,log: 200 e registra" \
                  || row "modsec arg detect-only -> 200" FAIL "esperava 200, veio $c"

LOGS="$( cd "$MSEC" && MSYS_NO_PATHCONV=1 docker compose logs waf 2>&1 )"
echo "$LOGS" | grep -q '2026114950' && row "modsec audit: header sid logado" PASS "ruleId 2026114950 no audit JSON" \
                                     || row "modsec audit: header sid logado" FAIL "ruleId 2026114950 ausente do audit"
echo "$LOGS" | grep -q '2026114952' && row "modsec audit: arg sid logado" PASS "ruleId 2026114952 no audit (detect-only)" \
                                     || row "modsec audit: arg sid logado" FAIL "ruleId 2026114952 ausente do audit"

summary
exit "$FAIL"
