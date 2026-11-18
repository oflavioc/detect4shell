#!/usr/bin/env bash
# Detect4Shell — verificação de patch LOCAL e confinada (CVE-2026-114938).
# Compila e roda o reprodutor confinado (escrita fica dentro de um array do próprio
# programa) e o controle de mitigação. NUNCA se conecta a uma JVM de aplicação nem à rede.
# Deriva de poc/verify_corruption.sh de ikow/java4shell-poc (MIT).
#
# Uso:  ./verificar_patch.sh [caminho-do-java]
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
JAVA="${1:-java}"
command -v "$JAVA" >/dev/null || { echo "INCONCLUSIVO: Java indisponível"; exit 2; }
JAVAC="${JAVA}c"; command -v "$JAVAC" >/dev/null || JAVAC="$(dirname "$(command -v "$JAVA")")/javac"
[[ "$(uname -m)" == x86_64 ]] || { echo "PULADO: requer x86-64 (AVX-512 VBMI)"; exit 2; }
flags=$(grep -m1 '^flags' /proc/cpuinfo 2>/dev/null || true)
for f in avx512f avx512bw avx512vbmi bmi2; do
  [[ " $flags " == *" $f "* ]] || { echo "PULADO: CPU sem a flag $f (não afetada nesta máquina)"; exit 2; }
done
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
"$JAVAC" "$DIR/Base64Trigger.java" -d "$work"

rodar() {  # nunca imprime a saída crua da JVM (opções herdadas podem conter segredos)
  local code=0
  "$JAVA" "$@" -cp "$work" Base64Trigger >"$work/out" 2>&1 || code=$?
  if [[ $code -eq 0 ]] && grep -qx REPRODUCED "$work/out"; then echo REPRODUZIDO
  elif [[ $code -eq 1 ]] && grep -qx 'NOT REPRODUCED' "$work/out"; then echo NAO_REPRODUZIDO
  else echo INCONCLUSIVO; fi
}

echo "[1] Runtime atual:          $(rodar)"
echo "[2] -XX:-UseBASE64Intrinsics: $(rodar -XX:-UseBASE64Intrinsics)"
echo "[3] -XX:UseAVX=2:           $(rodar -XX:UseAVX=2)"
echo
echo "Leitura: [1]=REPRODUZIDO + [2]/[3]=NAO_REPRODUZIDO  => este runtime está VULNERÁVEL,"
echo "         e as mitigações funcionam. [1]=NAO_REPRODUZIDO => build corrigido OU CPU sem VBMI"
echo "         (um negativo NÃO prova por si a segurança do serviço em produção)."
