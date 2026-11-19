#!/usr/bin/env bash
# Detect4Shell - compile+run do harness funcional do Servlet Filter (AUTO-CONTIDO: sem Maven, sem baixar
# a servlet-api). Compila os STUBS inline de jakarta.servlet (mitigacao/test/jakarta/) + o REAL
# mitigacao/Java4ShellFilter.java + o harness mitigacao/test/Java4ShellFilterTest.java com javac, roda os
# cenarios com assertions e propaga o exit-code (0 = todos passam, !=0 = alguma falha => gate vermelho).
# Requer apenas um JDK (javac + java) no PATH; validado com javac/java 21. Portavel Git-Bash/Windows +
# Linux CI: usa paths RELATIVOS (sem leading '/') p/ evitar o path-mangling do MSYS.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # raiz do repo (este script esta em mitigacao/test/)
OUT="mitigacao/test/build"
rm -rf "$OUT"; mkdir -p "$OUT"

echo "[filter-harness] javac -> $OUT (stubs jakarta.servlet + filtro + harness)"
if ! javac -d "$OUT" \
    mitigacao/test/jakarta/servlet/*.java \
    mitigacao/test/jakarta/servlet/http/*.java \
    mitigacao/Java4ShellFilter.java \
    mitigacao/test/Java4ShellFilterTest.java; then
  echo "[filter-harness] COMPILE FAIL"; rm -rf "$OUT"; exit 1
fi

echo "[filter-harness] java detect4shell.Java4ShellFilterTest"
java -cp "$OUT" detect4shell.Java4ShellFilterTest
rc=$?

rm -rf "$OUT"
exit $rc
