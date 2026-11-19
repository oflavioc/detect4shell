#!/usr/bin/env bash
# Detect4Shell regression gate. Runs the EXISTING tests in order; stops at the FIRST failure (exit 1).
#   bash test.sh            # needs python3 + Docker
#
# NOT in the blocking gate: laboratorio/matrix/run_matrix.sh. It pulls 5 external JDK images whose
# floating tags DRIFT (e.g. Corretto already rolled to the patched build), so its results legitimately
# change over time. It is periodic VALIDATION, not a regression gate. Opt in (warn-only, non-blocking):
#   RUN_MATRIX=1 bash test.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

TIERS=(
  "1/7 validar.py (FN+FP unit, no Docker)|python3 -I testes/validar.py"
  "2/7 canonical drift-guard: 3 out-of-band regex copies (no Docker)|python3 -I testes/canonical_sync.py"
  "3/7 Servlet Filter compile+harness: javac stubs + 13 scenarios (no Docker)|bash mitigacao/test/run.sh"
  "4/7 per-engine regex matrix (Docker)|bash testes/per-engine/run.sh"
  "5/7 in-engine rule LOAD: YARA/nginx/Suricata (Docker)|bash testes/per-engine/load_check.sh"
  "6/7 fp-replay 0-FP (Docker)|MSYS_NO_PATHCONV=1 bash testes/fp-replay/run.sh"  # NO_PATHCONV: Git-Bash/Windows mount fix for run.sh; no-op on Linux
  "7/7 on-the-wire replay: Suricata PCAP + ModSecurity live (Docker)|bash testes/on-the-wire/run.sh"
)

SUMMARY=()
for t in "${TIERS[@]}"; do
  name="${t%%|*}"; cmd="${t#*|}"
  echo; echo "===== TIER $name ====="; echo "\$ $cmd"
  if bash -c "$cmd"; then
    echo "----- PASS: $name"; SUMMARY+=("PASS  $name")
  else
    rc=$?
    echo "----- FAIL: $name (exit $rc)"; SUMMARY+=("FAIL  $name")
    echo; echo "===== SUMMARY ====="; printf '%s\n' "${SUMMARY[@]}"
    echo "OVERALL: FAIL (stopped at first failure)"
    exit 1
  fi
done

if [ "${RUN_MATRIX:-0}" = "1" ]; then
  echo; echo "===== OPTIONAL (non-blocking) laboratorio/matrix/run_matrix.sh ====="
  bash laboratorio/matrix/run_matrix.sh || echo "WARN: matrix run failed (non-blocking; JDK images drift)"
fi

echo; echo "===== SUMMARY ====="; printf '%s\n' "${SUMMARY[@]}"
echo "OVERALL: PASS (all ${#TIERS[@]} tiers)"
