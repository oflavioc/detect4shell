#!/usr/bin/env bash
# Re-run the local Docker JDK sweep for the Detect4Shell / Java4Shell (CVE-2026-114938)
# confined reproducer (laboratorio/Base64Trigger.java) and print a results table.
#
# Usage (Git-Bash on Windows, Docker Desktop running with Linux containers):
#   MSYS_NO_PATHCONV=1 ./run_matrix.sh
# or on native Linux/macOS Bash, just:
#   ./run_matrix.sh
#
# NOTE: image tags below are NOT pinned to a digest — they are the floating
# "latest for this major" tags (e.g. eclipse-temurin:21-jdk, amazoncorretto:21).
# Vendors roll these tags forward over time (notably Amazon Corretto, which had
# already rolled to a patched `.1` point release for 17 and 21 as of 2026-11-18),
# so re-running this script LATER may report a different `java.runtime.version`
# and potentially a different REPRODUCED/NOT REPRODUCED result than matrix.md
# captured. That drift is expected and is itself useful signal — record the new
# runtime version alongside the result rather than assuming the matrix is stale.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."   # -> laboratorio/
LAB_DIR="$(pwd -W 2>/dev/null || pwd)"   # Windows-style path under Git-Bash if available

IMAGES=(
  "eclipse-temurin:17-jdk"
  "eclipse-temurin:21-jdk"
  "eclipse-temurin:25-jdk"
  "amazoncorretto:17"
  "amazoncorretto:21"
)

export MSYS_NO_PATHCONV=1

printf '%-28s %-24s %-8s %-10s %-9s %s\n' "IMAGE" "RUNTIME" "LENGTH" "REJECTED" "CHANGED" "RESULT"
printf '%-28s %-24s %-8s %-10s %-9s %s\n' "-----" "-------" "------" "--------" "-------" "------"

run_one() {
  local image="$1"
  shift
  local extra_args=("$@")
  local out
  # Pull (online) only if the image is missing, THEN run the reproducer with --network none so the
  # measurement itself is offline — matching matrix.md's "sem acesso à rede" claim for the data run.
  docker image inspect "$image" >/dev/null 2>&1 || docker pull "$image" >/dev/null 2>&1 || true
  out="$(docker run --rm --network none -v "${LAB_DIR}:/t:ro" "$image" sh -c \
    "cd /tmp && cp /t/Base64Trigger.java . && javac Base64Trigger.java && java ${extra_args[*]:-} Base64Trigger" 2>&1)"
  local runtime length rejected changed result
  runtime="$(printf '%s\n' "$out" | sed -n 's/^runtime=//p' | head -1)"
  rejected="$(printf '%s\n' "$out" | sed -n 's/.*rejected=\([a-z]*\).*/\1/p' | head -1)"
  changed="$(printf '%s\n' "$out" | sed -n 's/.*changed=\([0-9-]*\).*/\1/p' | head -1)"
  if printf '%s\n' "$out" | grep -q '^REPRODUCED$'; then
    result="REPRODUCED"
  elif printf '%s\n' "$out" | grep -q 'NOT REPRODUCED'; then
    result="NOT REPRODUCED"
  else
    result="ERROR (see raw output below)"
  fi
  # Infer trigger length from runtime major (reproducer logic: 128 on JDK 17, else 64)
  local major="${runtime%%.*}"
  local length="?"
  if [ "$major" = "17" ]; then length=128; else length=64; fi

  printf '%-28s %-24s %-8s %-10s %-9s %s\n' "$image ${extra_args[*]:-}" "$runtime" "$length" "$rejected" "$changed" "$result"
  if [ "$result" = "ERROR (see raw output below)" ]; then
    echo "----- raw output for $image ${extra_args[*]:-} -----"
    printf '%s\n' "$out"
    echo "-----------------------------------------------------"
  fi
}

for img in "${IMAGES[@]}"; do
  run_one "$img"
done

echo
echo "Mitigation proxies on eclipse-temurin:21-jdk (the known-vulnerable build):"
run_one "eclipse-temurin:21-jdk" -XX:-UseBASE64Intrinsics
run_one "eclipse-temurin:21-jdk" -XX:UseAVX=2

echo
echo "Done. Compare against laboratorio/matrix/matrix.md — image tags are NOT pinned,"
echo "so a vendor rolling a tag to a new point release can change the result/version."
