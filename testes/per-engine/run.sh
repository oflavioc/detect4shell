#!/usr/bin/env bash
# Git-Bash on Windows. Builds the image and runs the per-engine harness with the repo mounted read-only.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && { pwd -W 2>/dev/null || pwd; })"   # D:/... on Git-Bash, /... elsewhere
docker build -q -t detect4shell-per-engine "$HERE" >/dev/null
MSYS_NO_PATHCONV=1 docker run --rm -v "${REPO}:/repo:ro" -w /repo/testes/per-engine \
  detect4shell-per-engine python -B run.py "$@"
