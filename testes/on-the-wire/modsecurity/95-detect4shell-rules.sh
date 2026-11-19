#!/bin/sh
# Roda DEPOIS do 90-copy-modsecurity-config.sh da imagem base, que gera
# /etc/modsecurity.d/modsecurity-override.conf (onde ficam SecRuleEngine/SecAuditEngine/...).
# Acrescentamos (sem reescrever) os Includes das regras ENVIADAS + o overlay de enforcement.
# Ordem importa: a regra 2026114950 precisa existir ANTES do SecRuleUpdateActionById do overlay.
set -eu
OVR=/etc/modsecurity.d/modsecurity-override.conf
{
  echo ""
  echo "# --- Detect4Shell on-the-wire: regras enviadas + overlay de enforcement ---"
  echo "Include /rules/detect4shell.conf"
  echo "Include /rules/overlay.conf"
} >> "$OVR"
