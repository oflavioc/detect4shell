#!/usr/bin/env python3
"""
Detect4Shell — lógica de DETECÇÃO de referência para o Java4Shell (CVE-2026-114938).

Identifica a assinatura de rede do gatilho do Java4Shell: um token Base64 malformado
cuja forma chega ao decodificador Base64 do OpenJDK com uma "cauda" que provoca o
underflow de `output_size` no intrínseco AVX-512 VBMI. Isto é uma REFERÊNCIA de detecção
— casa a *forma do gatilho*; NÃO gera, envia nem arma nada.

Por que uma referência nova (vs. as regras upstream ikow/java4shell-poc):
  - Os alertas upstream são centrados em Basic auth e, em parte, por STRING EXATA
    ("AAAA…A="). O gatilho real é QUALQUER sequência Base64 terminando em '=' com
    comprimento % 4 != 0 e trecho pré-padding >= 64 — os bytes não precisam ser 'A',
    e o "sink" é qualquer caminho de Base64.decode()/getUrlDecoder() pré-autenticação:
    Basic auth, segmentos Bearer/JWT, SAML (SAMLRequest/SAMLResponse/RelayState),
    cookies, parâmetros de query/corpo.
  - Logo, as regras exatas-de-'A' do upstream são trivialmente evadidas e perdem SAML +
    Base64 url-safe por completo. Esta referência é estrutural, agnóstica ao vetor,
    cobre os dois alfabetos e tem piso de comprimento para manter os falsos-positivos
    baixos.

Forma do gatilho (alta confiança):
    token ∈ (padrão [A-Za-z0-9+/] ou url-safe [A-Za-z0-9_-]) + '=' final (1..2)
    E    len(token) % 4 != 0            # Base64 válido é sempre % 4 == 0
    E    len(token sem '=' final) >= 64  # bloco de 64 do intrínseco + aquecimento JIT

Fundamentado em docs/ANALISE.md da divulgação e no commit de correção do OpenJDK
5177a70b385c (JDK-8393212). Mecanismo, não exploit.
"""
from __future__ import annotations
import re
import sys

# Uma sequência Base64 em qualquer alfabeto, com 1 ou 2 '=' de padding no fim.
_TOKEN = re.compile(r'[A-Za-z0-9+/_-]{60,}={1,2}')
MIN_PREPAD = 64  # o intrínseco só roda após um bloco completo de 64 chars (+ aquecimento JIT)


def is_trigger_shape(token: str) -> bool:
    """True se `token` casa a FORMA do gatilho Base64-malformado do Java4Shell.

    Escopo da validação (temurin 21.0.13, confinado): nessa build, o overflow disparou com um
    corpo de 64 chars Base64 + EXATAMENTE um '=' (65 no total). 68/72/128/192/256 + '=' NÃO
    dispararam — ou seja, o gatilho é um comprimento ESPECÍFICO por build (64 no JDK 21/25/27;
    128 no JDK 17), não "qualquer múltiplo de 4". `A*64+"=="` (dois pads) e sem-'=' também não
    disparam. A regra usa `{16,}` de propósito: pega 64 E 128 (os dois gatilhos documentados) e é
    robusta a variações de build, aceitando super-casar comprimentos malformados que não disparam
    (ok para detecção). Outras builds/APIs/normalizações não foram testadas."""
    m = re.fullmatch(r'([A-Za-z0-9+/_-]+)=', token.strip())  # exatamente UM '=' no fim
    if not m:
        return False
    body = m.group(1)
    if len(body) < MIN_PREPAD:          # precisa alcançar o bloco de 64 do intrínseco
        return False
    if len(body) % 4 != 0:              # prepad precisa ser quads Base64 completos (lab: não-alinhado não dispara)
        return False
    return True


def find_triggers(text: str) -> list[str]:
    """Retorna cada substring de `text` que casa a forma do gatilho."""
    return [m.group(0) for m in _TOKEN.finditer(text) if is_trigger_shape(m.group(0))]


# ---- classificação do vetor (onde, numa requisição HTTP, o token apareceu) ----
def classify_vector(name: str, location: str) -> str:
    n = (name or '').lower()
    if location == 'header' and n == 'authorization':
        return 'auth-basic-ou-bearer'
    if n in ('samlrequest', 'samlresponse', 'relaystate'):
        return 'saml'
    if location == 'cookie':
        return 'cookie'
    if location == 'query':
        return 'parametro-query'
    if location == 'body':
        return 'parametro-corpo'
    return f'{location}:{n}'


# ---- o casamento exato-de-'A' do UPSTREAM, só para comparação de lacuna ----
_UPSTREAM_EXACT = (
    'A' * 64 + '=',   # sid 2026114902
    'A' * 128 + '=',  # sid 2026114903 (JDK17)
)
_UPSTREAM_BASIC_PCRE = re.compile(r'Basic\s+[A-Za-z0-9+/]{64,}={1}\s*$')


def upstream_would_alert(raw_request: str) -> bool:
    """Aproxima as regras upstream: conteúdo exato-de-'A' OU pcre de Basic-auth malformado."""
    if any(sig in raw_request for sig in _UPSTREAM_EXACT):
        return True
    for line in raw_request.splitlines():
        if _UPSTREAM_BASIC_PCRE.search(line):
            return True
    return False


if __name__ == '__main__':
    data = sys.stdin.read() if len(sys.argv) < 2 else ' '.join(sys.argv[1:])
    hits = find_triggers(data)
    if hits:
        print(f'FORMA-DE-GATILHO x{len(hits)}')
        for h in hits:
            print(f'  len={len(h)} pads={len(h)-len(h.rstrip("="))} {h[:24]}...{h[-6:]}')
        sys.exit(1)
    print('nenhuma forma de gatilho')
