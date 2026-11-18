#!/usr/bin/env python3
"""
Valida a detecção do Detect4Shell contra vetores rotulados e quantifica a lacuna
frente às regras upstream (ikow/java4shell-poc).

Todos os vetores são TEXTO BENIGNO (strings Base64 malformadas / trechos de requisição
HTTP). Nada aqui envia tráfego ou dispara qualquer coisa. Rode:  python -I testes/validar.py
"""
import os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'deteccao'))
import detect4shell as d

# A PCRE EXATA embarcada nas regras Suricata / Sigma / ModSecurity:
# >=16 "quads" Base64 (64 chars, ambos alfabetos) + EXATAMENTE um '=' numa fronteira
# não-Base64. Validado em lab: o overflow só dispara com corpo alinhado a quads (múltiplo
# de 4, >=64) + UM '='; `A*65+"="` (não-alinhado) e `A*64+"=="` (dois pads) NÃO disparam,
# então são corretamente excluídos. Base64 válido (% 4 == 0) também é excluído.
ENGINE_PCRE = re.compile(r'(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{4}){16,}+=(?![A-Za-z0-9+/_=-])')

B64_STD_64 = ("Zm9vYmFy" * 8)[:64]          # 64 chars do alfabeto padrão, não-'A'
B64_URLSAFE_64 = ("Zm9v-mF_" * 8)[:64]      # 64 chars incl. url-safe '-' e '_'
assert len(B64_STD_64) == 64 and len(B64_URLSAFE_64) == 64, (len(B64_STD_64), len(B64_URLSAFE_64))

# Cada vetor: (id, descrição, requisição_crua, deve_alertar)
VETORES = [
    # ---- GATILHOS (devem ser detectados) ----
    ("T1-basic-A",   "canônico: Basic auth, 64*A + '='",
     f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*64}=\r\n\r\n", True),
    ("T2-basic-naoA", "evasão: Basic auth, 64 chars Base64 não-'A' + '='",
     f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {B64_STD_64}=\r\n\r\n", True),
    ("T3-saml-corpo",  "LACUNA: SAMLResponse no corpo POST (sink pré-auth Keycloak/PingFederate)",
     f"POST /saml/acs HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nSAMLResponse={B64_STD_64}=&RelayState=/home", True),
    ("T4-saml-query", "LACUNA: SAMLRequest na query (redirect binding)",
     f"GET /saml?SAMLRequest={B64_STD_64}=&x=1 HTTP/1.1\r\nHost: x\r\n\r\n", True),
    ("T5-urlsafe",    "LACUNA: alfabeto url-safe (- _) — classes do upstream perdem",
     f"GET /api?token={B64_URLSAFE_64}= HTTP/1.1\r\nHost: x\r\n\r\n", True),
    ("T6-cookie",     "LACUNA: Base64 malformado em valor de Cookie",
     f"GET /app HTTP/1.1\r\nHost: x\r\nCookie: sess={B64_STD_64}=\r\n\r\n", True),
    ("T7-param",      "LACUNA: Base64 malformado como parâmetro de query (não corpo, não basic-auth)",
     f"GET /r?data={B64_STD_64}=&next=/ HTTP/1.1\r\nHost: x\r\n\r\n", True),
    ("T8-jdk17-128",  "gatilho JDK 17: 128×A + '=' (32 quads)",
     f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*128}=\r\n\r\n", True),

    # ---- NÃO-GATILHOS (NÃO podem ser detectados — controles de falso-positivo) ----
    ("N6-prepad65",   "lab: prepad NÃO-alinhado a 4 (65 chars)+'=' NÃO dispara o overflow",
     f"GET /r?data={B64_STD_64}Q=&n=/ HTTP/1.1\r\nHost: x\r\n\r\n", False),
    ("N7-dois-pads",  "lab: A×64 + '==' (dois pads) NÃO dispara o overflow",
     f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*64}==\r\n\r\n", False),
    ("N8-data-uri",   "FP-control: data-URI base64 válido em corpo (len%4==0, '==')",
     f"POST /u HTTP/1.1\r\nHost: x\r\n\r\nimg=data:image/png;base64,{B64_STD_64}QQ==", False),
    ("N1-basic-valido","Basic auth válido (len%4==0)",
     "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n", False),
    ("N2-longo-valido", "Base64 longo válido, padding correto (len%4==0)",
     f"POST /u HTTP/1.1\r\nHost: x\r\n\r\nblob={B64_STD_64}QQ==", False),
    ("N3-malf-curto","malformado porém curto (<64 pré-padding) — não alcança o bloco do intrínseco",
     "GET /?t=aGVsbG8=x HTTP/1.1\r\nHost: x\r\n\r\n", False),
    ("N4-sem-pad",     "sequência Base64 longa, sem '=' no fim",
     f"GET /?t={B64_STD_64}QQ HTTP/1.1\r\nHost: x\r\n\r\n", False),
    ("N5-nao-b64",  "token longo não-Base64 (hex)",
     "GET /?t=" + "0123456789abcdef"*5 + " HTTP/1.1\r\nHost: x\r\n\r\n", False),
]

def main():
    print(f"{'ID':<14} {'alertar':<8} {'py':<5} {'pcre-ids':<9} {'exata-A':<9} {'veredito'}")
    print("-"*74)
    meu_ok = up_ok = eng_ok = 0
    lacunas = []  # gatilhos reais que nós pegamos e o upstream perde
    fp_meu = fp_up = fp_eng = 0
    for vid, desc, raw, deve in VETORES:
        meu = bool(d.find_triggers(raw))
        eng = bool(ENGINE_PCRE.search(raw))
        up = d.upstream_would_alert(raw)
        meu_ok += (meu == deve); eng_ok += (eng == deve); up_ok += (up == deve)
        if deve and meu and not up: lacunas.append((vid, desc))
        if (not deve) and meu: fp_meu += 1
        if (not deve) and eng: fp_eng += 1
        if (not deve) and up: fp_up += 1
        veredito = "OK" if (meu == deve and eng == deve) else "*** ERRADO ***"
        print(f"{vid:<14} {str(deve):<8} {str(meu):<5} {str(eng):<9} {str(up):<9} {veredito}")
    n = len(VETORES)
    print("-"*74)
    print(f"referência py: {meu_ok}/{n} corretos   (falsos-positivos: {fp_meu})")
    print(f"pcre das regras: {eng_ok}/{n} corretos   (falsos-positivos: {fp_eng})")
    print(f"exata-A/Basic:   {up_ok}/{n} corretos   (falsos-positivos: {fp_up})")
    print()
    print(f"GANHO — gatilhos reais que pegamos e a abordagem exata-A/Basic-only PERDE ({len(lacunas)}):")
    for vid, desc in lacunas:
        print(f"  + {vid}: {desc}")
    sys.exit(0 if meu_ok == n and eng_ok == n and fp_meu == 0 and fp_eng == 0 else 1)

if __name__ == '__main__':
    main()
