#!/usr/bin/env python3
"""
Detect4Shell — verificador PASSIVO de CANDIDATO a exposição (CVE-2026-114938).

Faz UM GET benigno, não autenticado, por endpoint de versão conhecido dos produtos
afetados, lê a versão do produto e reporta um CANDIDATO a exposição. NUNCA envia o
gatilho Base64 malformado, nunca um payload, nunca nada que possa corromper memória.

LIMITE RÍGIDO (por design, e honesto): a versão de um produto NÃO revela o build do
OpenJDK por baixo, nem se a CPU do host tem AVX-512 VBMI — os dois fatos que realmente
determinam a vulnerabilidade. Então esta ferramenta só consegue dizer "produto afetado
alcançável, confirme host-local". A confirmação é host-local (laboratorio/verificar_patch.sh
num host que você possui). Use apenas contra hosts que você está autorizado a testar. Faz 1 GET benigno por
endpoint de versão (até ~2 por produto; para na primeira resposta), nunca o payload.

Uso:  python -I verificar_exposicao.py [--insecure] https://host[:porta] [https://host2 ...]
      (TLS é verificado por padrão; --insecure só para estados de teste auto-assinados que você controla)
"""
from __future__ import annotations
import sys, ssl, json, urllib.request, urllib.error

TIMEOUT = 8
UA = "detect4shell-exposicao/1.0 (defensivo; um GET benigno)"

# produto -> lista de (caminho, como-ler-a-versao). Todos sem autenticação, benignos.
PROBES = {
    "Jenkins":      [("/login", "header:X-Jenkins")],
    "Keycloak":     [("/realms/master/.well-known/openid-configuration", "json-ish"),
                     ("/", "header:Server")],
    "Jira":         [("/rest/api/2/serverInfo", "json:version"),
                     ("/", "header:X-AREQUESTID")],  # Atlassian/Jira request-id header
    "Confluence":   [("/rest/api/content", "header:X-Confluence-Request-Time"),
                     ("/", "header:Server")],
    "Artifactory":  [("/artifactory/api/system/ping", "text"),
                     ("/", "header:Server")],
    "PingFederate": [("/pf/heartbeat.ping", "text"), ("/", "header:Server")],
}

def _make_ctx(insecure: bool):
    # TLS VERIFICADO por padrão. Use --insecure só contra estados de teste com certificado
    # auto-assinado que VOCÊ controla; nenhum dado é enviado de qualquer forma (só GET benigno).
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _get(url: str, ctx):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            body = r.read(4096).decode("utf-8", "replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), ""
    except Exception:
        return None, {}, ""


def verificar(base: str, ctx) -> dict:
    base = base.rstrip("/")
    achados = []
    for produto, probes in PROBES.items():
        for caminho, como in probes:
            status, headers, body = _get(base + caminho, ctx)
            if status is None:
                continue
            sinal = None
            if como.startswith("header:"):
                sinal = headers.get(como.split(":", 1)[1])
            elif como == "json:version":
                try: sinal = json.loads(body).get("version")
                except Exception: sinal = None
            elif como in ("text", "json-ish"):
                sinal = (body[:80].strip() or None)
            if status in (200, 401, 403) and (sinal or caminho != "/"):
                achados.append({"produto": produto, "caminho": caminho, "status": status,
                                "sinal_versao": sinal, "server": headers.get("Server")})
                break
    return {"alvo": base, "candidatos": achados}


def main(argv):
    insecure = "--insecure" in argv
    alvos = [a for a in argv[1:] if not a.startswith("-")]
    if not alvos:
        print(__doc__); return 2
    ctx = _make_ctx(insecure)
    for base in alvos:
        res = verificar(base, ctx)
        print(f"\n== {res['alvo']} ==")
        if not res["candidatos"]:
            print("  nenhum endpoint de versão de produto afetado respondeu (NÃO é um atestado de segurança)")
            continue
        for c in res["candidatos"]:
            print(f"  [CANDIDATO] {c['produto']:<12} {c['caminho']} -> {c['status']}"
                  f"  sinal_versao={c['sinal_versao']!r}  server={c['server']!r}")
        print("  >> Só CANDIDATO. Build do JDK + AVX-512 VBMI NÃO são observáveis remotamente.")
        print("  >> Confirme host-local: laboratorio/verificar_patch.sh num host que você possui.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
