# Detect4Shell — Cloudflare WAF (Java4Shell / CVE-2026-114938)

Regra de WAF customizada para **detectar e prevenir** na borda. Cloudflare usa regex RE2
(sem lookbehind), então ancoramos com classes de fronteira. Cloudflare decodifica URL-encoding
nos campos de URI automaticamente na maioria dos casos; para corpo, use a inspeção de body.

## Expressão da regra (cole em Security → WAF → Custom rules)

```
(any(http.request.headers["authorization"][*] matches "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)"))
or (http.request.uri.query matches "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)")
or (any(http.request.cookies[*] matches "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)"))
```

## Ação
- **Comece em `Log`** por alguns dias (observe falsos-positivos no seu tráfego).
- Depois troque para **`Block`** (ou `Managed Challenge` se preferir não bloquear duro).

## Notas
- A forma `{64,}` é levemente mais ampla que as regras Suricata/ModSec (que exigem alinhamento a
  quads); para **bloqueio na borda** isso é seguro — nenhum cliente correto envia Base64 malformado.
- Para inspecionar o **corpo** (ex.: `SAMLResponse` em POST), habilite a inspeção de payload e
  adicione uma condição com `http.request.body.raw matches "..."`.
- Isto detecta a **forma do ataque na rede**. Não substitui **corrigir o Java** — é controle
  compensatório (exatamente o que a CISA recomenda para quem ainda não corrigiu).
