# Detect4Shell — Fortinet FortiWeb (Java4Shell / CVE-2026-114938)

Custom Signature para **detectar e prevenir** o gatilho Base64-malformado na borda, via FortiWeb.
FortiWeb usa um motor regex compatível com PCRE (lookbehind de tamanho fixo costuma ser suportado).
Se a sua versão rejeitar o lookbehind, use a **forma de fallback RE2** indicada abaixo.

> Nomes de `target` variam entre versões do FortiWeb — ajuste conforme o seu build (os abaixo
> são os comuns). Comece a ação em **`alert`** por alguns dias; depois troque para **`alert_deny`**.

> 🎬 **Walkthrough ao vivo (ataque vs. defesa nesta stack):**
> [`../../demo/fortiweb/README.md`](../../demo/fortiweb/README.md) — esta Custom Signature criada na
> GUI de um FortiWeb-VM 8.0.8 (isolada só no virtual server de teste), com o Console de Ataque
> provando o primitivo no alvo Java local e o `403` de bloqueio na borda.

## Expressões (regex)

**Precisa (PCRE com lookbehind)** — header / cookie (campos não URL-encoded):
```
(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-])
```

**URI / corpo (trata também o `=` percent-encoded `%3D`)**:
```
(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})(?:={1,2}(?![A-Za-z0-9+/_=-])|%3[dD])
```

**Fallback RE2 (se o lookbehind não for aceito)** — ancora com classe de fronteira:
```
(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)
```

## Via CLI (custom-protection-rule)

```
config waf custom-protection-rule
    edit "D4S_Java4Shell_Base64"
        set action alert          # troque para alert_deny após ajustar
        set severity High
        set case-sensitivity enable
        config rule
            edit 1
                set target REQUEST_HEADER
                set header-name-type specify
                set header-name "Authorization"
                set type regular-expression
                set expression "(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-])"
            next
            edit 2
                set target REQUEST_URI
                set type regular-expression
                set expression "(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})(?:={1,2}(?![A-Za-z0-9+/_=-])|%3[dD])"
            next
            edit 3
                set target REQUEST_COOKIE
                set type regular-expression
                set expression "(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-])"
            next
            edit 4
                set target REQUEST_BODY
                set type regular-expression
                set expression "(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})(?:={1,2}(?![A-Za-z0-9+/_=-])|%3[dD])"
            next
        end
    next
end
```

Agrupe e aplique no perfil de proteção:
```
config waf custom-protection-group
    edit "D4S_Java4Shell"
        set custom-protection-rule "D4S_Java4Shell_Base64"
    next
end
# depois: referencie o grupo no Web Protection Profile usado pela(s) policy(ies) da app Java exposta.
```

## Via GUI
1. **Web Protection → Custom Signature → Custom Signature Group**: crie um grupo `D4S_Java4Shell`.
2. Adicione uma **Signature**: Direction = **Request**, Case Sensitive = **Yes**.
3. Adicione um **Target** por campo (HTTP Header `Authorization`, Request URI, Cookie, Request Body)
   com **Expression Type = Regular Expression** e cole a regex correspondente acima.
4. **Action** inicial = **Alert** (só registra). Após validar, mude para **Alert & Deny**. Severity = High.
5. Associe o grupo ao **Web Protection Profile** das policies que publicam suas apps Java expostas
   (Jira, Confluence, Jenkins, Keycloak, Artifactory, apps Spring Boot…).

## Notas
- Isto detecta/bloqueia a **forma do ataque na rede** — é controle **compensatório** (o que a CISA
  recomenda para quem ainda não corrigiu). **Não substitui atualizar o Java** para o build `.1`.
- Um token Base64 malformado não é exigido por cliente correto → bloquear costuma ser seguro; ainda
  assim, rode em **Alert** primeiro e observe fluxos de **auth/SAML/JWT** reais antes de negar.
- FortiWeb também tem assinaturas e ML próprios; esta custom signature cobre o gatilho específico do
  Java4Shell que assinaturas genéricas podem não pegar (SAML/JWT/cookie/url-safe).
