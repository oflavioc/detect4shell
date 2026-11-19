# Demo AWS WAFv2 — bloqueio do Java4Shell na borda da nuvem (CVE-2026-114938)

A mesma história do [demo nginx](../README.md), do [FortiWeb](../fortiweb/README.md) e do [FortiGate IPS](../fortigate/README.md), agora na **borda da nuvem**: um **AWS WAFv2 real**, em frente a um **API Gateway real**, barrando a *forma* do gatilho Java4Shell — com a **managed rule do próprio repo** ([`../../regras/cloud-waf/aws-waf.json`](../../regras/cloud-waf/aws-waf.json)).

> ⚠️ **Teste ao vivo e EFÊMERO em conta AWS real.** Tudo rodou em `us-east-1`: um **WebACL WAFv2 REGIONAL** em frente a um **API Gateway REGIONAL** com integração **MOCK** (sem Java por trás) — **criado e destruído no mesmo run** (`TEARDOWN: removido`). Não é um exploit: o "payload" é a string Base64 malformada já **pública** (`A×64 + "="`), aqui só como header/query HTTP para o WAF **ver a forma**. A conta **não fica com recursos**.

## O que você vai ver

Uma prova **honestamente rotulada**: a managed rule do repo bloqueia o gatilho num **AWS WAFv2 real** — **benigno → HTTP 200**, **gatilho no header → 403**, **gatilho na query → 403**.

> **O que isso prova — e o que NÃO prova.** O **403** prova que o WAF barra a **forma** do gatilho (≥16 "quads" Base64 + `=`/`==` na fronteira) **antes** de chegar em qualquer backend. **Não** prova que o host atrás era explorável; não bloquear não provaria que era seguro. O alvo foi um **API Gateway MOCK** (sem app Java) — validamos a **regra do WAF**, não "protegemos uma app Java real".

```
RESUMO (medido ao vivo — AWS WAFv2 REGIONAL, us-east-1)
  benigno        -> HTTP 200
  gatilho header -> HTTP 403   (regra SingleHeader "authorization", transform NONE)
  gatilho query  -> HTTP 403   (regra QueryString, transform URL_DECODE)
```

## Pré-requisitos

- **Conta AWS** + **AWS CLI** (ou **CloudShell**, que já vem autenticado).
- ⚠️ **Escopo certo:** WAFv2 **REGIONAL** (`--scope REGIONAL`) associa a **API Gateway REGIONAL / ALB / AppSync** — **não** a um API GW *edge-optimized* (senão dá `WAFUnavailableEntityException`). Para **CloudFront**, use `--scope CLOUDFRONT` em `us-east-1`.
- A **managed rule do repo** ([`../../regras/cloud-waf/aws-waf.json`](../../regras/cloud-waf/aws-waf.json)): um `OrStatement` com 3 `RegexMatchStatement` — **SingleHeader `authorization`** (transform `NONE`) + **QueryString** (`URL_DECODE`) + **Body** (`URL_DECODE`).

## Passo a passo

> Os dois prints abaixo são **capturas reais do run** (AWS CloudShell, `us-east-1`), em [`img/`](img/).

### P1 — A regra (forma RE2 de fronteira)

O AWS WAF usa **RE2** (sem lookbehind/lookahead) → a regex canônica (header/PCRE) vira a **forma de fronteira**:

```
(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)
```

*Por que casa só a forma do gatilho (e não Base64 legítimo):* um corpo Base64 válido **pré-padding** tem sempre comprimento `4n-1` ou `4n-2` (**nunca** múltiplo de 4), então um run **quad-alinhado** (`{4}`×`{16,}`) imediatamente antes do `=` **exclui** Base64 válido — é o argumento anti-falso-positivo. As transforms importam: **header = `NONE`**; **query/body = `URL_DECODE`** (para pegar o `=` codificado como `%3D`). A regra completa (3 `RegexMatchStatement` no `OrStatement`, `Action: Block`) está em [`../../regras/cloud-waf/aws-waf.json`](../../regras/cloud-waf/aws-waf.json).

### P2 — Deploy: alvo REGIONAL + WebACL + associar

Suba um alvo **REGIONAL** (aqui, um API Gateway com integração **MOCK** — nenhum backend real), crie o WebACL com as regras de regex (`Action: Block`, `DefaultAction: Allow`) e **associe**:

```bash
# alvo REGIONAL (edge-optimized NÃO funciona com WAFv2 regional)
aws apigateway create-rest-api --name d4s-test --endpoint-configuration types=REGIONAL
# ... método GET + integração MOCK + deploy no stage "test" ...

# WebACL com as regras do repo (ver aws-waf.json), bloqueando a forma do gatilho
aws wafv2 create-web-acl --scope REGIONAL --region us-east-1 \
  --name Detect4Shell-test --default-action Allow={} \
  --visibility-config SampledRequestsEnabled=true,CloudWatchMetricsEnabled=true,MetricName=d4s \
  --rules file://rules.json   # as RegexMatchStatement de aws-waf.json, Action=Block

aws wafv2 associate-web-acl --web-acl-arn <ARN> \
  --resource-arn "arn:aws:apigateway:us-east-1::/restapis/<id>/stages/test"
```

### P3 — A pegadinha: eventual consistency + propagação

`associate-web-acl` tem **eventual consistency** — o stage demora a *reportar* o WAF (daí o loop "associa + confirma": tent 1→4). E depois a regra ainda leva **~60s para propagar** no WAF. Antes disso o gatilho passa (**200**); depois, bloqueia (**403**):

![AWS CloudShell: poll do gatilho no header a cada ~12s retornando 200/200/200/200 e no ~60s HTTP 403 — a regra propaga e passa a bloquear](img/aws-waf-poll-block.png)
*Prova (poll): o header volta `200 / 200 / 200 / 200` e **no ~60s → 403** — a regra propaga e passa a **bloquear**. (Neste run a amostra final da *query* ainda deu `200` por ter sido medida cedo demais — foi exatamente o que motivou esperar `90s` de propagação completa antes do teste final.)*

### P4 — Teste final: 200 / 403 / 403

Depois da propagação completa, 3 requests — um benigno, um com o gatilho no **header**, um com o gatilho na **query** (`A×64+"="`):

```bash
curl -s -o /dev/null -w "%{http_code}\n" "https://<id>.execute-api.us-east-1.amazonaws.com/test"                 # benigno   -> 200
curl -s -o /dev/null -w "%{http_code}\n" "https://<id>.execute-api.us-east-1.amazonaws.com/test" \
     -H "Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="             # header    -> 403
curl -s -o /dev/null -w "%{http_code}\n" "https://<id>.execute-api.us-east-1.amazonaws.com/test?x=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"   # query -> 403
```

![AWS CloudShell: run completo do script — API GW REGIONAL criado, WebACL, associa+confirma (4 tentativas), propaga 90s, teste final benigno 200 / gatilho header 403 / gatilho query 403, TEARDOWN removido](img/aws-waf-200-403-403.png)
*Prova: **benigno → 200**, **gatilho header → 403**, **gatilho query → 403** — a managed rule do repo **bloqueia** o gatilho num **AWS WAFv2 real** em frente a um **API Gateway real**, e o tráfego legítimo passa. O `URL_DECODE` na regra de query pega o `=` codificado como `%3D`.*

### P5 — Teardown (efêmero)

Tudo foi criado **e removido** no mesmo run (WebACL, associação, API Gateway) — a conta **não fica com recursos** (`== TEARDOWN == removido.`). Um `trap cleanup EXIT` garante a limpeza mesmo se um passo falhar.

## Três fatos honestos sobre este demo

- **403 = bloqueio da FORMA na borda ≠ bug.** O 403 prova que o WAF barra a **forma** do gatilho antes de qualquer backend. **Não** prova explorabilidade; **não** bloquear não provaria segurança. O alvo foi um API Gateway **MOCK** (sem Java) — validamos a **regra**, não "uma app Java protegida de ponta a ponta".
- **O `URL_DECODE` é o que fecha o encoding.** A regra de query/body **decodifica antes de casar** → pega o `=` como `%3D`/`%3d`. O header usa `NONE` (não vem URL-encoded). É o boundary de encoding, não um "match de assinatura mágico".
- **É controle COMPENSATÓRIO.** WAF na borda **não substitui** atualizar o JDK para o build `.1` (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1). E quem é vulnerável é decidido pelo **hardware** (x86-64 AVX-512 VBMI + OpenJDK não corrigido) — o WAF bloquear ou não não muda isso.

## Como isso vira produção

1. **Comece em `Count`** (não `Block`) — deixe a regra em Count alguns dias observando fluxos reais de **auth/SAML/JWT**; só então vire `Block`.
2. **Associe a WebACL** ao seu **API Gateway REGIONAL / ALB / AppSync** real (ou `--scope CLOUDFRONT` para CloudFront).
3. A **managed rule** está pronta em [`../../regras/cloud-waf/aws-waf.json`](../../regras/cloud-waf/aws-waf.json) — importável via `create-web-acl --rules file://…`. O equivalente Cloudflare (mesma forma RE2) está em [`../../regras/cloud-waf/cloudflare.md`](../../regras/cloud-waf/cloudflare.md).
4. **Compensatório** — corrija o JDK de qualquer forma.
