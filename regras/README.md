# Detect4Shell — regras de detecção e prevenção (todos os engines)

Conjunto de regras para **detectar** (IDS/SIEM) e **prevenir** (WAF/proxy) o gatilho do Java4Shell
(CVE-2026-114938) em dispositivos expostos. Isto é o **controle compensatório** que a **CISA
recomenda** para quem ainda não corrigiu o Java ("validar a entrada Base64 no boundary da aplicação").
**Não substitui atualizar o JDK** — veja o [README](../README.md) e a [EXPLICACAO-SIMPLES](../docs/EXPLICACAO-SIMPLES.md).

## Padrões canônicos (a "forma do gatilho")

Ground truth de lab (temurin 21.0.13.0.2, padrão fixo do reprodutor): o overflow dispara com corpo
**alinhado a quads (múltiplo de 4, ≥64) + 1 OU 2 `=`** — **`A×64+"="` E `A×64+"=="`** (JDK 21/25/27;
128 no JDK 17). Sem-`=` (65/66/67/68) e corpo não-alinhado **não** disparam. ⚠️ O **disparo** da escrita
OOB é **heap-dependente** (precisa de bytes Base64 válidos logo após o buffer de decode) — reprodutível
no padrão fixo, **raro** em alocação arbitrária; por isso o crash é probabilístico (ver
[ANALISE](../docs/ANALISE.md)). A regra usa alfabeto **SPLIT** (padrão `+/` OU url-safe `_-`, nunca
misto — reduz FP em paths REST), aceita **1-2 `=`** (aceitar só um era bypassável por `==`), e `{16,}`
amplo (pega 64 e 128). O `{16,}+` é **possessivo** (anti-ReDoS); FortiWeb/FortiGate/Splunk `rex` enviam a variante **não-possessiva** `{16,}` (FortiOS pode rejeitar possessivo), detecção idêntica. Variante low-FP: `{64,}` no lugar de
`{16,}` casa só múltiplos de 64 (os strides reais do vetor AVX-512).

| Motor de regex | Padrão |
|---|---|
| **PCRE** (Suricata, ModSecurity, nginx; FortiWeb/FortiGate/Splunk `rex` usam `{16,}` não-possessivo) | `(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}+\|(?:[A-Za-z0-9_-]{4}){16,}+)={1,2}(?![A-Za-z0-9+/_=-])` |
| **RE2 / sem-lookbehind** (AWS WAF, Cloudflare, FortiAnalyzer) | `(^\|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}\|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]\|$)` |
| **+ `=` percent-encoded (`%3D`)** p/ URI/corpo brutos | `…={1,2}(?![A-Za-z0-9+/_=-])` ou o ramo `(?:={1,2}…\|%3[dD])` |

> **Evasão (regras de rede são pré-normalização):** `%3D`, `\u003d` (JSON) e `&#61;` (XML/SAML) passam no
> sensor e chegam decodificados ao `Base64.decode`. Normalize antes do match quando possível (ex.: ModSec
> `t:urlDecodeUni,t:jsDecode`). O MIME decoder **não** é vulnerável, então line-wrap MIME **não** é evasão.

> **Elastic `regexp`/`RLIKE` é Lucene** — ancorado ao termo inteiro (match no campo todo), `^`/`$` são
> **literais** e não há lookaround. Por isso usa uma forma de **fronteira OPCIONAL** distinta da RE2 acima
> (que vale para AWS WAF/Cloudflare/FortiAnalyzer, que fazem substring-search): a forma de fronteira "dura"
> casaria **zero** gatilhos no Lucene. Ver [`siem/splunk-elastic.md`](siem/splunk-elastic.md).

## Engines disponíveis

| Arquivo | Motor | Detecta | Previne | Observações |
|---|---|---|---|---|
| [`suricata/detect4shell.rules`](suricata/detect4shell.rules) | Suricata/Snort IDS | ✅ | (drop inline) | header/URI/corpo/cookie/SAML/Bearer + warm-up + crash |
| [`sigma/detect4shell.yml`](sigma/detect4shell.yml) | Sigma → SIEM | ✅ | — | converta p/ seu backend; campos `cs-*` precisam de mapeamento |
| [`modsecurity/detect4shell.conf`](modsecurity/detect4shell.conf) | ModSecurity v3 (WAF) | ✅ | ✅ (`deny`) | DETECTONLY por padrão; vire p/ `deny` após ajustar |
| [`nginx/detect4shell.conf`](nginx/detect4shell.conf) | nginx (edge) | ✅ | ✅ (403) | `map` + `if return 403` |
| [`fortiweb/detect4shell.md`](fortiweb/detect4shell.md) | **FortiWeb** (WAF) | ✅ | ✅ (alert_deny) | custom signature; CLI + GUI |
| [`fortigate-ips/detect4shell.md`](fortigate-ips/detect4shell.md) | **FortiGate IPS** | ✅ | ✅ (drop inline) | custom F-SBID; exige SSL deep-inspection p/ HTTPS |
| [`cloud-waf/aws-waf.json`](cloud-waf/aws-waf.json) | AWS WAFv2 | ✅ | ✅ (Block) | use `URL_DECODE` p/ `%3D` |
| [`cloud-waf/cloudflare.md`](cloud-waf/cloudflare.md) | Cloudflare WAF | ✅ | ✅ (Block) | expressão custom-rule |
| [`yara/detect4shell.yar`](yara/detect4shell.yar) | YARA | ✅ (arquivos) | — | crash-dump forense + payload capturado |
| [`siem/splunk-elastic.md`](siem/splunk-elastic.md) | Splunk / Elastic | ✅ | — | host (exceções/crash) + rede |
| [`siem/fortisiem-fortianalyzer.md`](siem/fortisiem-fortianalyzer.md) | **FortiSIEM / FortiAnalyzer** | ✅ | — | event handlers + rules + correlação |

> **Status de validação (honesto):** a forma foi validada em `testes/validar.py` (16/16, 0 FP no
> conjunto curado), nos **motores reais** via [`testes/per-engine/`](../testes/per-engine/) (as 43 regexes
> em google-re2 + pcre2 + yara, mais o **LOAD** das regras enviadas no engine real — YARA/nginx/Suricata),
> e com **0 FP em 107.752 strings benignas** ([`testes/fp-replay/`](../testes/fp-replay/)). O **bloqueio/alerta
> HTTP ao vivo** foi demonstrado no **nginx** (demo: bloqueia `=` **e** `==`) e agora também no **Suricata**
> (replay de PCAP) e no **ModSecurity** (403) via o tier [`testes/on-the-wire/`](../testes/on-the-wire/) — prova
> de que a regra **dispara no fio**, não só que a regex casa e o arquivo carrega. Os demais
> engines são **ports da mesma forma canônica** (regex + LOAD testados; bloqueio ao vivo não) — valide cada
> um no seu ambiente (sintaxe, buffers e ponto de inspeção variam por produto; ex.: YARA/RE2 não têm
> lookbehind, FortiOS pode rejeitar possessivo).

## Prevenir vs. detectar
- **Prevenir (bloquear na borda):** ModSecurity, nginx, FortiWeb, FortiGate IPS, AWS/Cloudflare WAF. Um token Base64
  malformado nunca é exigido por cliente correto, então bloquear costuma ser seguro — mas **comece em
  modo observação/alerta** por alguns dias e valide fluxos **auth/SAML/JWT** reais antes de negar.
- **Detectar/correlacionar:** Suricata, Sigma, Splunk/Elastic, FortiSIEM/FortiAnalyzer, YARA. O sinal de
  rede sozinho é confiança baixa/média → escale com a **rajada de aquecimento** ou um **indicador de crash**.

## Nota de evasão — `=` percent-encoded (`%3D`)
As regras de forma precisa casam o `=` **literal**. Em parâmetros de URL/corpo, o `=` pode vir
**percent-encoded** como `%3D`. Isso é tratado assim, por engine:
- **Decodificam a URL automaticamente** (então o `=` literal aparece e a regra pega): Suricata `http.uri`,
  ModSecurity `ARGS`, AWS WAF/Cloudflare **com a transformação `URL_DECODE`**.
- **Brutos (precisam da variante `%3D`)**: Suricata `http.request_body`, nginx `$args`, FortiWeb URI/corpo,
  logs crus em SIEM. Para esses, as regras já incluem o ramo `(?:=…|%3[dD])` ou um filtro URL-decode.
- **Dupla codificação (`%253D`)** derrota decodificadores de passo único — e normalmente a própria app
  também; é caso de borda. Prefira **corrigir o JDK**.

## Ordem de implantação recomendada
1. Carregue em **observação/alerta** (IDS em alert, WAF em count/log, SIEM em evento).
2. Observe **falsos-positivos** no seu tráfego por alguns dias (candidatos benignos: imagens data-URI,
   URLs pré-assinadas S3/GCS, tokens de analytics longos).
3. Ligue o **bloqueio** no WAF/proxy das apps Java expostas.
4. Em paralelo, **inventarie e corrija** o JDK (o controle definitivo).
