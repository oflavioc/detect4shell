# Detect4Shell — consultas SIEM (Splunk + Elastic) para Java4Shell (CVE-2026-114938)

Consultas de **detecção** para logs de **host** (o sinal mais confiável) e de **rede** (proxy/WAF).
Ajuste os nomes de índice/campo ao seu ambiente.

> Lembrete do lab: **crash não é o único sinal e a ausência de crash não prova segurança** —
> em JDK 21.0.13 + G1 a corrupção ocorreu **sem** crash em testes. Priorize a detecção pela
> **forma da requisição** (rede) somada às exceções de Base64 (host).

## Splunk

**1) Host — rajada de exceções do decodificador Base64 (forte indício de tentativas):**
```
index=app_java ("java.util.Base64" AND "IllegalArgumentException")
| bin _time span=5m
| stats count by _time, host
| where count > 10
```

**2) Host — crash da JVM no stub de Base64 / GC (possível exploração / DoS):**
```
index=os (source="*hs_err_pid*" OR ("SIGSEGV" AND ("StubRoutines" OR "_base64_decodeBlock" OR "G1ParScanThreadState")))
| stats count by host, source
```

**3) Rede — forma do gatilho em Authorization/URI (proxy/WAF logs; rex é PCRE):**
```
index=proxy
| rex field=_raw "(?<j4s>(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-]))"
| where isnotnull(j4s)
| stats count values(uri_path) as paths by src_ip, http_user_agent
```
> O `rex` do Splunk é **PCRE de verdade** (com lookbehind/lookahead), então a forma canônica com
> `(?<!…)`/`(?!…)` roda aqui sem adaptação — é o mesmo padrão validado no motor fiel (pcre2).

**4) Rede — correlação de aquecimento (muitos Basic auth da mesma origem em pouco tempo):**
```
index=proxy authorization="Basic *"
| bin _time span=1m | stats count by _time, src_ip | where count > 1000
```

## Elastic (ES|QL / Query DSL)

**1) Host — exceções repetidas de Base64 (ES|QL):**
```
FROM logs-java-*
| WHERE message LIKE "*java.util.Base64*" AND message LIKE "*IllegalArgumentException*"
| STATS c = COUNT(*) BY host.name, bucket = BUCKET(@timestamp, 5 minute)
| WHERE c > 10
```

**2) Host — crash no stub de Base64 (Query DSL):**
```json
{ "query": { "bool": { "must": [
  { "match_phrase": { "message": "SIGSEGV" } },
  { "bool": { "should": [
    { "match_phrase": { "message": "_base64_decodeBlock" } },
    { "match_phrase": { "message": "StubRoutines" } },
    { "match_phrase": { "message": "G1ParScanThreadState" } }
  ], "minimum_should_match": 1 } } ] } } }
```

**3) Rede — forma do gatilho via `regexp` (Query DSL; aplique ao campo do header/uri):**
```json
{ "query": { "regexp": {
  "http.request.headers.authorization": "(.*[^A-Za-z0-9+/_=-])?((?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-].*)?"
} } }
```
> **Por que ESTA forma — e por que a antiga estava silenciosamente MORTA.**
> O `regexp` do Elasticsearch roda no **Lucene**, um autômato **ancorado ao termo inteiro** (fullmatch
> implícito): a regex tem de casar o **valor inteiro** do campo, e `^`/`$` são **caracteres literais**,
> não âncoras — e não existe lookbehind/lookahead. Por isso as fronteiras aqui ficam **opcionais nas
> pontas**: `(.*[^base64])?` come o que vier antes e termina num char **não-base64** (ou casa vazio, se o
> token já começa no início do campo — tipo `AAAA…A=`); `([^base64].*)?` faz o mesmo à direita. O miolo
> `((?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}` é a **run quad-alinhada** (≥16 quads = ≥64
> chars, de **um** alfabeto puro: `+/` **ou** `_-`, nunca misto) colada no `=`. É isso que separa o gatilho
> do Base64 válido: Base64 bem-formado tem `len % 4 == 0`, então **nunca** termina quad-alinhado
> imediatamente antes do `=`.
>
> ⚠️ **A forma anterior casava ZERO gatilhos no cluster.** A versão antiga
> `(^|[^A-Za-z0-9+/_-])…={1,2}([^A-Za-z0-9+/_=-]|$)` foi escrita pensando em RE2/PCRE, onde `^`/`$` são
> âncoras. No Lucene o `^` vira **literal**: a alternativa `(^|[^base64])` passa a exigir que o **1º char
> do campo** seja um `^` literal **ou** um char não-base64 — mas todo gatilho real (`Basic AAAA…=`,
> `token=AAAA…=`) começa com char base64. Logo, **nenhum** gatilho casava. E o *workaround* de "envolver
> com `.*` dos dois lados" (`".*…={1,2}.*"`) derruba as **duas** fronteiras e **volta a dar FP** em Base64
> longo válido. Medido por emulação Lucene (`re.fullmatch`, com `^`/`$` tratados como literais) sobre os
> **36 vetores** de `testes/per-engine/vectors.py`: **forma nova = 15/15 gatilhos, 0/21 FP**; **forma
> antiga = 0/15 gatilhos**; *workaround* `.*….*` = 15/15 mas **9 FP** (casa `data-uri`, Base64 válido com
> 1 ou 2 `=`, etc.).
>
> **Limites honestos — o Lucene NÃO decodifica.** O `regexp` casa o **byte literal** do campo indexado: se
> o `=` chegou como `%3D` (URL-encode), `&#61;` (entidade HTML) ou escapado dentro de um JSON, **não
> casa** — isso é esperado, não é bug da regex. Normalize no **ingest** (Grok/dissect + `url_decode`) e
> aplique o `regexp` ao campo já decodificado. Indexe o campo como `keyword`/`wildcard` (o `regexp` **não**
> roda em `text` tokenizado). E **valide no seu próprio cluster** antes de confiar: versão de Lucene e
> mapeamento do campo mudam o resultado.

**3b) Mesma detecção em ES|QL (`RLIKE` — também ancora no valor inteiro):**
```
FROM logs-proxy-*
| WHERE http.request.headers.authorization RLIKE "(.*[^A-Za-z0-9+/_=-])?((?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-].*)?"
| STATS c = COUNT(*) BY source.ip, user_agent.original
```
> `RLIKE` usa a **mesma** sintaxe Lucene e **a mesma** semântica fullmatch, então a forma é idêntica e os
> limites de decode são os mesmos. Se precisar casar tokens que chegam codificados (`%3D`, `&#61;`),
> extraia/decodifique num **pipeline de ingest** e rode o `regexp`/`RLIKE` no campo derivado — tentar
> "decodificar dentro da regex" não é possível no Lucene.

## O que fazer com os hits
- Sinal de rede **sozinho** = confiança baixa/média → correlacione com (2) crash ou (1) rajada de exceções.
  A **forma** casada prova só que alguém mandou um Base64 malformado longo quad-alinhado terminado em `=`,
  **não** que houve exploração.
- Qualquer hit em **(2)** num host afetado = investigue como possível DoS/exploração; cheque patch + CPU.
- O **disparo** em si é **heap-dependente e probabilístico** (depende de layout de GC/heap no momento) —
  a mesma requisição pode corromper memória num processo e não em outro. Trate a detecção como *tentativa*,
  não como *compromisso confirmado*.
- Nenhum destes **prova** compromisso nem **limpa** o host — e **nada substitui corrigir o JDK**: confirme
  o build/patch no próprio host (ver `laboratorio/verificar_patch.sh` / `scanner/verificar_exposicao.py`).
