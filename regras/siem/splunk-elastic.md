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

**3) Rede — forma do gatilho via regexp (Query DSL; aplique ao campo do header/uri):**
```json
{ "query": { "regexp": {
  "http.request.headers.authorization": "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)"
} } }
```
> `regexp` do Elasticsearch (Lucene) não suporta lookbehind — usamos a classe de fronteira à direita;
> é levemente mais amplo (aceitável para detecção). Habilite o campo como `keyword`/`wildcard`.
> ⚠️ **Semântica Lucene (importante):** o `regexp` do Lucene ancora no **termo inteiro** e trata `^`/`$`
> como **literais** (não âncoras como no RE2, o motor onde validamos as 43 regexes), então um token no
> **fim** do valor pode **não** casar as fronteiras acima. Para Lucene, envolva a forma com `.*` dos dois
> lados — `".*(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}.*"` — e **valide no seu cluster**.

## O que fazer com os hits
- Sinal de rede **sozinho** = confiança baixa/média → correlacione com (2) crash ou (1) rajada de exceções.
- Qualquer hit em **(2)** num host afetado = investigue como possível DoS/exploração; cheque patch + CPU.
- Nenhum destes **prova** compromisso nem **limpa** o host — confirme o build/patch do JDK no próprio host.
