# Detect4Shell — FortiSIEM & FortiAnalyzer (Java4Shell / CVE-2026-114938)

Detecção/correlação no ecossistema Fortinet. O fluxo natural: **FortiWeb** barra/alerta na borda
(veja `regras/fortiweb/`) e encaminha os logs para **FortiAnalyzer** e/ou **FortiSIEM**, que
**detectam, correlacionam e reportam**.

> Nomes de atributos/campos variam por versão e por parser — ajuste ao seu ambiente. Rode primeiro
> em modo observação; o sinal de rede sozinho é confiança baixa/média, escale com crash/host.

---

## FortiAnalyzer

### A) Event Handler sobre o hit da custom signature do FortiWeb (mais simples e confiável)
Quando a custom signature `D4S-Java4Shell-Base64` dispara no FortiWeb, o log chega ao FAZ. Crie um
**Event Handler** (Incidents & Events → Handlers) com filtro:

```
# Log filter (FortiWeb / attack logs)
(type=="attack" or subtype=="waf") and (msg contain "Java4Shell" or signature contain "D4S-Java4Shell-Base64")
```
Ação: gerar evento **High**, notificar. Opcional: `group by srcip` com limiar (ex.: > 5 em 10 min).

### B) Event Handler independente do FortiWeb (forma do gatilho na URL/corpo)
Se você tiver o `http_url` / request nos logs (proxy, FortiGate UTM, FortiWeb traffic log):
```
(http_url =~ "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)")
```
> O motor de regex do filtro FAZ (Lucene-like) não tem lookbehind → usamos fronteira à direita
> (levemente mais amplo; ok para detecção).

### C) Dataset / Report (tendência e top-ofensores)
```sql
select count(*) as hits, srcip, http_url
from $log
where (msg like '%Java4Shell%' or signature like '%D4S-Java4Shell%')
group by srcip, http_url
order by hits desc
```
Agende como relatório diário durante a janela de resposta.

---

## FortiSIEM

### Rule 1 — Forma do gatilho na rede (FortiWeb/proxy)
**SubPattern** `J4S_Net`:
- **Filter:** `(eventType CONTAIN "WAF" OR eventType CONTAIN "HTTP") AND (httpUrl REGEXP "(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)" OR rawEventMsg REGEXP "Authorization: Basic (?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)")`
- **Group By:** `srcIpAddr` · **Aggregate:** `COUNT(*) >= 1`
- **Incident:** "Java4Shell malformed-Base64 trigger seen (CVE-2026-114938)", severity High.

### Rule 2 — Rajada de aquecimento JIT (correlação de volume)
**SubPattern** `J4S_Warmup`:
- **Filter:** `rawEventMsg CONTAIN "Authorization: Basic"`
- **Group By:** `srcIpAddr` · **Aggregate:** `COUNT(*) > 1000` numa janela de 60s.
- Encadeie com Rule 1 (mesma origem) para elevar a confiança.

### Rule 3 — Crash / corrupção na JVM (host)
**SubPattern** `J4S_Crash` (eventos de app/host, ex.: via FortiSIEM agent / syslog):
- **Filter:** `(rawEventMsg CONTAIN "SIGSEGV" AND (rawEventMsg CONTAIN "_base64_decodeBlock" OR rawEventMsg CONTAIN "StubRoutines")) OR rawEventMsg CONTAIN "hs_err_pid"`
- **Aggregate:** `COUNT(*) >= 1` por `hostName`.
- **Incident:** severity High — possível DoS/exploração; verifique patch + CPU do host.

### Rule 4 — Exceções repetidas do decodificador Base64 (host, sinal precoce)
**SubPattern** `J4S_Base64Exc`:
- **Filter:** `rawEventMsg CONTAIN "java.util.Base64" AND rawEventMsg CONTAIN "IllegalArgumentException"`
- **Group By:** `hostName` · **Aggregate:** `COUNT(*) > 10` em 5 min.

### Correlação recomendada
Incidente de **alta** confiança = `J4S_Net` (ou `J4S_Warmup`) **seguido de** `J4S_Crash` **ou**
`J4S_Base64Exc` no destino. Enriquecer com CMDB: marcar hosts que rodam **OpenJDK 17.0.6+/21/25/27**
em **CPU x86-64 com AVX-512 VBMI** como os de maior risco.

---

## Lembrete (do lab)
Crash **não** é o único sinal e a **ausência de crash não prova segurança** (em JDK 21.0.13 + G1 a
corrupção ocorreu sem crash). Priorize a detecção pela **forma da requisição** (rede) + exceções de
Base64 (host), e confirme o **build/patch do JDK no próprio host** — nenhuma regra de rede/SIEM
substitui atualizar o Java.
