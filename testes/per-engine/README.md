# Harness de regex + carga-de-regra por engine

Dois tiers, mantidos separados para que ambos fiquem visíveis:

1. **Matriz de regex** (`run.sh` -> `run.py`): cada regex enviada é extraída LITERALMENTE de `regras/**` e
   rodada em 3 runtimes centrais, `google-re2`, `libpcre2` e `libyara`, contra um corpus de vetores (TP/TN).
   NÃO é "o engine fiel dos 11 arquivos de regra".
2. **Matriz de LOAD** (`load_check.sh`): o ARQUIVO de regra enviado de fato é carregado pelo binário real do
   **YARA** (yara-python / libyara 4.5.4), do **nginx** (`nginx:1.27-alpine`, `nginx -t`, arquivo enviado
   incluído no `http{}`) e do **Suricata** (`jasonish/suricata:latest` = 8.0.8, `suricata -T -S`; verifica 0
   falhas e carregadas == nº de linhas `alert`).

| tipo | runtime no container | observações |
|------|----------------------|-------------|
| pcre | `pcre2` (libpcre2)   | lookbehind + quantificadores possessivos suportados |
| re2  | `google-re2`         | rejeita lookbehind / possessivo: falha de compilação é um bug REAL da regra, sem fallback |
| yara | `yara-python`        | regex embutida literalmente numa regra descartável |

Arquivos: `vectors.py` (corpus; acrescente com `add(...)`/`_adv(...)`), `engines.py` (manifesto), `run.py`,
`run.sh`, `load_check.sh`, `load_yara.py`, `Dockerfile`.
Regras que exigem contexto (`SAML...=`, `Bearer x.`, `Authorization: Basic `) recebem esse prefixo
adicionado ao token; o `$shape` do YARA recebe um CRLF no fim (o byte de fronteira que ele exige).

Rodar (Git-Bash, Docker ativo), a partir de `dist/detect4shell`:

    bash testes/per-engine/run.sh         # matriz de regex, exit 1 em qualquer falha
    bash testes/per-engine/load_check.sh  # matriz de LOAD, exit 1 em qualquer falha

O harness é read-only: uma linha que falha é um achado sobre a regra, nunca corrigido aqui.

## O que este harness NÃO testa (ainda)

Verde aqui NÃO significa cobertura total.

- **Replay HTTP completo** através de Suricata/ModSecurity: posicionamento de buffer, pipeline de transformações
  (`t:urlDecode`/`t:lowercase`), corpos chunked/comprimidos, limites de tamanho, `fast_pattern`/MPM (regra "morta"),
  flowbits/`chain`/cross-packet. Testamos o regex extraído + o LOAD da regra, não o tráfego completo.
- **Elastic `regexp`** é Lucene (ancorado ao campo inteiro; `\b`/`\d`/`^`/`$` não equivalem ao RE2) e é testado só
  como proxy RE2. Um teste fiel exige `org.apache.lucene.util.automaton.RegExp` num container Java.
- **Offset/span do match**: a diferença entre a fronteira consumida do RE2 e o lookbehind PCRE de largura zero não é
  comparada (irrelevante para alert/no-alert; importa para extração).
- **Versões**: a fidelidade é a do binário/versão exatos em produção; testamos contra as versões do Docker
  (google-re2 / pcre2 / yara-python 4.5.4 instalados via pip sem pin, nginx 1.27-alpine, Suricata 8.0.8 via
  `jasonish/suricata:latest`). Fixe as versões para reprodutibilidade.
- **ModSecurity**: o LOAD (parse de `SecRule`) ainda não é verificado no engine.
- **Sem LOAD in-engine** para FortiWeb, FortiGate IPS, Splunk, Sigma (conversão), AWS WAF, Cloudflare,
  FortiSIEM/FortiAnalyzer: só o regex é testado.
