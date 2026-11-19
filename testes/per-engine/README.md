# Harness de regex + carga-de-regra por engine

Dois tiers, mantidos separados para que ambos fiquem visíveis:

1. **Matriz de regex** (`run.sh` -> `run.py`): cada regex enviada é extraída LITERALMENTE de `regras/**` e
   rodada em 3 runtimes centrais, `google-re2`, `libpcre2` e `libyara`, contra um corpus de vetores (TP/TN).
   NÃO é "o engine fiel dos 11 arquivos de regra".
2. **Matriz de LOAD** (`load_check.sh`): o ARQUIVO de regra enviado de fato é carregado pelo binário real do
   **YARA** (yara-python / libyara 4.5.4), do **nginx** (`nginx:1.27-alpine`, `nginx -t`, arquivo enviado
   incluído no `http{}`) e do **Suricata** (`jasonish/suricata:8.0.8`, `suricata -T -S`; verifica 0
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

- **Replay HTTP ao vivo** através de Suricata/ModSecurity: **agora coberto em parte** pelo tier
  [`testes/on-the-wire/`](../on-the-wire/) — PCAP no Suricata + requisição HTTP no ModSecurity provam que a
  regra **dispara no fio** (não só que a regex casa e o arquivo carrega). Ainda **não** cobertos lá: corpos
  chunked/comprimidos, limites de tamanho, `fast_pattern`/MPM em toda posição, flowbits/`chain`/cross-packet.
- **Elastic `regexp`** é Lucene (ancorado ao campo inteiro; `^`/`$` são **literais**, sem lookaround). O harness
  agora o casa com **`.fullmatch`** (não `.search`), fiel à ancoragem de termo-inteiro do Lucene — fecha a
  lacuna de fidelidade principal (substring-vs-fullmatch). Um teste 100% fiel ainda exigiria
  `org.apache.lucene.util.automaton.RegExp` num container Java, mas o resultado match/no-match bate.
- **Offset/span do match**: a diferença entre a fronteira consumida do RE2 e o lookbehind PCRE de largura zero não é
  comparada (irrelevante para alert/no-alert; importa para extração).
- **Versões**: a fidelidade é a do binário/versão exatos em produção; testamos contra as versões do Docker,
  **agora fixadas (`==`)** no Dockerfile/scripts (google-re2, pcre2, yara-python 4.5.4; nginx 1.27-alpine) e com
  a imagem Suricata pinada (`jasonish/suricata:8.0.8`) — gate reprodutível.
- **ModSecurity**: o parse de `SecRule` agora é exercido **ao vivo** no tier `on-the-wire` (o container ModSec
  carrega as regras enviadas e bloqueia/loga); um LOAD estático isolado do ModSec ainda não existe.
- **Sem LOAD in-engine** para FortiWeb, FortiGate IPS, Splunk, Sigma (conversão), AWS WAF, Cloudflare,
  FortiSIEM/FortiAnalyzer: só o regex é testado.
