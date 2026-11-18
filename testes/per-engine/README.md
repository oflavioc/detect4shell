# Per-engine regex + rule-load harness

Two tiers, kept separate so both are visible:

1. **Regex matrix** (`run.sh` -> `run.py`): every shipped regex is extracted LITERALLY from `regras/**` and run
   through 3 core runtimes, `google-re2`, `libpcre2` and `libyara`, against a vector corpus (TP/TN). It is NOT
   "the faithful engine for all 11 rule files".
2. **LOAD matrix** (`load_check.sh`): the actual shipped rule FILE is loaded by the real binary for
   **YARA** (yara-python / libyara 4.5.4), **nginx** (`nginx:1.27-alpine`, `nginx -t`, shipped file include'd in
   `http{}`) and **Suricata** (`jasonish/suricata:latest` = 8.0.8, `suricata -T -S`; asserts 0 failed and loaded == #`alert` lines).

| kind | runtime in container | notes |
|------|----------------------|-------|
| pcre | `pcre2` (libpcre2)   | lookbehind + possessive quantifiers supported |
| re2  | `google-re2`         | rejects lookbehind / possessive: a compile failure is a REAL rule bug, no fallback |
| yara | `yara-python`        | regex embedded literally in a throwaway rule |

Files: `vectors.py` (corpus; append with `add(...)`/`_adv(...)`), `engines.py` (manifest), `run.py`, `run.sh`,
`load_check.sh`, `load_yara.py`, `Dockerfile`.
Rules that demand context (`SAML...=`, `Bearer x.`, `Authorization: Basic `) get that prefix added to the token;
the YARA `$shape` gets a trailing CRLF (its required boundary byte).

Run (Git-Bash, Docker running), from `dist/detect4shell`:

    bash testes/per-engine/run.sh         # regex matrix, exit 1 on any failure
    bash testes/per-engine/load_check.sh  # LOAD matrix, exit 1 on any failure

The harness is read-only: a failing row is a finding about the rule, never fixed here.

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
