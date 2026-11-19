# Changelog

Mudanças notáveis do Detect4Shell. Formato baseado em
[Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/); versionamento
[SemVer](https://semver.org/lang/pt-BR/).

## [1.0.0] — 2026-11-19

Primeiro release público. Kit defensivo completo para o Java4Shell (CVE-2026-114938).

### Adicionado

- **Detecção multi-engine (11):** Suricata/Snort, Sigma, ModSecurity v3, nginx, FortiWeb, FortiGate IPS,
  AWS WAFv2, Cloudflare WAF, YARA, Splunk/Elastic e FortiSIEM/FortiAnalyzer — todas derivadas de uma
  **forma canônica** validada (alfabeto split `+/` ou url-safe `_-`, `={1,2}`, sinks pré-auth
  Basic/Bearer/SAML/cookie/param), com o ramo `%3D` para buffers brutos.
- **Mitigação na aplicação:** Servlet Filter (`jakarta`/`javax`) que fecha a evasão `%3D` e inspeciona
  header, parâmetros, cookie e **segmentos de path**, com um harness auto-contido de 13 cenários.
- **Scanner passivo** de exposição (1 GET benigno por endpoint) e **honeypot** sensor→mock inerte.
- **Lab confinado** (`laboratorio/`): reprodutor offline (`--network none`), `verificar_patch.sh` e a
  matriz CPU×JDK (17/21/25 × VBMI/sem-VBMI × flags/patch).
- **Demo ataque-vs-defesa ao vivo:** alvo Java vulnerável + edge nginx, o **Console de Ataque** visual
  (classifica cada rajada em 4 estados) e um **walkthrough FortiWeb** real (Alert→Alert & Deny, bloqueio
  403 na borda, isolamento por clone de Signature Policy com o policy público intocado).
- **Gate de regressão de 7 tiers** (`test.sh` + CI, bloqueante): unit FN/FP; drift-guard da regex
  canônica (10 locais, incl. o oráculo do tier 1); harness do Servlet Filter; matriz por engine em
  re2/pcre2/yara reais; LOAD in-engine (YARA/nginx/Suricata); fp-replay (0 FP em 107.752 strings
  benignas); e **replay on-the-wire** (PCAP no Suricata + ModSecurity ao vivo). Dependências e imagens
  Docker fixadas por versão/digest.
- **Documentação** em PT-BR, do leigo ([`docs/EXPLICACAO-SIMPLES.md`](docs/EXPLICACAO-SIMPLES.md),
  [`docs/FAQ.md`](docs/FAQ.md)) ao técnico ([`docs/ANALISE.md`](docs/ANALISE.md),
  [`docs/FORTINET-FABRIC.md`](docs/FORTINET-FABRIC.md)), com **disciplina de honestidade** (taxonomia de
  impacto em 3 níveis; sem overclaim de RCE; "banner ≠ match de regra ≠ bug").

[1.0.0]: https://github.com/oflavioc/detect4shell/releases/tag/v1.0.0
