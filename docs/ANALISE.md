# Java4Shell (CVE-2026-114938) — análise técnica resumida

Resumo em português da mecânica, para fundamentar a detecção. Elaborado a partir de fontes
públicas (OpenJDK advisory, Oracle CPU, Calif.io, The Hacker News, Endor Labs) e do commit de
correção `5177a70b385c` (JDK-8393212). Para a análise completa original, veja a divulgação da
Calif.io e o repositório `ikow/java4shell-poc`.

## Causa raiz

O intrínseco de decodificação Base64 **AVX-512 VBMI** do HotSpot
(`StubGenerator::generate_base64_decodeBlock`, `stubGenerator_x86_64.cpp`) trata a "cauda" (1–63
bytes finais) com aritmética de tamanho que pode ficar **negativa**:

1. Entrada `"A"×64 + "="` → após o bloco de 64, resta 1 byte (o `=`).
2. `output_size = (1/4)*3 = 0`.
3. Ajuste de padding: `decrementq(output_size, 1)` → `output_size = -1` (0xFFFF…FF).
4. `bzhiq(-1, 0xFF…)` usa só `índice[7:0] = 255`. Como 255 ≥ 64 (largura do registrador), **nenhum
   bit é zerado** → máscara = toda-em-uns.
5. O `evmovdqub` mascarado escreve **os 64 bytes** do registrador ZMM.
6. Buffer de 50 bytes, escrita começa no offset 48 → offsets 48–111 → **62 bytes além do fim**.
7. A `IllegalArgumentException` é lançada **depois** da escrita — o dano já ocorreu.

## Pré-condições (todas necessárias)

| Condição | Requisito |
|---|---|
| CPU | x86-64 com `avx512f` + `avx512bw` + `avx512vbmi` + `bmi2` (Intel Ice Lake+ / AMD Zen 4+) |
| JDK | OpenJDK 17.0.6+ / 21 / 25 / 27 (antes do build `.1`). Java 8/11 padrão **não** afetados |
| JIT | o intrínseco Base64 precisa ter sido compilado pelo C2 (aquecimento ~200k decodificações) |
| Decodificador | Basic (`getDecoder()`) **ou** URL (`getUrlDecoder()`). **MIME não** é afetado |
| Entrada | Base64 malformado terminando em `=`, cauda 1–3 bytes além de um limite de bloco |

Gatilho por versão: **JDK 17** → `"A"×128 + "="`; **JDK 21/25/27** → `"A"×64 + "="` (os bytes não
precisam ser `A` — qualquer Base64 do alfabeto serve).

## Impacto (o que é demonstrado vs. alegado)

- **Demonstrado publicamente (independente):** crash da JVM (**DoS**) e vazamento **local** de heap
  ("JavaBleed", ex. Blackpoint 30/30 em teste local).
- **Alegado e retido (Calif.io), não reproduzido de forma independente:** RCE pré-auth via cadeia de
  grooming de heap → corromper campo de tamanho de array vizinho (primitiva de escrita) → corromper
  um segundo array (primitiva de leitura) → disclosure/execução. Oracle/Amazon tratam o code-exec
  como difícil e, no caso da Amazon, para **usuário autenticado de baixo privilégio em certos
  ambientes**. Não está no catálogo CISA KEV (em 2026-11-18).

## Correção

Commit `5177a70b385c` (JDK-8393212): guarda de 3 linhas que desvia caudas curtas (< 4 bytes) para o
decodificador escalar correto:

```
__ BIND(L_finalBit);
+   __ cmpl(length, 4);
+   __ jcc(Assembler::less, L_bruteForce);
```

Builds corrigidos: 17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1 (Oracle); Corretto `.1.2`; Zulu `*.201`.
Red Hat / Temurin / Microsoft / Liberica estavam sem correção em 2026-11-18.

## Produtos em risco (sinks pré-auth que decodificam Base64)

Sem autenticação por padrão: **Keycloak, Jira, Confluence, JFrog Artifactory, Jenkins, PingFederate**.
Com autenticação: Kafka, Solr, Elasticsearch, Gerrit, Spinnaker. Também há uma variante cliente-TLS
(programa Java que conecta a servidor malicioso). A exposição é de **runtime + CPU**, não de classpath
— por isso scanners de dependência e SAST não enxergam.
