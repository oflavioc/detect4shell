# FP-replay — taxa de falsos-positivos de PRODUÇÃO

O `validar.py` prova **0 FP em 18 vetores curados** — um teste unitário, não uma taxa de produção. Isto
mede a FP contra um corpus **grande de Base64 benigno REAL**.

## Resultado (2026-11-18, seed 1337)

```
Corpus benigno: 107.752 strings em 10 categorias
  base64 válido std (random 1–400 bytes) .... 40.000 → 0 FP
  base64 válido url-safe ..................... 40.000 → 0 FP
  JWTs (base64url, 3 segmentos, sem pad) ......  5.000 → 0 FP
  data: URIs .................................  3.000 → 0 FP
  presigned URLs (S3 X-Amz-Signature) ........  3.000 → 0 FP
  hex · UUID · REST-path · analytics .........  3.000 cada → 0 FP
  paths web reais (SecLists common.txt) ......  4.752 → 0 FP
  ───────────────────────────────────────────────────────────
  TOTAL  PCRE = 0/107.752 (0.0000%)   RE2 = 0/107.752 (0.0000%)
```

**Nenhum falso-positivo**, nos dois motores (pcre2 e google-re2). ⚠️ Com 0 FP em N observações, o limite
superior ~95% é **≈ 3/N** (a "regra de 3"), não zero: aqui ≈ **3/107.752 ≈ 0,0028%**. É "**zero FP
observado**", não "0% garantido".

## Por que 0 FP (a aritmética, agora confirmada em escala)
Base64 **válido** de padding simples tem comprimento total `4n`, logo o run de dados antes do `=` tem
`4n−1` chars — **nunca** múltiplo de 4. A regra exige um run **alinhado a quad** (`(?:[...]{4}){16,}`)
terminando exatamente antes de 1–2 `=`, numa fronteira. Base64 válido não satisfaz isso. Só a **forma
malformada** (`4k` chars + `=`, total `4k+1`/`4k+2`, sintaticamente inválida) casa.

## Rodar
```bash
bash testes/fp-replay/run.sh      # baixa o SecLists + roda no Docker (pcre2 + re2)
```
Exit 0 = zero FP. Qualquer FP imprime exemplos e sai 1 (é um achado).

## Limites honestos
- Este é um **corpus de ESTRESSE enriquecido** (superrepresenta de propósito o que se parece com o
  gatilho), **não uma amostra representativa** da distribuição de produção. Ótimo para **descobrir modos
  de falha** (0 FP aqui = a forma é robusta); **não** estima prevalência de FP na sua rede — para isso,
  aponte o `fp_replay.py` para um **PCAP/HAR real**, amostrado independentemente da regra.
- **Representação inspecionada:** testamos a forma **crua**. O engine pode ver algo diferente (URL-decoded,
  form-decoded — `+`→espaço, JSON-unescaped, descomprimido). Meça na representação que a **sua** regra lê.
- Mede a FP da **forma canônica** (PCRE/RE2). As variantes shipadas por engine são garantidas iguais pelo
  harness [`../per-engine/`](../per-engine/) (que também roda no motor real).
- Não mede falsos-**negativos** — isso é o `validar.py` + o lab de reprodução.
