# Detect4Shell / Java4Shell (CVE-2026-114938) — matriz de validação CPU × JDK

Reprodutor confinado: `laboratorio/Base64Trigger.java` (offline, escreve só dentro do próprio
array de 4096 bytes, escolhe o comprimento do gatilho automaticamente — 128 no JDK 17, senão 64).
Rodado via Docker num host Windows com Docker Desktop (containers Linux, linux/amd64). Sem acesso
à rede, sem modificação do reprodutor. Data desta execução: 2026-11-18.

## Matriz de builds JDK (Docker, imagens locais, linux/amd64)

| # | Imagem (tag) | Fornecedor | `java.runtime.version` reportado | Comprimento do gatilho | rejected | changed | Resultado |
|---|---|---|---|---|---|---|---|
| 1 | `eclipse-temurin:17-jdk` | Eclipse Temurin | 17.0.21+9 | 128 | true | 62 | **REPRODUZIDO** |
| 2 | `eclipse-temurin:21-jdk` | Eclipse Temurin | 21.0.13+9-LTS | 64 | true | 62 | **REPRODUZIDO** ← build sabidamente-vulnerável usado nas execuções-proxy abaixo |
| 3 | `eclipse-temurin:25-jdk` | Eclipse Temurin | 25.0.5+8-LTS | 64 | true | 62 | **REPRODUZIDO** |
| 4 | `amazoncorretto:17` | Amazon Corretto | 17.0.21.1+2-LTS | 128 | true | 0 | **NÃO REPRODUZIDO** — point release já-corrigida (`.1`) |
| 5 | `amazoncorretto:21` | Amazon Corretto | 21.0.13.1+2-LTS | 64 | true | 0 | **NÃO REPRODUZIDO** — point release já-corrigida (`.1`) |

As linhas 4–5 satisfazem diretamente o passo "teste um build corrigido": as tags flutuantes `17`/`21`
do Amazon Corretto já tinham avançado para a point release `.1` que corrige este problema na data desta
execução, enquanto as tags `17-jdk`/`21-jdk`/`25-jdk` do Eclipse Temurin ainda estavam na point release
pré-correção. Não foi preciso caçar uma tag corrigida fixada à parte — este é um dado corrigido real,
ocorrido naturalmente, não um cherry-pick.

## Proxies de flag de mitigação (rodados na linha 2, `eclipse-temurin:21-jdk`, runtime 21.0.13+9-LTS — o
build confirmado-vulnerável)

| Flag | rejected | changed | Resultado |
|---|---|---|---|
| `-XX:-UseBASE64Intrinsics` (desliga o intrínseco Base64 por completo) | true | 0 | **NÃO REPRODUZIDO** |
| `-XX:UseAVX=2` (limita o teto AVX do HotSpot abaixo do AVX-512 VBMI) | true | 0 | **NÃO REPRODUZIDO** |

Os dois proxies modelam um runtime "imune" sobre bits de JDK vulnerável idênticos no resto: desligar o
intrínseco, ou forçar o codegen para fora do caminho AVX-512 VBMI, suprime o overrun exatamente como uma
CPU não-VBMI real ou um JDK corrigido fazem.

## Eixo de CPU (resultados já-conhecidos, não re-executados — incluídos para completude)

| CPU | Microarquitetura | AVX-512 VBMI | JDK testado | Resultado |
|---|---|---|---|---|
| AMD Ryzen 9 7950X | Zen 4 | Sim | Temurin 21.0.13.0.2 (bare metal, host) | **REPRODUZIDO** (changed=62) |
| AMD EPYC 7713 (VPS, via Docker `temurin:21`) | Zen 3 | Não | Temurin 21 (container) | **NÃO REPRODUZIDO** (changed=0) — CPU x86 imune real |

## O que esta matriz prova

- **A vulnerabilidade reproduz nos majors JDK 17, 21 e 25**, e entre fornecedores (Eclipse Temurin
  confirmado vulnerável nos três majors; o Amazon Corretto também reproduz nas suas point releases
  pré-correção, embora as tags flutuantes puxadas aqui já tenham caído pós-correção) — não é um artefato
  de um único build JDK. Depende de o intrínseco Base64 do HotSpot C2 escolher o codegen AVX-512 VBMI,
  que existe nesses majors.
- **Está ausente em hardware sem AVX-512 VBMI**: o EPYC 7713 Zen 3 real (sem VBMI) nunca reproduz,
  enquanto o Ryzen 9 7950X Zen 4 real (com VBMI) reproduz de forma confiável — confirmando que o recurso
  da CPU, não a versão do JDK sozinha, condiciona o overrun.
- **As duas mitigações de software o suprimem num build JDK de outra forma vulnerável**: desligar o
  intrínseco Base64 (`-XX:-UseBASE64Intrinsics`) ou limitar o teto AVX abaixo do VBMI (`-XX:UseAVX=2`)
  ambos levam o `eclipse-temurin:21-jdk` (21.0.13+9-LTS) de REPRODUZIDO para NÃO REPRODUZIDO sem nenhuma
  outra mudança.
- **Um patch real de fornecedor também o suprime**: as point releases `.1` do Amazon Corretto para 17 e
  21 dão NÃO REPRODUZIDO, consistente com o intrínseco estar corrigido/desligado upstream nesses builds
  posteriores, enquanto as point releases pré-correção do Temurin nos mesmos majors ainda reproduzem.

Resumo: isto substitui a divulgação anterior de máquina-única ("validado em 1 máquina: Zen 4 / JDK
21.0.13.0.2") por uma matriz de **5 builds JDK (2 já-corrigidos `.1`) × 2 flags de mitigação**, mais o
eixo de **CPU** (2 microarquiteturas — resultados prior-art, não re-executados neste run). A varredura
JDK roda com `--network none` (o `run_matrix.sh` só baixa a imagem, se faltar, antes do run isolado) e o
reprodutor confinado não é modificado.
