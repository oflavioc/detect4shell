# Demo — ataque vs. defesa do Java4Shell (CVE-2026-114938)

Mostra, passo a passo, o **ataque acontecendo** (a escrita fora-dos-limites de 62 bytes do
Java4Shell) e depois a **defesa na borda** barrando o mesmo request **antes** de chegar no Java —
usando a regra nginx **do próprio repo** ([`../regras/nginx/detect4shell.conf`](../regras/nginx/detect4shell.conf)).

> ⚠️ **SÓ LABORATÓRIO.** O alvo é um servidor Java **deliberadamente vulnerável**; não o exponha na
> Internet. Não é um exploit: o "payload" é a string Base64 malformada já pública (`A×64 + "="`), e toda
> consequência fica dentro do processo (ele **mede** a violação de memória; não é weaponizado).

![Detect4Shell — ataque vs. defesa: sem a borda o gatilho dispara a escrita OOB de 62 bytes; com a borda é bloqueado antes do backend Java](demo-before-after.png)

## O que você vai ver (resultado real, capturado)

```
FASE 1 — SEM DEFESA (direto no alvo :18080)
  benigno                 -> HTTP 200 | OK user=admin
  GATILHO (Authorization) -> HTTP 500 | MEMORY-CORRUPTION cve-2026-114938 oob_write=62 bytes
  GATILHO (query SAML)    -> HTTP 200 | OK user=anon   (este alvo só modela o sink Authorization;
                                                        a query só é barrada pela borda nginx na FASE 2)

FASE 2 — COM DEFESA (edge nginx Detect4Shell :8088)
  benigno                 -> HTTP 200 | OK user=admin
  GATILHO (Authorization) -> HTTP 403 | Detect4Shell: ... bloqueado na borda
  GATILHO (query SAML)    -> HTTP 403 | Detect4Shell: ... bloqueado na borda

LOG DA BORDA (nginx):
  200 j4s_auth=0  GET /                       <- benigno passa, proxied pro alvo
  403 j4s_auth=1  GET /  (Authorization)      <- gatilho barrado na borda
  403 j4s_args=1  GET /?SAMLResponse=...=      <- gatilho em query barrado

LOG DO ALVO: só 1 escrita OOB (a da Fase 1). O gatilho da Fase 2 NÃO gerou OOB
             => a borda barrou antes do backend Java.
```

## Dois fatos honestos sobre o demo
- **A escrita OOB de 62 bytes é HEAP-DEPENDENTE, não determinística:** mesmo input, o reprodutor
  oficial estoura 100% (padrão de alocação fixo) mas um loop com arrays frescos ~0% — ela só dispara
  quando há bytes Base64 válidos logo **após** o buffer de decode. O **crash (DoS)** é, portanto,
  **probabilístico** (a escrita cai em *slack* de TLAB) e uma exploração confiável exige *heap grooming*.
  Este demo usa o padrão do reprodutor, então o `oob_write=62` dispara de forma estável — mas é sinal
  **de lab**, não garantia nem IoC de produção.
- **Precondição de hardware:** o OOB só dispara em CPU **x86-64 com AVX-512 VBMI** (Intel Ice Lake+ /
  AMD Zen 4+) rodando **OpenJDK 17.0.6+ / 21 / 25 / 27** não corrigido. ARM e CPUs sem VBMI são imunes.
- **Sinal sintético, NÃO um IoC:** `oob_write=62` e o `HTTP 500` são instrumentação **deste alvo de
  lab** para provar o primitivo — não são indicadores de produção. Um WAF/filtro que bloqueia não prova
  que o host era explorável; um que não bloqueia não prova que era seguro. Banner, match de regra e o bug
  do intrínseco são **três coisas diferentes**.

## Pré-requisitos
- JDK **21/25/27 não corrigido** (`javac`/`java` no PATH). ⚠️ Este demo usa o gatilho de **64 chars**
  (`A×64+"="`), que dispara em 21/25/27. **Em JDK 17 o gatilho é `A×128+"="`** — contra um alvo rodando
  JDK 17, o payload de 64 chars faz o alvo responder `400 "SEM escrita OOB"` num JVM **genuinamente
  vulnerável** (falso-negativo); troque o payload para 128 chars.
- CPU com **AVX-512 VBMI** (ver "Dois fatos honestos"). Checagem: `laboratorio/verificar_patch.sh` roda
  só em **Linux/WSL** (lê `/proc/cpuinfo`); no Git-Bash do Windows ele imprime "PULADO". No Windows,
  rode-o via WSL ou dentro do Docker lab (`laboratorio/Dockerfile`).
- **Docker** (para o edge nginx). O container alcança o alvo via `host.docker.internal`.

## Passo a passo

### 1) Compilar e subir o alvo vulnerável
```bash
cd demo/alvo
javac VulnBasicAuthServer.java
java VulnBasicAuthServer 0.0.0.0 18080      # 0.0.0.0 p/ o container nginx alcançar
```
Espere a linha `[alvo] vulneravel ouvindo em 0.0.0.0:18080`. Esse processo **bloqueia o terminal** —
**abra um segundo terminal** para rodar os ataques (os `./atacar.sh` saem sempre de `demo/`; os
`java VulnBasicAuthServer` saem de `demo/alvo/`, onde está o `.class`).

### 2) FASE 1 — ataque SEM defesa (direto no alvo)
```bash
cd demo
./atacar.sh http://127.0.0.1:18080/
```
O gatilho retorna **HTTP 500 `oob_write=62 bytes`** e o alvo loga `!!! ESCRITA OOB DE 62 BYTES`.
**→ print:** terminal do ataque + terminal do alvo lado a lado.

### 3) (Opcional) mitigação por flag de JVM — zero código
Derrube o alvo (Ctrl-C no terminal do servidor) e suba com o intrínseco vulnerável desligado:
```bash
# terminal do servidor (em demo/alvo)
java -XX:-UseBASE64Intrinsics VulnBasicAuthServer 0.0.0.0 18080
```
```bash
# terminal do ataque (em demo)
./atacar.sh http://127.0.0.1:18080/
```
Agora o gatilho vira **HTTP 400 `SEM escrita OOB`** — a flag `-XX:-UseBASE64Intrinsics`
(product/default no HotSpot) força o Base64 puro-Java, imune. **→ print.**

### 4) FASE 2 — defesa na borda (edge nginx Detect4Shell)
Com o alvo vulnerável no ar (passo 1), suba o nginx com a regra do repo:
```bash
docker run -d --name d4s-edge \
  --add-host host.docker.internal:host-gateway \
  -p 8088:80 \
  -v "$(pwd)/edge-nginx/nginx.conf:/etc/nginx/nginx.conf:ro" \
  nginx:1.27-alpine
```
> No Git-Bash (Windows) use o caminho absoluto `C:/...` e prefixe `MSYS_NO_PATHCONV=1`.

Ataque agora pela borda:
```bash
./atacar.sh http://127.0.0.1:8088/
```
Benigno → **200** (proxied); gatilho (Authorization e query) → **403** bloqueado. **→ print.**

Logs da borda (a evidência do bloqueio + qual regra casou):
```bash
docker exec d4s-edge cat /var/log/nginx/j4s.log
```
Prove que o gatilho barrado **não chegou** no backend (o log do alvo não ganha novo OOB). **→ print.**

### 5) Limpeza
```bash
docker rm -f d4s-edge
# e encerre o processo java do alvo
```

## Como isso vira a stack real (FortiWeb / Fortinet)
A mesma lógica roda nos engines da pasta [`../regras/`](../regras/). Para a defesa de borda com a
stack Fortinet, a assinatura custom do FortiWeb está em
[`../regras/fortiweb/detect4shell.md`](../regras/fortiweb/detect4shell.md) (modo reverse-proxy,
ação `alert_deny`) e a correlação em FortiSIEM/FortiAnalyzer em
[`../regras/siem/fortisiem-fortianalyzer.md`](../regras/siem/fortisiem-fortianalyzer.md).
**Importante:** o gatilho não tem metacaractere de ataque (é só Base64 + `=`), então o conjunto de
assinaturas **padrão** de um WAF não o pega — é preciso a **assinatura da forma** (a do Detect4Shell).
