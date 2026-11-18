# Demo — ataque vs. defesa do Java4Shell (CVE-2026-114938)

Mostra, passo a passo, o **ataque acontecendo** (a escrita fora-dos-limites de 62 bytes do
Java4Shell) e depois a **defesa na borda** barrando o mesmo request **antes** de chegar no Java —
usando a regra nginx **do próprio repo** ([`../regras/nginx/detect4shell.conf`](../regras/nginx/detect4shell.conf)).

> ⚠️ **SÓ LABORATÓRIO.** O alvo é um servidor Java **deliberadamente vulnerável**; não o exponha na
> Internet. Não é um exploit: o "payload" é a string Base64 malformada já pública (`A×64 + "="`), e toda
> consequência fica dentro do processo (ele **mede** a violação de memória; não é weaponizado).

## O que você vai ver (resultado real, capturado)

```
FASE 1 — SEM DEFESA (direto no alvo :18080)
  benigno                 -> HTTP 200 | OK user=admin
  GATILHO (Authorization) -> HTTP 500 | MEMORY-CORRUPTION cve-2026-114938 oob_write=62 bytes

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
- **O primitivo (escrita OOB de 62 bytes) é determinístico**; o **crash de processo (DoS) é
  probabilístico** — a escrita quase sempre cai em *slack* de TLAB (heap ainda não usado) e não
  derruba na hora. Por isso o demo prova a **violação de memória** (`oob_write=62`), não um crash
  que pode não acontecer na hora da demonstração.
- **Precondição de hardware:** o OOB só dispara em CPU **x86-64 com AVX-512 VBMI** (Intel Ice Lake+ /
  AMD Zen 4+) rodando **OpenJDK 17.0.6+ / 21 / 25 / 27** não corrigido. ARM e CPUs sem VBMI são imunes.

## Pré-requisitos
- JDK 17/21/25/27 **não corrigido** (`javac`/`java` no PATH). Confira a CPU: `laboratorio/verificar_patch.sh`.
- **Docker** (para o edge nginx). O container alcança o alvo via `host.docker.internal`.

## Passo a passo

### 1) Compilar e subir o alvo vulnerável
```bash
cd demo/alvo
javac VulnBasicAuthServer.java
java VulnBasicAuthServer 0.0.0.0 18080      # 0.0.0.0 p/ o container nginx alcançar
```
Espere a linha `[alvo] vulneravel ouvindo em 0.0.0.0:18080`.

### 2) FASE 1 — ataque SEM defesa (direto no alvo)
```bash
cd demo
./atacar.sh http://127.0.0.1:18080/
```
O gatilho retorna **HTTP 500 `oob_write=62 bytes`** e o alvo loga `!!! ESCRITA OOB DE 62 BYTES`.
**→ print:** terminal do ataque + terminal do alvo lado a lado.

### 3) (Opcional) mitigação por flag de JVM — zero código
Derrube o alvo e suba com o intrínseco vulnerável desligado:
```bash
java -XX:-UseBASE64Intrinsics VulnBasicAuthServer 0.0.0.0 18080
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
