# Demo FortiWeb — ataque vs. defesa do Java4Shell (CVE-2026-114938)

A mesma história do [demo nginx](../README.md), agora na **stack Fortinet**: o **ataque
acontecendo** (a escrita fora-dos-limites de 62 bytes do Java4Shell) e a **defesa na borda** —
o FortiWeb barrando o mesmo request **antes** de chegar no Java — com a **Custom Signature do
próprio repo** ([`../../regras/fortiweb/detect4shell.md`](../../regras/fortiweb/detect4shell.md))
e o **Console de Ataque** ([`../console/`](../console/AttackConsole.java)).

> ⚠️ **SÓ LABORATÓRIO.** O alvo é um servidor Java **deliberadamente vulnerável**. Tudo rodou num
> **FortiWeb-VM 8.0.8** em `10.10.10.101` (lab, acesso por Guacamole/RDP) e num host de ataque
> isolado. Não é um exploit: o "payload" é a string Base64 malformada já **pública** (`A×64 + "="`),
> e toda consequência fica **dentro do processo** (ele **mede** a violação de memória; nada é
> weaponizado). **Nunca** exponha o JVM vulnerável na Internet.
>
> **Isolamento (não tocar produção):** no FortiWeb a *Signature Policy* era **compartilhada** entre
> o perfil do **PILOT** e o do **PUBLIC**. Para testar sem risco, **clonamos** a Signature Policy e
> apontamos **só** o *Inline Protection Profile* do PILOT para o clone — o policy público
> `NEXA_AURORA_WAF_PUBLIC` ficou **intocado**.

## O que você vai ver

Duas provas **separadas e honestamente rotuladas** (não são a mesma máquina):

- ✅ **O primitivo no JVM** — o Console de Ataque dispara o gatilho contra o **alvo Java LOCAL
  vulnerável** (`127.0.0.1:18080`) e o backend responde com a **medição da escrita OOB**
  (`oob_write=62 bytes`). Prova que o bug é real naquele JVM.
- 🛡️ **O bloqueio na borda** — um `curl` **do NUC** contra o virtual server do FortiWeb
  (`10.10.10.101:8899`) com o mesmo header leva **HTTP 403** + página de bloqueio do FortiWeb
  (**Attack ID 20000009**). Prova que a borda barra a **forma** do gatilho.

> **Por que separadas?** No teste, o **backend do PILOT não servia** — então o estado `OOB_SUCCESS`
> (verde) foi demonstrado **no alvo Java local**, não "através do FortiWeb". Nós **não** afirmamos
> que o OOB atravessou o FortiWeb; afirmamos só o que foi demonstrado: o **primitivo** no JVM local
> **e** o **403** na borda. São dois fatos verdadeiros, medidos em pontos diferentes.

![Console de Ataque em "Pronto", com a legenda dos 4 estados (OOB_SUCCESS / WAF_BLOCKED / REACHED_NO_OOB / NO_RESPONSE)](img/00-console-legenda.png)
*O Console classifica cada rajada num de 4 estados — a legenda que vamos usar no passo a passo.*

```
RESUMO (medido no lab)
  alvo Java LOCAL (console -> 127.0.0.1:18080)     -> ✅ OOB_SUCCESS   1/20 · 62 bytes no JVM
  borda FortiWeb (curl do NUC -> 10.10.10.101:8899) -> 🛡️ WAF_BLOCKED  HTTP 403 · Attack ID 20000009
```

## Pré-requisitos

- **FortiWeb** em modo reverse-proxy com um **Server Policy** publicando a app Java (no lab:
  FortiWeb-VM **8.0.8** em `10.10.10.101`, admin via Guacamole/RDP). A GUI de assinaturas custom
  fica em **Web Protection → Known Attacks → Custom Signature** (abas *Custom Signature Group* e
  *Custom Signature*).
- **Console de Ataque** ([`../console/AttackConsole.java`](../console/AttackConsole.java)), compilado:
  ```bash
  cd demo/console
  javac AttackConsole.java
  java AttackConsole                         # alvo default http://127.0.0.1:8899, UI em 8090
  # ou aponte explicitamente:
  D4S_TARGET=http://127.0.0.1:18080 java AttackConsole
  ```
  Abra a UI em `http://127.0.0.1:8090`.
- **Alvo Java vulnerável** ([`../alvo/VulnBasicAuthServer.java`](../alvo/VulnBasicAuthServer.java)) num
  host **x86-64 com AVX-512 VBMI** + **OpenJDK não corrigido**. No lab: **AMD Ryzen 9 7950X (Zen 4,
  VBMI) + OpenJDK 21.0.13** ouvindo em `127.0.0.1:18080`. ⚠️ O gatilho aqui é o de **64 chars**
  (`A×64+"="`, dispara em JDK 21/25/27); **em JDK 17 use `A×128+"="`** (cenário "Gatilho A×128").
- **A máquina que manda o curl do bloqueio** é o **NUC** (Intel **i7-6770HQ**, Skylake, **sem VBMI**,
  sem Java) — **imune** por hardware; ela serve só para provar o 403 na borda.

## Passo a passo

> Todos os prints abaixo são **capturas reais do lab** (FortiWeb-VM 8.0.8 em `10.10.10.101`, o Console
> de Ataque, e o NUC via Guacamole), em [`img/`](img/).

### P1 — Criar a Custom Signature (a *forma* do gatilho)

Em **Web Protection → Known Attacks → Custom Signature → aba Custom Signature → New**:

- **Name:** `D4S_Java4Shell_Base64`
- **Direction:** `Request`
- **Severity:** `High`
- **Case Sensitive:** `Disable` *(inócuo aqui: a regex já traz `[A-Za-z]` nas duas caixas)*
- **Rule (tipo `Regular expression match`):** `Available Target = Request Header`, header
  `Authorization`, com a **regex canônica** (header / PCRE):
  ```
  (?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-])
  ```
- **Action:** comece em `Alert` (só **registra**, não bloqueia).

![FortiWeb — Edit Custom Signature D4S_Java4Shell_Base64: Direction=Request, regra "Regular expression match" com Available Target=Request Header e a regex de forma Base64, Action=Alert, Severity=High](img/01-signature.png)
*Prova: a assinatura casa a **forma** do gatilho (≥16 "quads" Base64 + `=`/`==` na fronteira) no
header `Authorization` — não há metacaractere de ataque, então o conjunto **padrão** de um WAF não
pegaria. A regra completa (URI, Cookie, Body e o fallback RE2) está em
[`../../regras/fortiweb/detect4shell.md`](../../regras/fortiweb/detect4shell.md).*

### P2 — Isolar por CLONE e encadear até o Server Policy do PILOT

A cadeia do FortiWeb 8.0 é: **Custom Signature → Custom Signature Group → Signatures (Signature
Policy) → Inline Protection Profile → Server Policy**. Para não tocar produção, **clonamos** a
Signatures que era compartilhada e trabalhamos só no clone:

- a Custom Signature `D4S_Java4Shell_Base64` vai no **Custom Signature Group** `D4S_Java4Shell`;
- esse grupo é referenciado pela **Signatures (clone)** `NEXA_JUICE_SIGNATURES_D4S`;
- o **Inline Protection Profile** do PILOT `NEXA_JUICE_STANDARD` aponta para **essa** Signatures;
- quem usa esse perfil é o **Server Policy** `NEXA_JUICE_WAF_PILOT` (serviço HTTP na porta `8899`).

O policy público `NEXA_AURORA_WAF_PUBLIC` continua com o perfil dele — **intocado**.

![Lista de Signatures mostrando o conjunto User-Defined NEXA_JUICE_SIGNATURES_D4S (o clone) ao lado dos originais](img/02-clone-signatures.png)
*Prova: a Signatures **clonada** `NEXA_JUICE_SIGNATURES_D4S` existe como User-Defined — editar/negar
nela **não** afeta o policy público.*

![Lista de Inline Protection Profile (coluna Signatures): NEXA_JUICE_STANDARD (PILOT) usa NEXA_JUICE_SIGNATURES_D4S; NEXA_AURORA_STANDARD (PUBLIC) usa NEXA_JUICE_SIGNATURES_CHAT](img/02b-perfil-inline.png)
*Prova de isolamento (coluna **Signatures**): o perfil do **PILOT** (`NEXA_JUICE_STANDARD`) aponta
para o clone **`NEXA_JUICE_SIGNATURES_D4S`** (com a regra D4S); o do **PUBLIC** (`NEXA_AURORA_STANDARD`)
aponta para **`NEXA_JUICE_SIGNATURES_CHAT`** — set **separado, sem a regra**. É o que garante que mexer
no clone não toca o público.*

![Lista de Server Policy: NEXA_JUICE_WAF_PILOT usa o perfil NEXA_JUICE_STANDARD e NEXA_AURORA_WAF_PUBLIC usa NEXA_AURORA_STANDARD (perfis diferentes)](img/02c-server-policy.png)
*Prova (Server Policy): o **PILOT** (`NEXA_JUICE_WAF_PILOT`) usa o perfil `NEXA_JUICE_STANDARD` e o
**PUBLIC** (`NEXA_AURORA_WAF_PUBLIC`) usa `NEXA_AURORA_STANDARD` — **perfis diferentes**. Mexer no perfil
do PILOT não toca o público.*

### P3 — Confirmar a assinatura em modo Alert (ainda não bloqueia)

Salve e confira na lista de Custom Signature que a `D4S_Java4Shell_Base64` está com **Action =
Alert**. Nesta fase o request **chega ao backend** — a assinatura só **registra** (é de propósito:
observe fluxos reais de auth/SAML/JWT antes de negar).

![Lista de Custom Signature com D4S_Java4Shell_Base64 salva: Direction=Request, Action=Alert, Severity=High](img/03-signature-alert.png)
*Prova: a assinatura está **ativa em Alert** — a borda vê o gatilho mas deixa passar.*

### P4 — Disparar o ataque e ver a escrita OOB no alvo vulnerável

Como o **backend do PILOT não servia** no teste, apontamos o Console **direto ao alvo Java local
vulnerável** para provar o **primitivo** no JVM:

```bash
D4S_TARGET=http://127.0.0.1:18080 java AttackConsole
```

Na UI (`http://127.0.0.1:8090`): cenário **"Gatilho A×64 ="** → botão **⚡ DISPARAR ATAQUE**.
Estado dominante **✅ ATAQUE BEM-SUCEDIDO** (`OOB_SUCCESS`): *"OOB disparou em 1/20 tentativas · 62
bytes no JVM"*, rodapé `MEMORY-CORRUPTION cve-2026-114938 oob_write=62 bytes`.

![Console de Ataque "ATAQUE BEM-SUCEDIDO" contra 127.0.0.1:18080: OOB 1/20, 62B no JVM, bloqueados 0/20, rodapé oob_write=62](img/04-console-oob.png)
*Prova: o gatilho **chegou ao JVM e disparou** a escrita OOB de 62 bytes — o primitivo é real
naquele host (Zen 4 + OpenJDK 21.0.13). Isso é **medição no alvo de lab**, independente do modo da
assinatura; não é "o OOB passou pelo FortiWeb" (ver "Três fatos honestos"). O `HTTP 500` com
`oob_write=62` é a mesma instrumentação do alvo.*

### P5 — Virar a assinatura para Alert & Deny (agora a borda bloqueia)

Edite `D4S_Java4Shell_Base64` e mude **Action → `Alert & Deny`**, **OK**. (As opções de Action do
FortiWeb 8.0 são: Alert / Alert & Deny / Deny (no log) / Block Period / Redirect / Send HTTP
Response / Client ID Block Period.)

![Edit Custom Signature com Action=Alert & Deny sendo salvo (OK)](img/05-action-deny.png)
*Prova: a assinatura passou de **registrar** para **registrar e bloquear** — só no PILOT isolado.*

![(opcional) Dropdown de Action do FortiWeb 8.0 com as opções Alert / Alert & Deny / Deny (no log) / Block Period / Redirect / Send HTTP Response / Client ID Block Period](img/05b-action-dropdown.png)
*Opcional: o leque de ações disponível — escolhemos **Alert & Deny**.*

### P6 — Reatacar com a borda em Deny → HTTP 403

Do **NUC** (sem Java, imune), `curl` no virtual server do PILOT com o header do gatilho
(`64 'A' + '='`):

```bash
curl -i -H "Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" \
     http://10.10.10.101:8899/
```

Esperado: **HTTP 403** + página de bloqueio do FortiWeb. **Neste lab** veio com **Attack ID
`20000009`** e **Message ID `000000005365`** — mas o **Attack ID é atribuído pelo appliance**
(ilustrativo; pode diferir entre builds/instâncias) e o **Message ID é por-evento** (muda a cada
bloqueio): **não** são valores reproduzíveis nem IoC. Se o Console estiver apontado ao vserver
(`D4S_TARGET=http://10.10.10.101:8899`), o estado vira **🛡️ BLOQUEADO PELO WAF** (`WAF_BLOCKED`).

![Desktop do NUC: a assinatura D4S em Alert & Deny na GUI do FortiWeb e, no PowerShell, o curl do gatilho recebendo a página de bloqueio do FortiWeb (Attack ID 20000009)](img/06-nuc-403.png)
*Prova: o `curl` do gatilho **do NUC** contra `10.10.10.101:8899` recebe a **página de bloqueio do
FortiWeb** ("The page cannot be displayed", Attack ID `20000009`) — a borda **negou** o request. Ao
fundo, a assinatura `D4S_Java4Shell_Base64` em **Alert & Deny**.*

> O 403 prova que a **borda barrou a forma** do gatilho — **não** prova que o backend era
> explorável; e **não** bloquear não provaria que era seguro.

### P7 — Conferir o Attack Log do FortiWeb (a evidência do Deny)

Em **Log & Report → Attack Log**, confira a entrada do bloqueio: **Action = Deny**, assinatura
`D4S_Java4Shell_Base64`, **Attack ID 20000009**.

![Attack Log do FortiWeb (Log Details): Policy NEXA_JUICE_WAF_PILOT, Action Alert_Deny, Main Type Custom Signature Detection, mensagem "triggered custom signature rule D4S_Java4Shell_Base64", Matched Pattern AAAA](img/07-attacklog.png)
*Prova (Attack Log): **Policy = `NEXA_JUICE_WAF_PILOT`**, **Action = `Alert_Deny`**, mensagem *"HTTP
Header(Authorization) triggered custom signature rule **D4S_Java4Shell_Base64**"*, Matched Pattern
`AAAA…`. Fecha o ciclo: a borda **viu, classificou e bloqueou** — com registro auditável, e **no PILOT**
(não no público).*

## Três fatos honestos sobre este demo

- **O "verde" foi no alvo Java LOCAL, e o disparo é heap-dependente.** O `OOB_SUCCESS` saiu do
  **alvo vulnerável local** (`127.0.0.1:18080`), porque o backend do PILOT não servia no teste — ele
  prova o **primitivo** no JVM, **não** que o OOB atravessou o FortiWeb. E a escrita OOB de 62 bytes
  é **heap-dependente**: ~100% no padrão fixo do reprodutor, ~0% com arrays frescos → o crash é
  **probabilístico**, uma exploração confiável exige *heap grooming*. É sinal **de lab**, não IoC.
- **Banner ≠ match de regra ≠ bug — três coisas diferentes.** O **403** (Attack ID 20000009) prova
  que o FortiWeb barrou a **forma** do gatilho na borda. Não prova que o host atrás era explorável;
  **não** bloquear não provaria que era seguro. `HTTP 500` e `oob_write=62` são **instrumentação do
  alvo de LAB**, não indicadores de produção.
- **Quem é vulnerável é decidido pelo hardware.** O OOB só dispara em **x86-64 com AVX-512 VBMI**
  (Intel Ice Lake+ / AMD Zen 4+) rodando **OpenJDK 17.0.6+ / 21 / 25 / 27** não corrigido. No lab, o
  alvo vulnerável é o host **Zen 4 + OpenJDK 21.0.13**; o **NUC** (i7-6770HQ, Skylake, **sem VBMI**,
  sem Java) que mandou o curl é **imune** — bloquear ou não na borda não muda isso. **ARM também é
  imune.**

## Como isso vira produção

1. **Rode em Alert primeiro.** Deixe a assinatura em `Alert` por alguns dias observando fluxos reais
   de **auth/SAML/JWT**; só então vire `Alert & Deny`. (No demo pulamos direto para Deny, mas **no
   PILOT isolado**.)
2. **Estenda às Server Policies públicas** que publicam apps Java reais (Jira, Confluence, Jenkins,
   Keycloak, Artifactory, Spring Boot…), vinculando o signature set ao *Inline Protection Profile*
   delas. Aqui mantivemos `NEXA_AURORA_WAF_PUBLIC` **intocado de propósito**.
3. **É controle COMPENSATÓRIO** (exatamente o que a CISA recomenda para quem ainda não corrigiu) —
   **não substitui atualizar o JDK** para o build `.1` (17.0.21.1 / 21.0.13.1 / 25.0.5.1 /
   27.0.1.1). Corrija o Java de qualquer forma.
4. **O boundary de rede é evadível por encoding** (`%3D`, `=`, `&#61;`) — a regra casa a forma
   **contígua** no buffer. Para fechar isso, some a **mitigação na aplicação** (Servlet Filter +
   flag de JVM `-XX:-UseBASE64Intrinsics`) descrita no repo.

**Mais na stack Fortinet:** a regra completa (CLI + GUI + fallback RE2) está em
[`../../regras/fortiweb/detect4shell.md`](../../regras/fortiweb/detect4shell.md); o IPS do FortiGate
em [`../../regras/fortigate-ips/detect4shell.md`](../../regras/fortigate-ips/detect4shell.md); a
correlação em FortiSIEM/FortiAnalyzer em
[`../../regras/siem/fortisiem-fortianalyzer.md`](../../regras/siem/fortisiem-fortianalyzer.md); e o
mapa do Fabric por função em [`../../docs/FORTINET-FABRIC.md`](../../docs/FORTINET-FABRIC.md).
