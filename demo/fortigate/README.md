# Demo FortiGate IPS — detecção inline do Java4Shell (CVE-2026-114938)

A mesma história do [demo nginx](../README.md) e do [demo FortiWeb](../fortiweb/README.md), agora na camada de **rede**: o **IPS do FortiGate** reconhecendo a *forma* do gatilho Java4Shell em HTTP que **atravessa o appliance** — não só o que está atrás de um WAF reverse-proxy. É o cenário ideal para proteger apps Java expostas no perímetro, com as **Custom Signatures do próprio repo** ([`../../regras/fortigate-ips/detect4shell.md`](../../regras/fortigate-ips/detect4shell.md)).

> ⚠️ **SÓ LABORATÓRIO.** Tudo rodou num **FortiGate-60E 7.4.12** (lab, admin por GUI) e um host de ataque isolado. Não é um exploit: o "payload" é a string Base64 malformada já **pública** (`A×64 + "="`), e aqui ela nem toca um JVM — vai como header HTTP num GET inócuo, só para a borda **ver a forma**. **Nunca** exponha o JVM vulnerável na Internet.
>
> **Isolamento (não tocar produção):** o sensor rodou em **Monitor** (`action pass` + log — **loga, não bloqueia**) numa **policy de teste dedicada e temporária** (`D4S-IPS-TEST`) no caminho de uma **VLAN de lab isolada** (`LAB_PILOTO → WAN`), e essa policy foi **apagada ao fim**. Nenhuma policy existente do lab/produção foi alterada; a custom signature pré-existente do lab (`NEXA.Demo.IPS`) ficou **intocada**.

## O que você vai ver

Uma prova **honestamente rotulada**: a custom signature do repo **`Java4Shell.Base64.Auth`** (attack ID `2038`) **carrega, compila e DISPARA** no gatilho Java4Shell real, num FortiGate-60E 7.4.12, em **Monitor mode** (`Action = detected` — registra, não bloqueia).

> **O que isso prova — e o que NÃO prova.** Prova que a assinatura casa a **forma** do gatilho (≥16 "quads" Base64 + `=`/`==` na fronteira, no header `Authorization`) em tráfego HTTP real que passa pelo FortiGate. **Não** prova que o host por trás era explorável — e não bloquear não provaria que era seguro. Rodamos em **Monitor** de propósito (valide falsos-positivos antes de virar Block). No teste o gatilho foi um GET **de saída** (host de lab → `neverssl.com`), porque é o caminho controlável; a assinatura é `--flow from_client`, então casa a mesma forma seja o request de saída do teste ou, em produção, o de **entrada** contra sua app Java.

```
RESUMO (medido no lab — FortiGate-60E 7.4.12)
  custom sig Java4Shell.Base64.Auth (attack ID 2038) -> carrega + compila (F-SBID + PCRE válidos)
  gatilho A×64+"=" de um host do lab (LAB VLAN30) -> 🛡️ IPS detected · Monitor · Severity High · threat score 30
```

## Pré-requisitos

- **FortiGate** com **IPS licenciado** (no lab: FortiGate-60E **7.4.12**). A GUI de custom signatures fica em **Security Profiles → IPS Signatures → Create New**.
- As **3 custom signatures** do repo ([`../../regras/fortigate-ips/detect4shell.md`](../../regras/fortigate-ips/detect4shell.md)): `Java4Shell.Base64.Auth` (header), `.URI` (uri) e `.Body` (body).
- Um **host de ataque no caminho inspecionado** (no lab: `Win10-Stark`, uma VM na **LAB VLAN30**, com `curl`). ⚠️ O gatilho aqui é o de **64 chars** (`A×64+"="`, dispara em JDK 21/25/27); **em JDK 17 use `A×128+"="`**.
- **HTTPS:** exige **SSL deep inspection** na policy, senão o IPS não vê o conteúdo. Aqui o gatilho é **HTTP puro** (sem TLS), então o IPS enxerga o header direto.

## Passo a passo

> Todos os prints abaixo são **capturas reais do lab** (FortiGate-60E 7.4.12), em [`img/`](img/).

### P1 — Criar as 3 Custom Signatures (pela GUI — e por que NÃO pelo CLI)

⚠️ **Lição prática:** o **console CLI do FortiGate engole os `?`** (o `?` dispara o help do CLI), corrompendo o PCRE — `(?:` vira `(:` e `(?!` vira `(!`, deixando a regex **inválida**. Então as assinaturas têm que ser criadas pelo **formulário da GUI** (seta o valor direto no campo, sem passar pelo parser de help).

Em **Security Profiles → IPS Signatures → Create New**, para cada uma das 3 (`Auth`/`URI`/`Body`), cole o `F-SBID(...)` com **aspas literais** (a GUI cuida do escaping), mantendo `\/` (escape do delimitador PCRE) e os `?` intactos. Exemplo (header/`Auth`):

```
F-SBID( --name "Java4Shell.Base64.Auth"; --protocol tcp; --service HTTP; --flow from_client; --context header; --pattern "Authorization|3a 20|"; --no_case; --pcre "/(?<![A-Za-z0-9+\/_-])(?:(?:[A-Za-z0-9+\/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+\/_=-])/"; --severity high; )
```

![FortiGate — New IPS Signature Java4Shell.Base64.Auth: campo Signature com o F-SBID e o PCRE com (?<! / (?:(?: / (?! intactos, botão API Preview habilitado](img/01-custom-signature.jpg)
*Prova: o PCRE gravado mantém `(?<!`, `(?:(?:` e `(?!` **intactos** — a GUI preserva os `?` que o CLI comeria. O FortiOS aceitou a sintaxe `F-SBID` e atribuiu o attack ID (`2038`). A regra completa das 3 (header/uri/body + o ramo `%3D` para buffers brutos) está em [`../../regras/fortigate-ips/detect4shell.md`](../../regras/fortigate-ips/detect4shell.md).*

![FortiGate IPS Signatures — seção "Custom IPS Signature (4)": Java4Shell.Base64.Auth, Java4Shell.Base64.Body, Java4Shell.Base64.URI e NEXA.Demo.IPS](img/02-custom-signatures-list.jpg)
*Prova: as 3 assinaturas D4S aparecem como **Custom IPS Signature** ao lado da pré-existente do lab (`NEXA.Demo.IPS`, **intocada**). Elas **compilaram** — o FortiOS validou o `F-SBID` + o PCRE.*

### P2 — Montar o IPS Sensor em modo Monitor (loga, não bloqueia)

Crie um sensor `D4S-Java4Shell` referenciando as 3 sigs pelos attack IDs, com **`action pass`** (Monitor), log e captura de pacote:

```
config ips sensor
    edit "D4S-Java4Shell"
        config entries
            edit 1
                set rule 2038 6211 7756
                set status enable
                set action pass
                set log enable
                set log-packet enable
            next
        end
    next
end
```

![FortiGate CLI — show ips sensor "D4S-Java4Shell": config entries edit 1 com set rule 2038 6211 7756, set status enable, set log-packet enable, set action pass](img/03-ips-sensor.jpg)
*Prova: o sensor `D4S-Java4Shell` com as 3 custom sigs (`rule 2038 6211 7756`), **`action pass`** (Monitor — detecta e loga, **não** bloqueia). O `log enable` é o default (por isso não aparece no `show`, que esconde valores-padrão).*

### P3 — Aplicar o sensor numa policy (teste isolado)

Para **não tocar** nenhuma policy existente, criamos uma **policy de teste dedicada e temporária** carregando só esse sensor, escopada ao teste, no caminho de uma **VLAN de lab isolada** (`LAB_PILOTO → WAN`), com **SSL `no-inspection`** (HTTP puro) e **Log = All sessions**. *(Em produção você anexa o sensor à policy que publica suas apps Java, com **SSL deep inspection** para enxergar HTTPS.)*

![FortiGate — Edit Policy, seção Security Profiles: IPS = D4S-Java4Shell, SSL inspection = no-inspection, Log allowed traffic = All sessions](img/04-ips-policy.jpg)
*Prova: a policy de teste com **IPS = `D4S-Java4Shell`**, **SSL inspection = `no-inspection`** (tráfego HTTP, o IPS vê o texto claro) e **Log = All sessions**.*

### P4 — Disparar o gatilho de um host do lab

De um host **no caminho inspecionado** (no lab: a VM `Win10-Stark` na **LAB VLAN30**), dispare o gatilho sobre **HTTP** (`A×64+"="`):

```
curl.exe -s -o NUL "http://neverssl.com/" -H "Authorization: Basic AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
```

`neverssl.com` fica sempre em HTTP puro, então o IPS enxerga o header `Authorization`. Qualquer host HTTP serve — o IPS inspeciona o **request** ao atravessar o FortiGate; o destino nem precisa responder nada útil.

### P5 — Ver a detecção no Log (a evidência)

Em **Log & Report → Security Events → Intrusion Prevention** (fonte **Memory** realtime, ou **FortiGate Cloud** para histórico), abra a entrada da detecção.

![FortiGate Log Details da detecção IPS: Action detected, Policy D4S-IPS-TEST, Profile D4S-Java4Shell, Attack Name Java4Shell.Base64.Auth, Attack ID 2.038, Message "custom: Java4Shell.Base64.Auth", Severity High, threat score 30, lan->wan, HTTP GET](img/05-detection.jpg)
*Prova (Log Details): **Attack Name `Java4Shell.Base64.Auth`**, **Attack ID `2.038`**, **Message `custom: Java4Shell.Base64.Auth`**, **Profile `D4S-Java4Shell`**, **Action `detected`** (Monitor — registrou, não bloqueou), **Policy `D4S-IPS-TEST`**, direção `lan→wan`, **HTTP GET**, Severity **High** / threat score **30**. Fecha o ciclo: a assinatura do repo **viu, classificou e registrou** o gatilho — em hardware real, com log auditável.*

### P6 — Reverter

Apague a **policy de teste** (`D4S-IPS-TEST`) — é a única coisa que tocava tráfego. As 3 custom sigs + o sensor ficam **inertes** (não anexados a nenhuma policy) como defesa Detect4Shell pronta para anexar quando quiser, ou remova-os para um revert total ao estado pré-teste.

## Três fatos honestos sobre este demo

- **Monitor "detected" ≠ block ≠ bug — três coisas diferentes.** O `detected` prova que a assinatura casou a **forma** do gatilho na camada de rede. **Não** prova que o host atrás era explorável; **não** detectar não provaria que era seguro. Rodamos **Monitor** (`action pass` + log) de propósito — em produção se vira **Block** depois de validar falsos-positivos.
- **A escrita OOB é heap-dependente — e aqui o gatilho nem tocou um JVM.** A exploração real (a escrita fora-dos-limites de 62 bytes) é **probabilística** e depende do heap; o IPS vê a **forma do request**, independente de o JVM por trás crashar ou não. Neste demo o gatilho foi um GET inócuo contra um host HTTP qualquer — a prova é da **detecção**, não de um "ataque bloqueado numa app Java".
- **Quem é vulnerável é decidido pelo hardware.** O OOB só dispara em **x86-64 com AVX-512 VBMI** (Intel Ice Lake+ / AMD Zen 4+) rodando **OpenJDK 17.0.6+ / 21 / 25 / 27** não corrigido. O IPS detectar ou não **não muda isso** — é controle **compensatório**. **ARM também é imune.**

## Como isso vira produção

1. **Comece em Monitor** (`action pass` + log) por alguns dias observando fluxos reais de **auth/SAML/JWT**; só então vire **Block**.
2. **SSL deep inspection** na policy para **HTTPS** (senão o IPS não vê o header). Aqui o gatilho era HTTP puro.
3. **Anexe o sensor às policies** que publicam apps Java reais (Jira, Confluence, Jenkins, Keycloak, Artifactory, Spring Boot…).
4. **Cheque o FortiGuard** — a Fortinet provavelmente publica uma assinatura IPS oficial para CVE-2026-114938; esta custom é **complemento/stopgap** e cobre vetores que genéricas podem perder (SAML/JWT/cookie/url-safe).
5. **É controle COMPENSATÓRIO** — **não substitui atualizar o JDK** para o build `.1` (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1). Corrija o Java de qualquer forma.

**Mais na stack Fortinet:** a regra completa (CLI + GUI + ramo `%3D`) está em [`../../regras/fortigate-ips/detect4shell.md`](../../regras/fortigate-ips/detect4shell.md); o WAF do FortiWeb em [`../fortiweb/README.md`](../fortiweb/README.md); a correlação em FortiSIEM/FortiAnalyzer em [`../../regras/siem/fortisiem-fortianalyzer.md`](../../regras/siem/fortisiem-fortianalyzer.md); e o mapa do Fabric por função em [`../../docs/FORTINET-FABRIC.md`](../../docs/FORTINET-FABRIC.md).
