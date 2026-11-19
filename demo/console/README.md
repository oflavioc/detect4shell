# Console de Ataque — Java4Shell no navegador (CVE-2026-114938)

**Ferramenta DEFENSIVA de demonstração.** Uma página web *single-file* que dispara o **gatilho** do
Java4Shell contra um alvo HTTP **que você escolhe** — tipicamente um **virtual server do FortiWeb** que
faz proxy para um backend Java, **ou** o alvo Java local de lab deste repo — e **classifica** o resultado
em **4 estados**, ao vivo, num painel. É o mesmo motor do passo-a-passo de terminal em
[`../README.md`](../README.md), só que no navegador e apontável para a stack real. Tudo embutido
(logo e fundo inclusos), sem dependência externa.

> ⚠️ **SÓ LABORATÓRIO / DEFENSIVO.** Não é um exploit: o "payload" é só a **string Base64 pública**
> (`A×64 + "="`), nada é weaponizado — toda consequência fica num array do **próprio** programa alvo
> (lab confinado, offline). Dispare **apenas** contra sistemas que você está autorizado a testar, em rede
> isolada. **Nunca** exponha o JVM vulnerável na Internet.

## O que é — e os 4 estados

O console ([`AttackConsole.java`](AttackConsole.java)) manda uma **rajada** de requisições (20 por disparo;
o header enviado é `Authorization: Basic <base64>`) e mostra o **estado dominante**, as contagens, a
latência, o header enviado e um trecho da resposta. Os quatro estados, com os **nomes exatos** que a
ferramenta usa:

| Estado | Ícone | Significado |
|---|---|---|
| **`OOB_SUCCESS`** | ✅ | O backend respondeu com a **medição da escrita OOB** (`oob_write=…`) — o ataque chegou ao JVM **e disparou**. |
| **`WAF_BLOCKED`** | 🛡️ | O WAF (FortiWeb) **barrou na borda** — `HTTP 403` / página de bloqueio (ou header `X-FortiWeb`). |
| **`REACHED_NO_OOB`** | ⚠️ | Chegou ao backend mas **não disparou** — JVM mitigada, CPU **sem AVX-512 VBMI**, ou já corrigido. |
| **`NO_RESPONSE`** | ❓ | **Sem resposta HTTP** — backend fora do ar / conexão fechada. |

Regra de decisão do estado dominante: **OOB vence** (basta **1** disparo da rajada); senão **WAF**, se
bloqueou a maioria; senão "chegou-sem-OOB"; senão "sem-resposta". A mesma legenda dos 4 estados aparece no
rodapé da página.

## Compilar e rodar

JDK **17+** (a UI usa `com.sun.net.httpserver`):

```bash
cd demo/console
javac AttackConsole.java
java AttackConsole [alvo] [porta-ui]
```

- **`alvo`** — default `http://127.0.0.1:8899` (aponte para o seu virtual server do FortiWeb; para o alvo
  Java local de lab use `http://127.0.0.1:18080/`).
- **`porta-ui`** — default `8090`. Abra **`http://127.0.0.1:8090`** no navegador.

Ou defina o alvo por variável de ambiente (equivale ao 1º argumento):

```bash
D4S_TARGET=http://10.10.10.101:8899 java AttackConsole
```

O terminal imprime a URL da UI e o alvo resolvido; `Ctrl-C` encerra.

## Os 3 cenários (botões na UI)

| Botão | O que manda | Dispara em |
|---|---|---|
| **Benigno (controle)** | `dXNlcjpwYXNzd29yZA==` (= `user:password`, Base64 **válido** curto) | nada — é o controle; **não** deve casar assinatura nem gerar OOB |
| **Gatilho A×64 =** | 64 × `A` + `=` | OpenJDK **21 / 25 / 27** |
| **Gatilho A×128 = (JDK 17)** | 128 × `A` + `=` | OpenJDK **17** |

⚠️ O gatilho é **específico por versão**: contra um JVM **genuinamente vulnerável rodando JDK 17**, o
payload de 64 chars **não** dispara (falso-negativo) — use o de 128. A mecânica (por que `=` e `==`
disparam, por que ARM e Skylake são imunes) está em [`../../docs/ANALISE.md`](../../docs/ANALISE.md).

## Para onde apontar o alvo

**(a) Alvo Java local de lab — o caminho mais simples.** Suba o
[`../alvo/VulnBasicAuthServer.java`](../alvo/VulnBasicAuthServer.java)
(`java VulnBasicAuthServer 127.0.0.1 18080`) e aponte o console para `http://127.0.0.1:18080/`. O
**Benigno** → `REACHED_NO_OOB` (200, chegou, sem OOB); o **Gatilho** → **`OOB_SUCCESS`** (o alvo responde
`HTTP 500 oob_write=62`). É aqui que o estado **verde** é demonstrado, num JVM realmente vulnerável
(host AMD **Zen 4** + **OpenJDK 21.0.13**).

**(b) Virtual server do FortiWeb → backend Java — a stack real.** Aponte para o vserver (ex.:
`http://10.10.10.101:8899`) com a assinatura custom do Detect4Shell carregada no Inline Protection Profile
(ver [`../../regras/fortiweb/detect4shell.md`](../../regras/fortiweb/detect4shell.md)). Com a ação em
**Alert & Deny**, o `403` do FortiWeb é classificado como **`WAF_BLOCKED`**; o Benigno **passaria** (200,
proxied) quando o backend serve — no demo ao vivo o backend do PILOT estava fora, então esse estado não
foi exercido. A assinatura casa a **forma** do gatilho — ele não tem metacaractere de ataque (é só Base64 +
`=`), então o conjunto **padrão** de um WAF não o pega:

```
(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}(?![A-Za-z0-9+/_=-])
```

> **Honestidade sobre o demo ao vivo (sem overclaim).** O estado **verde (`OOB_SUCCESS`)** foi demonstrado
> contra o **alvo Java LOCAL vulnerável** (Zen 4 + OpenJDK 21.0.13) — **não** "através do FortiWeb PILOT":
> o backend do PILOT **não servia** durante o teste. O **403 (`WAF_BLOCKED`)** foi demonstrado via `curl`
> do **NUC** (Intel Skylake, **sem** VBMI → imune, sem Java instalado) contra o vserver do PILOT com a
> assinatura em **Alert & Deny** (Attack ID `20000009`). São **duas fases / dois alvos** distintos — o
> console rotula **cada resposta** pelo que ela mostra, não por suposição.

## Rotas servidas

| Rota | Serve |
|---|---|
| `/` | a UI (HTML *single-file*) |
| `/config` | `{"target":"…"}` — o alvo configurado, em JSON |
| `/fire?scenario=<benign\|trigger\|trigger128>` | dispara a rajada e devolve resultado + estado em JSON |
| `/logo.svg` | o logo (gatinho mascote) |
| `/bg.svg` | a marca d'água de fundo (ver abaixo) |

## Fatos honestos (leia antes de tirar conclusão)

- **A escrita OOB é HEAP-DEPENDENTE, não determinística.** Mesmo input, o reprodutor oficial estoura
  **100%** (padrão de alocação fixo); um loop com arrays **frescos**, **~0%** — ela só cai quando há bytes
  Base64 válidos logo **após** o buffer de decode. O alvo de lab usa o padrão do reprodutor (buffer reusado
  + JIT aquecido), então o `OOB_SUCCESS` é **estável** — mas é sinal **de lab**, não garantia. A rajada
  existe justamente porque o disparo é **probabilístico**.
- **`HTTP 500` / `oob_write=62` são INSTRUMENTAÇÃO do alvo de lab, não IoC de produção.** Esses números
  são a forma como o **alvo** prova o primitivo para você — não são indicadores que você vá ver num
  servidor real comprometido.
- **Banner ≠ match de regra ≠ bug** — três coisas diferentes. Um WAF **bloquear** não prova que o host era
  explorável; **não** bloquear não prova que era seguro. O console mede **alcance e reação**, não
  explorabilidade (reforço: o 403 acima saiu de um NUC que é **imune** por hardware).
- **Nada disso substitui CORRIGIR o JDK** (builds `.1`). A regra de borda (FortiWeb / nginx / …) é controle
  **compensatório** — exatamente o que a CISA recomenda enquanto o patch não chega.

## Detalhe de UI — a marca d'água do gatinho 🐱

O fundo do console (`/bg.svg`) é o **mesmo gatinho mascote** do logo, só que sem o retângulo escuro
(transparente) e com a "parede de `A`" trocada por **0s e 1s** — aplicado como marca d'água **discreta**
(bem esmaecida) atrás do painel. É só enfeite da identidade visual: não muda nenhum comportamento da
ferramenta.

## Veja também

- [`../README.md`](../README.md) — o passo-a-passo **ataque vs. defesa** no terminal (alvo + edge nginx).
- [`../alvo/VulnBasicAuthServer.java`](../alvo/VulnBasicAuthServer.java) — o alvo Java de lab (porta 18080).
- [`../../regras/fortiweb/detect4shell.md`](../../regras/fortiweb/detect4shell.md) — a assinatura custom do FortiWeb (modo reverse-proxy, `alert_deny`).
- [`../../docs/FAQ.md`](../../docs/FAQ.md) — "o WAF bloqueou = era explorável?" e outras.
- [`../../docs/EXPLICACAO-SIMPLES.md`](../../docs/EXPLICACAO-SIMPLES.md) — o ataque explicado do zero.
