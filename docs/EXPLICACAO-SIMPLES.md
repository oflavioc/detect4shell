# Java4Shell explicado de um jeito simples 🧩

> **Segurança Descomplicada.** Esta página explica o Java4Shell (CVE-2026-114938) como se fosse
> para alguém de 10 anos. Sem jargão. Se você só tem 5 minutos, leia isto.

---

## 1. O que é? (a história curta)

Imagine que o computador tem um **motor** que roda programas feitos na linguagem **Java**. Esse motor
precisa, o tempo todo, **traduzir mensagens** que chegam da internet — por exemplo, quando você faz
login num site, seu usuário e senha viajam numa "embalagem" chamada **Base64** (um jeito de escrever
usando só letras e números "seguros", para não confundir os computadores).

O **Java4Shell** é um **erro de cálculo** no motor. Quando chega uma embalagem Base64 **quebrada de um
jeito bem específico**, o motor **conta errado o tamanho** e escreve **um pouquinho a mais do que cabe**
— como encher um copo que já está cheio e **derramar na mesa do lado**. 💧

A "embalagem quebrada" mais famosa é simplesmente **64 letras "A" seguidas de um "="**:

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
```

(É por isso que o gatinho do nosso logo está gritando num monte de "A". 🐱)

## 2. Como funciona? (bem devagar)

1. O motor tem um **atalho super-rápido** para traduzir Base64 (só em computadores com um chip
   moderno — isso é importante no passo 5).
2. Quando a mensagem termina naquele "=" quebrado, o atalho **faz uma conta que dá número negativo**.
3. Número negativo vira um **"escreva tudo"** — e o motor escreve **62 bytes a mais**, invadindo a
   **memória do vizinho** ali do lado. 🧱➡️🧱
4. O programa até percebe que a mensagem era inválida e reclama — **mas só DEPOIS** de já ter derramado.
5. **Só acontece em chips modernos** (Intel Ice Lake pra frente / AMD Zen 4 pra frente, com um recurso
   chamado **AVX-512 VBMI**). Em celular, Mac M1/M2, e muito servidor mais antigo, **não acontece**.
   É como um vazamento que só aparece num modelo específico de motor.

## 3. Por que isso é um problema? (as implicações)

O "derramar na mesa do lado" pode causar, do mais comum para o mais raro:

- 🔴 **Derrubar o serviço (o mais provável).** O motor se atrapalha e **desliga** — o site/sistema
  **cai** (fica fora do ar). Isso é o que já foi provado na prática várias vezes.
- 🟠 **Vazar segredos (demonstrado em teste, localmente).** Com cuidado, o atacante pode fazer o vizinho
  "derramado" ser um pedaço de memória com **senhas, tokens ou dados** e **ler** isso — pesquisadores já
  mostraram isso localmente ("JavaBleed"). (Parecido com o antigo "Heartbleed".)
- 🟡 **Assumir o controle — RCE (não provado contra produtos reais).** Em teoria, encadeando vários passos
  difíceis, daria para **executar comandos**. Até agora **ninguém mostrou RCE genérico contra um produto
  real**; houve só uma demonstração **data-only num alvo-demo controlado** (contêiner como root + função
  de admin), e quem testou produtos reais só conseguiu **derrubar** e **vazar**.

> **Tradução honesta:** hoje, o risco real e comprovado é **tirar o sistema do ar** (e talvez **vazar
> dado**). O "hacker assume tudo" é possibilidade, não realidade demonstrada. Não entre em pânico —
> **mas corrija**, porque derrubar um sistema importante já é grave.

## 4. Onde provavelmente está o problema na minha empresa? 🔎

O erro está **dentro do Java**, não num produto específico. Então procure **onde você roda Java que
recebe login/token da internet**. Os lugares mais prováveis (e expostos):

| Procure por... | Por que é alvo |
|---|---|
| **Keycloak, PingFederate** (login único / SSO) | leem Base64 (SAML/login) **antes** de autenticar |
| **Jira, Confluence** (Atlassian) | aceitam login e tokens Base64 sem o usuário estar logado |
| **Jenkins** (esteira de build) | login Basic exposto |
| **Artifactory** (repositório de artefatos) | login Basic exposto |
| **Apps internos em Java/Spring Boot, Tomcat** | qualquer tela de login que decodifica Base64 |
| **Aparelhos/appliances e containers** com Java embutido | o Java vem "escondido" dentro do produto |

**Regra de ouro:** se é **Java**, está **exposto na internet**, e roda num **servidor x86-64 moderno**,
coloque na lista para checar.

## 5. O que fazer — passo a passo simples ✅

1. **Faça a lista.** Anote todo lugar que roda Java (incluindo os "escondidos" em containers e appliances).
   Para cada um, anote a **versão do Java** e em **qual servidor/chip** roda.
2. **Veja se o chip é dos afetados.** No servidor Linux, rode:
   ```bash
   grep -m1 '^flags' /proc/cpuinfo | grep -qw avx512vbmi && echo "CHIP AFETADO" || echo "chip NAO afetado"
   ```
   Se disser "chip NAO afetado", **esse servidor está fora de perigo** para esta falha.
3. **Veja se a versão do Java é das afetadas.** São **OpenJDK 17.0.6+**, **21**, **25**, **27** (sem a
   correção). Java 8 e 11 "normais" **não** são afetados.
4. **Corrija (o mais importante):** atualize o Java para a versão com `.1` no fim
   (17.0.21.1 / 21.0.13.1 / 25.0.5.1 / 27.0.1.1) e **reinicie** os serviços.
5. **Se não der para atualizar agora**, ligue uma "trava" temporária no Java:
   `-XX:-UseBASE64Intrinsics` (desliga só o atalho com defeito). Depois que atualizar, pode tirar.
6. **Enquanto isso, vigie e barre na porta de entrada.** Use as regras do Detect4Shell no seu
   IDS/WAF (pasta [`regras/`](../regras)) para **detectar e bloquear** as mensagens Base64 quebradas
   — é exatamente o que a **CISA recomenda** para quem ainda não corrigiu.

## 6. Em uma frase

> Uma mensagem Base64 quebrada (tipo "64 letras A e um =") faz o motor do Java **derramar memória** e
> **derrubar o sistema** — só em chips modernos. **Atualize o Java**, e use o Detect4Shell para
> **vigiar a porta** enquanto isso. 🛡️

---

*Quer os detalhes técnicos? Veja [ANALISE.md](ANALISE.md). Quer usar as regras? Veja o
[README](../README.md).*
