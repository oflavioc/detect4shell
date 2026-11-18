# Detect4Shell — FAQ (perguntas frequentes sobre o Java4Shell / CVE-2026-114938)

_Segurança Descomplicada: respostas diretas, sem hype e sem minimizar._ Se você só tem 1 minuto, leia a
pergunta 1 e a regra de ouro no fim.

> **A regra de ouro — três coisas DIFERENTES (não confunda):**
> 1. **Banner/versão** = o software/JDK *parece* afetado. É só um **candidato**.
> 2. **Match de regra** (WAF/IDS/filtro) = alguém *mandou a forma do ataque*. Não prova que funcionaria.
> 3. **O bug de verdade** = corrupção de memória, que só ocorre com **CPU + JDK + sink** certos.
>
> Um WAF **bloquear** não prova que o host era explorável. **Não** bloquear não prova que era seguro.
> Um scanner achar a versão **não** confirma o bug. Decida pelo predicado 3, não pelo 1 ou 2.

---

## É hype ou é real? (os dois memes que estão circulando)

Dois profissionais de segurança, **dois extremos opostos** — e a verdade está no meio.

- 🔥 **Lado ofensivo — "RCE / root em 15 minutos, corra!"** (infla). Foi um ataque **_data-only_ num
  alvo-demo próprio**, com *heap grooming* + container rodando como root + uma feature admin que executa
  comando — **não** um RCE nativo, não-autenticado e genérico caindo em Keycloak/Jira de fábrica (ver
  pergunta 5).
- 🥱 **Lado defensivo-vendor — "é só um bug de assembly C++ que roda em chips específicos, pânico inútil"**
  (deflaciona). Está **mais certo que errado** — o nome "4Shell" realmente infla —, mas exagera a dose em
  dois pontos:
  1. **"chips específicos" não é exótico.** AVX-512 **VBMI** = Intel **Ice Lake (2019+)** e AMD **Zen 4**
     = **mainstream em servidor e nuvem modernos**. (Imunes de verdade: **ARM/Graviton**, e **Xeon
     Skylake-SP / Cascade Lake** — têm `avx512f` mas **não** `avx512vbmi`.)
  2. **"só um bug de assembly"** subestima: é **remotamente alcançável pré-auth** (Base64 em auth/SAML) e
     **já demonstrou DoS + vazamento de heap**. Academicamente low-level; operacionalmente, um **DoS remoto**.

**Por que cada lado puxa pro seu extremo?** Incentivo. O pesquisador **ofensivo** ganha visibilidade com
"RCE em 15 min, a janela encolhe"; o **vendor de SAST / scan de dependência** ganha com "bug de runtime não
importa" — e, de fato, esse tipo de ferramenta **não enxerga** este bug, porque ele é **runtime + CPU, não
classpath**. Nenhum dos dois é desonesto; cada um olha pela própria lente.

**A verdade (medida em lab):** o **rótulo "4Shell" é hype** (não é Log4Shell — aquilo era RCE pré-auth
trivial e universal), mas o **bug é real e condicional** — um primitivo de **DoS + leak** remoto nas frotas
x86 modernas sem patch, com RCE genérico **não** reproduzido publicamente contra produtos stock. **Nem fim
do mundo, nem _nothingburger_. Corrija o JDK e siga a vida.**

---

## 1. "Estou vulnerável?" — a árvore de decisão (3 portões, TODOS precisam ser sim)

```
┌─ A CPU é x86-64 com AVX-512 VBMI?  (Intel Ice Lake+ / AMD Zen 4+)
│     ARM/Graviton = NÃO · Xeon Skylake/Cascade Lake (1ª/2ª ger) = NÃO (têm avx512f, mas NÃO vbmi)
│        │ não → IMUNE (pare aqui)
│        ▼ sim
├─ O JDK é OpenJDK 17.0.6+ / 21 / 25 / 27 ANTES do build de correção `.1`?
│     Java 8/11 padrão = NÃO · build `.1` (ex. 21.0.13.1) = corrigido = NÃO
│        │ não → não afetado por este bug (pare)
│        ▼ sim
└─ A app passa uma string controlada pelo atacante para `Base64.getDecoder()` / `getUrlDecoder()`
   num caminho PRÉ-autenticação? (Basic/Bearer, SAML, cookie, parâmetro)
         │ não/incerto → superfície baixa; corrija mesmo assim quando puder
         ▼ sim
   → EXPOSTO. Priorize corrigir o JDK. Use as regras do Detect4Shell como controle compensatório.
```

## 2. Como checo se minha CPU tem AVX-512 VBMI?

- **Linux:** `grep -o 'avx512vbmi' /proc/cpuinfo | head -1` → se imprimir `avx512vbmi`, tem. (Cheque
  **vbmi** especificamente — `avx512f` sozinho **não** basta.)
- **Windows:** rode o reprodutor confinado do repo via WSL ou Docker (`laboratorio/`), ou use uma
  ferramenta de CPU-ID. O `laboratorio/verificar_patch.sh` faz o teste empírico (Linux/WSL).
- **Regra prática:** Intel **Ice Lake** (2019+) e posteriores, AMD **Zen 4** (Ryzen 7000 / EPYC 9004+)
  têm VBMI. **Skylake-SP/Cascade Lake, ARM, Graviton, a maioria das VMs com AVX-512 mascarado = imunes.**

## 3. O scanner (`scanner/`) achou uma "versão vulnerável". Confirmei o bug?

**Não.** O scanner é **passivo** e só lê **banner/versão** — é o predicado 1 (candidato). Ele **não** sabe
a CPU, se o intrínseco está ativo, nem se há um sink alcançável. Confirme no **próprio host** (CPU + build
do JDK). Trate o resultado como "vale investigar", não como "está vulnerável".

## 4. O WAF/filtro bloqueou um request. Eu estava sendo hackeado? Era explorável?

**Não necessariamente.** Um match significa que **a forma do gatilho passou na rede** — pode ser scan,
pesquisa, ou um falso-positivo raro. **Não** prova que o backend era explorável (precisa dos 3 portões).
E o contrário também vale: **não bloquear não prova que você está seguro** (a forma pode vir ofuscada, ou
o host pode estar vulnerável sem ninguém ter tentado). Correlacione com sinais de **host** (exceções de
`Base64`, crash) e **corrija o JDK**.

## 5. Vi um post: "fizeram RCE / root em 15 minutos". É o fim do mundo?

**Calma — leia o que foi de fato demonstrado.** Publicamente houve um **ataque _data-only_** (um
pesquisador, assistido por IA) num **alvo-demo construído por ele**: corromper o heap → ganhar leitura/
escrita → virar `admin`/sessão → e o "root" veio de o **container rodar como root + uma feature admin que
executa comando**. Isso é real e impressionante, **mas**:
- É num **alvo controlado** com *heap grooming* (a escrita OOB é **heap-dependente** — ver pergunta 8).
- **Não** é um "RCE nativo, não-autenticado, genérico" caindo em cima de Keycloak/Jira de fábrica.
- As precondições (R/W groomável + booleano de authz pra flipar + feature de exec / container root) são
  **muitas e específicas**.

**Resumo honesto:** o risco demonstrado hoje é **DoS** (derrubar) e **vazamento de heap**; RCE genérico
contra produtos stock **não** foi reproduzido publicamente. **Corrija assim mesmo.**

## 6. "Base64 está em todo lugar no Java — então o bug está em todo lugar?"

**Não.** O bug é num **intrínseco específico** (AVX-512 VBMI) de uma **ISA específica** (x86-64 com VBMI),
num **conjunto de versões** do OpenJDK, num **sink específico** (`getDecoder`/`getUrlDecoder`). A maioria
das JVMs corporativas **não** está nesse caminho: ARM na nuvem, Xeon sem VBMI, quem usa `getMimeDecoder`
ou uma lib de Base64 de terceiros, ou só processa Base64 bem-formado. "Base64 em todo lugar" ≠ "bug em
todo lugar".

## 7. E o `getMimeDecoder()` / Base64 com quebra de linha?

- **`Base64.getMimeDecoder()` NÃO é vulnerável.** Só `getDecoder` (Basic) e `getUrlDecoder` são.
- **Mas atenção:** se a sua app faz `string.replaceAll("\\s+","")` (remove espaços/quebras) e **depois**
  chama `getDecoder().decode(...)` — comum em processadores XML/SAML — então um payload com `\r\n` no meio
  **passa** pela regra de rede (que casa a forma contígua) e é remontado antes do sink. Para esse caso,
  o controle é a **flag de JVM** ou o **patch**, não só a regra de borda.

## 8. A tal "escrita OOB de 62 bytes" sempre acontece?

**Não — é HEAP-DEPENDENTE.** Em lab (mesmo input, mesma máquina): o reprodutor oficial estoura **100%**
(padrão de alocação fixo), mas um loop com arrays frescos estoura **~0%**. A escrita de 62 bytes só se
completa quando a memória **logo após** o buffer de decode contém bytes Base64 válidos. Por isso:
- o **crash (DoS) é probabilístico** (a escrita quase sempre cai em área de heap não usada);
- um **exploit confiável precisa de _heap grooming_** (arrumar o heap de propósito);
- o `oob_write=62` do nosso demo é um **sinal de lab** (usamos o padrão do reprodutor), **não** um IoC
  de produção.

## 9. Qual a diferença entre patch, flag de JVM, filtro e WAF? Por qual começo?

| Ordem | Controle | O que faz | Observação |
|---|---|---|---|
| 1 | **Atualizar o JDK** (`.1`) | Corrige a causa raiz | **Definitivo.** O resto é stopgap. |
| 2 | **`-XX:-UseBASE64Intrinsics`** | Desliga só o intrínseco vulnerável | Zero código, validado; pequena perda de perf em decode pesado. |
| 3 | **Servlet Filter** (`mitigacao/`) | Rejeita a forma no boundary da app | Dentro da JVM; fecha `%3D`, mas não `&#61;`/`=` de corpos. |
| 4 | **Regra de WAF/IDS** (`regras/`) | Barra a forma na rede | Pré-normalização; comece em alert/count. |

## 10. A regra vai encher meu SIEM de falso-positivo?

Raramente. A forma casada (um bloco Base64 de 64+ chars alinhado a quad + `=`/`==`) é
**sintaticamente inválida** como Base64 (comprimento `4n+1`/`4n+2`), então **Base64 legítimo quase nunca
casa**. Ainda assim: **comece em modo observação** (IDS=alert, WAF=count, SIEM=evento) por alguns dias,
valide fluxos **auth/SAML/JWT** reais, e só então ligue o bloqueio. Candidatos benignos a observar:
data-URIs, URLs pré-assinadas S3/GCS, tokens de analytics longos.

## 11. O gatilho é só `AAAA…A=`?

Não. O **AAAA…=** é o PoC público, mas a detecção é **estrutural**: qualquer run de **64 chars** Base64
(alfabeto padrão `+/` **ou** url-safe `_-`) + **1 ou 2 `=`** — **128 chars** no JDK 17. (Em lab, só
`64±'='`/`'=='` alinhado dispara; sem-`=` e comprimentos não-alinhados não. A regra é ampla de propósito,
para pegar variantes.) As regras do Detect4Shell cobrem os dois alfabetos, SAML/JWT/cookie/param — não só
Basic auth e não só a string exata de "A".

## 12. Isto é uma ferramenta de ataque? Posso usar em produção?

**É 100% defensiva.** Só **detecção + prevenção + verificação de patch**. A única parte que roda o gatilho
é uma **reprodução local confinada** (escrita dentro de um array do próprio programa, offline). Não há
exploit, nem cadeia weaponizada, nem nada que dispare a corrupção contra um alvo remoto. Use nas suas
próprias defesas e em sistemas que você está autorizado a testar.

---

**Ainda em dúvida? A ação certa quase sempre é a mesma: _atualize o JDK para o build `.1`._** Tudo o mais
é para ganhar tempo enquanto você corrige. Veja o [README](../README.md) e a
[EXPLICACAO-SIMPLES](EXPLICACAO-SIMPLES.md).
