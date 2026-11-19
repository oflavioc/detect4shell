# Detect4Shell — mitigação na aplicação (Servlet Filter)

Controle **compensatório de boundary de aplicação** contra o Java4Shell (CVE-2026-114938): um
Servlet Filter que rejeita a **forma do gatilho** Base64-malformado **antes** de a sua app chamar
`Base64.getDecoder().decode(...)`. É o controle que a **CISA recomenda** ("validar a entrada Base64
no boundary da aplicação") para quem ainda não corrigiu o JDK.

## As camadas de mitigação, em ordem de preferência

| # | Controle | Onde | Observação |
|---|---|---|---|
| 1 | **Atualizar o JDK** (builds `.1`) | runtime | **O controle definitivo.** Ver [README §Mitigação](../README.md#mitigação-para-reportar-a-donos-de-ativos). |
| 2 | **Flag de JVM** `-XX:-UseBASE64Intrinsics` | runtime | Zero código, desliga só o intrínseco vulnerável. Validada (product/default). |
| 3 | **Servlet Filter** (este diretório) | aplicação | Dentro da JVM, **fecha a evasão `%3D`** (params); não vê `&#61;`/`\u003d` de corpos. Defense-in-depth. |
| 4 | **Regra de borda (WAF/proxy)** | rede | [`../regras/`](../regras/) — FortiWeb, ModSecurity, nginx, AWS/Cloudflare. Pré-normalização. |

> Por que o filtro (camada 3) e não só a regra de borda (camada 4)? O filtro roda **depois do parser
> do container**, então vê os **params já URL-decodificados** → **fecha a evasão `%3D`** que passa por
> regras de rede pré-normalização. ⚠️ Mas ele **não** decodifica entidades XML/SAML (`&#61;`) nem escapes
> JSON (`\u003d`) — esses só são resolvidos **downstream** (Jackson / parser XML), *depois* do filtro;
> para eles o controle é a **flag de JVM** (camada 2) ou o patch. Não é "imune a tudo".

## O Servlet Filter — [`Java4ShellFilter.java`](Java4ShellFilter.java)

Inspeciona cada request e, se um header, **segmento de path**, parâmetro (query/form) ou cookie casar a
forma do gatilho, responde **HTTP 400** (ou só loga, em `mode=detectonly`). Usa **o mesmo padrão canônico**
das regras
do repo ([regras/README.md](../regras/README.md)), com quantificador possessivo (anti-ReDoS).

**Escopo (honesto):** cobre os sinks pré-auth documentados — `Authorization` (Basic/Bearer),
parâmetros de query e de corpo **form** (SAMLRequest/SAMLResponse/RelayState), cookies e **segmentos do
PATH da URL** (ver abaixo). **Não** lê o corpo bruto de JSON/XML: o container não parseia esses
content-types em params, então o filtro não toca o stream deles — para um token Base64 dentro de um corpo
JSON, conte com a **flag de JVM** (camada 2) ou a **regra de borda**.

> **Cobertura de PATH (segmento de caminho).** Apps que **Base64-decodam um segmento do path**
> (`/download/<b64>`, ids REST codificados) têm um pré-sink que **não** aparece em header/param/cookie. O
> filtro inspeciona `getRequestURI()`/`getPathInfo()` **quebrando o caminho em segmentos** (split `/`) e
> rodando a forma em cada um — no cru **e** no URL-decodificado (fecha a evasão `%3D` no path). A
> segmentação é **necessária**: o gatilho canônico tem lookbehind `(?<![A-Za-z0-9+/_-])` que exclui `/`
> (o `/` é do alfabeto Base64 padrão), então um run colado no separador de path não casaria a URI inteira
> — isolado por segmento, ele casa. Roda nos **dois** modos (a URI não é o corpo: não consome o stream,
> não é afetada por `skipFormBody`).

> **Se a sua app é JSON-API-first, o filtro (camada 3) cobre pouco** — a maior parte do payload entra
> por um corpo JSON que ele não inspeciona. **Priorize a camada 1 (patch) e a camada 2 (flag de JVM).**

**⚠️ Dois footguns de produção** (porque o filtro chama `getParameterMap()` cedo, em
`HIGHEST_PRECEDENCE`). Em POST `application/x-www-form-urlencoded`/multipart, pedir os params faz o
container **parsear o corpo** — e isso tem dois efeitos colaterais não óbvios:

1. **Consome o input stream.** Os params seguem acessíveis via `getParameter*` (o container cacheia) —
   quem lê params do jeito normal **não** quebra; mas quem lê o **corpo bruto** depois
   (`getInputStream()`/`getReader()`: verificação de **HMAC sobre o corpo**, algumas implementações de
   **SAML POST-binding**, parsers custom) acha o stream **vazio** e quebra. Como SAML é alvo explícito
   deste filtro, **valide o seu fluxo SAML POST antes de ligar o bloqueio**.
2. **Trava o charset.** Parsear params fixa o character-encoding da requisição. Se o filtro rodar
   **antes** do `CharacterEncodingFilter` da app, o default é travado e um `setCharacterEncoding()`
   posterior não surte mais efeito → **mojibake** em valores de form não-ASCII.

**Como conviver com os dois:** ordene o filtro **logo após** o `CharacterEncodingFilter` (ele só precisa
preceder o **sink de Base64**, não o setter de encoding) ou chame `setCharacterEncoding()` você mesmo; e
rode em **`mode=detectonly`** tempo suficiente para pegar **regressões de encoding/stream** antes de
negar. Em último caso, o init-param **`skipFormBody=true`** liga o modo **stream-safe** — não toca no
corpo (inspeciona só header/cookie/query-string/**path**), evitando ambos os footguns. **Lacuna honesta
desse modo:** params de **corpo** (SAML POST-binding `SAMLResponse`/`RelayState`) deixam de ser vistos —
nesse modo a cobertura de corpo fica com a camada 1 (patch) / 2 (flag de JVM); header, cookie,
**query-string** (com a evasão `%3D` fechada via URL-decode) e **segmento de path** continuam cobertos.

**Validação:** o **padrão TRIGGER** é byte-idêntico ao canônico (`regras/README.md`) e o **CI garante
isso a cada push** via o drift-guard [`testes/canonical_sync.py`](../testes/canonical_sync.py) — logo é
exercido nos motores reais (pcre2/re2/yara) pela matriz [`testes/per-engine/`](../testes/per-engine/) e
pela unidade [`testes/validar.py`](../testes/validar.py) (**16/16**, 0 falso-positivo).

O filtro **compila com `javac` 21** e passa um **harness funcional auto-contido de 13 cenários**
([`test/Java4ShellFilterTest.java`](test/Java4ShellFilterTest.java); rode com `bash mitigacao/test/run.sh`).
O harness compila a classe **real** contra **stubs inline de `jakarta.servlet`** ([`test/jakarta/`](test/jakarta/)
— só a superfície que o filtro usa: `getParameterMap`/`getMethod`/`getContentType`/`getQueryString`/
`getHeaders`/`getCookies`/`getRequestURI`/`getPathInfo`, assinaturas idênticas em `jakarta.servlet` 6.0 e
`javax.servlet` 4.0.1), **sem Maven e sem baixar a servlet-api**, e exercita o filtro com requisições fake.
Os 13 cenários cobrem default × `skipFormBody` × `detectonly`: gatilho no corpo form (bloqueia no default;
**lacuna esperada** no stream-safe), na query (inclusive a evasão `%3D`), em `Authorization`, em cookie e em
**segmento de PATH** (`/download/<b64>`, inclusive `%3D`); GET benigno, corpo JSON (não parseado em params)
e o corpo-form no modo stream-safe passam. `exit != 0` em qualquer falha. O harness **está** no gate automático (`test.sh`) como o **tier 3/7** (só JDK, sem Docker) — ver
[`test/README.md`](test/README.md).

### Como implantar

**1. Jakarta (Tomcat 10+/Jetty 11+/Spring Boot 3+)** — use o arquivo como está (`jakarta.servlet`).
**Legado javax (Tomcat 9-/Spring Boot 2.x):** troque os imports `jakarta.servlet.*` por
`javax.servlet.*` (o resto é idêntico; ambos compilam).

Coloque o `.java` na sua árvore de fontes sob o pacote `detect4shell` e compile com a
`servlet-api` como `provided` (o container já a fornece). Ex. Maven:
```xml
<dependency>
  <groupId>jakarta.servlet</groupId>
  <artifactId>jakarta.servlet-api</artifactId>
  <version>6.0.0</version>
  <scope>provided</scope>
</dependency>
```

**2a. Wiring por `web.xml`** — ver [`web.xml`](web.xml) (cole dentro do seu `<web-app>`).

**2b. Wiring por Spring Boot 3 (`@Bean`)** — sem `web.xml`:
```java
import detect4shell.Java4ShellFilter;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class Detect4ShellConfig {
    @Bean
    public FilterRegistrationBean<Java4ShellFilter> java4ShellFilter() {
        FilterRegistrationBean<Java4ShellFilter> reg = new FilterRegistrationBean<>();
        reg.setFilter(new Java4ShellFilter());
        reg.addUrlPatterns("/*");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE + 1); // LOGO APÓS o CharacterEncodingFilter (que fica
                                                      // em HIGHEST_PRECEDENCE) p/ não travar o charset;
                                                      // ainda antes do decode de Base64 da app.
        // reg.addInitParameter("mode", "detectonly");   // opcional: só logar primeiro (dias) p/ pegar
        //                                                // regressões de encoding/stream antes de negar
        // reg.addInitParameter("skipFormBody", "true"); // opcional: stream-safe — não lê o corpo form
        //                                                // (não quebra HMAC/SAML-POST), mas perde params de corpo
        return reg;
    }
}
```

### Ordem de implantação recomendada
0. **Posicione o filtro logo após o `CharacterEncodingFilter`** da app (não antes) — ele só precisa
   preceder o **sink de Base64**, não o setter de encoding; isso evita a trava de charset (footgun #2).
   Se a app lê o **corpo bruto** de POSTs form (HMAC sobre o corpo, SAML POST-binding por assinatura),
   use `skipFormBody=true` **ou** garanta que este filtro não roda antes desse leitor (footgun #1).
1. Suba com `mode=detectonly` e observe os logs `[detect4shell]` por alguns dias — tempo suficiente para
   pegar **regressões de encoding/stream** (um Base64 malformado nunca é exigido por um cliente correto,
   mas valide auth/SAML/JWT reais **e** os fluxos que leem o corpo).
2. Remova o `detectonly` para **bloquear** (400).
3. Em paralelo, **atualize o JDK** (camada 1 — o controle definitivo).
