# Harness funcional do `Java4ShellFilter` (auto-contido)

Prova — compilável e executável **dentro do repo**, sem Maven e sem baixar a `servlet-api` — da
afirmação do [`mitigacao/README.md`](../README.md): o filtro **compila com `javac` 21** e **passa um
harness funcional**. É um teste JUnit-free, zero-dependência: só precisa de um **JDK** (`javac` + `java`)
no `PATH`. Validado com `javac`/`java` 21.

## Rodar

```bash
bash mitigacao/test/run.sh      # a partir da raiz do repo (ou de qualquer lugar: o script se reposiciona)
```

Saída esperada (resumo): `Resultado: 13/13 cenarios OK (0 falha(s))` e **exit 0**. Qualquer cenário que
falhe imprime `[FAIL] ...` e o processo sai com **exit != 0** (serve de gate de regressão).

## Como é auto-contido

`jakarta.servlet` **não** é baixado. [`jakarta/`](jakarta/) traz **stubs mínimos** — só os tipos e
métodos que o filtro consulta, com assinaturas **idênticas** a `jakarta.servlet` 6.0 e `javax.servlet`
4.0.1:

| Stub | Superfície (o que o filtro usa) |
|---|---|
| `jakarta/servlet/Filter.java` | interface implementada (`init`/`doFilter`/`destroy`) |
| `jakarta/servlet/FilterChain.java` | `doFilter(req, resp)` (marca "deixou passar") |
| `jakarta/servlet/FilterConfig.java` | `getInitParameter` (`mode`/`skipFormBody`) |
| `jakarta/servlet/ServletRequest.java` | `getParameterMap`/`getContentType`/`getRemoteAddr`/`getServletContext` |
| `jakarta/servlet/ServletResponse.java` | `setContentType`/`getWriter` |
| `jakarta/servlet/ServletContext.java` | `log` |
| `jakarta/servlet/ServletException.java` | tipo checked lançado |
| `jakarta/servlet/http/HttpServletRequest.java` | `getHeaderNames`/`getHeaders`/`getQueryString`/`getMethod`/`getCookies` + `getRequestURI`/`getPathInfo` |
| `jakarta/servlet/http/HttpServletResponse.java` | `setStatus` + `SC_BAD_REQUEST` |
| `jakarta/servlet/http/Cookie.java` | `getName`/`getValue` |

[`Java4ShellFilterTest.java`](Java4ShellFilterTest.java) implementa fakes desses stubs (request builder,
response que captura o status, chain que marca se foi chamada) e roda o filtro **real**
([`../Java4ShellFilter.java`](../Java4ShellFilter.java)) — o mesmo `.java` que você implanta.

## Os 13 cenários

Default (bloqueia 400): **1** corpo form `SAMLResponse` · **2** query `SAMLRequest` · **3** header
`Authorization` · **4** cookie · **5** segmento de PATH `/download/<b64>=` · **6** PATH com evasão `%3D` ·
**7** `Authorization` com dois pads `==` · **8** GET benigno passa · **9** corpo JSON (não parseado em
params) passa. `skipFormBody` (stream-safe): **10** corpo form **não** inspecionado — passa (lacuna
esperada) · **11** evasão `%3D` na query **ainda** pega · **12** PATH **ainda** pega. `detectonly`: **13**
gatilho só logado — passa.

Os cenários 5/6/12 cobrem a **inspeção de PATH** (segmento de caminho Base64): a URI inteira
(`/download/<b64>=`) **não** casa o gatilho canônico porque o `/` pertence ao alfabeto Base64 e cai no
lookbehind `(?<![A-Za-z0-9+/_-])`; por isso o filtro **quebra o path em segmentos** e roda a forma em cada
um, no cru e no URL-decodificado.

## No gate de CI

Este harness **está** no gate de regressão como o **tier 3/7** do [`../../test.sh`](../../test.sh)
(`bash mitigacao/test/run.sh`, só JDK, sem Docker): bloqueia o CI em qualquer cenário que falhe ou erro de
compilação. O workflow fixa o JDK 21 via `actions/setup-java@v4.7.1` (temurin) em
[`.github/workflows/test.yml`](../../.github/workflows/test.yml).
