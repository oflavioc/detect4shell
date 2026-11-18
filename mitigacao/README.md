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

Inspeciona cada request e, se um header, parâmetro (query/form) ou cookie casar a forma do gatilho,
responde **HTTP 400** (ou só loga, em `mode=detectonly`). Usa **o mesmo padrão canônico** das regras
do repo ([regras/README.md](../regras/README.md)), com quantificador possessivo (anti-ReDoS).

**Escopo (honesto):** cobre os sinks pré-auth documentados — `Authorization` (Basic/Bearer),
parâmetros de query e de corpo **form** (SAMLRequest/SAMLResponse/RelayState) e cookies. **Não**
inspeciona o corpo bruto de JSON/XML (para não consumir/quebrar o stream da app); para um token
Base64 dentro de um corpo JSON, conte com a **flag de JVM** (camada 2) ou a **regra de borda**.

**Validação:** o **padrão TRIGGER** é byte-idêntico ao canônico (`regras/README.md`) e o **CI garante
isso a cada push** via o drift-guard [`testes/canonical_sync.py`](../testes/canonical_sync.py) — logo é
exercido nos motores reais (pcre2/re2/yara) pela matriz [`testes/per-engine/`](../testes/per-engine/).
A **compilação completa** do filtro foi verificada manualmente em `jakarta.servlet` 6.0.0 **e**
`javax.servlet` 4.0.1; spot-check do padrão no motor de regex do Java = **10/10** (gatilho de 64 e 128
chars, os dois alfabetos, `Authorization` **e `==`** casam; path REST misto, 3-pad, base64 válido,
JWT-like e `<64` chars **não**).

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
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE); // antes de qualquer decode da app
        // reg.addInitParameter("mode", "detectonly"); // opcional: só logar primeiro
        return reg;
    }
}
```

### Ordem de implantação recomendada
1. Suba com `mode=detectonly` e observe os logs `[detect4shell]` por alguns dias (um Base64
   malformado nunca é exigido por um cliente correto, mas valide auth/SAML/JWT reais).
2. Remova o `detectonly` para **bloquear** (400).
3. Em paralelo, **atualize o JDK** (camada 1 — o controle definitivo).
