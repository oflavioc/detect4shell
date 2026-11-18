package detect4shell;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Enumeration;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Detect4Shell — Servlet Filter defensivo contra o Java4Shell (CVE-2026-114938).
 *
 * <p>Roda DENTRO da JVM, depois do TLS e do parser do container, então inspeciona os valores
 * já decodificados pelo container. Isso o torna imune à evasão parser-differential de rede
 * ({@code %3D}, {@code \\u003d} em JSON, {@code &#61;} em XML/SAML) que engana regras de borda
 * que operam PRÉ-normalização. Rejeita (HTTP 400) qualquer header, parâmetro (query/form) ou
 * cookie cujo valor casa a FORMA do gatilho Base64-malformado — ANTES de a aplicação chamar
 * {@code Base64.getDecoder().decode(...)}.
 *
 * <p><b>Não substitui atualizar o JDK</b> (o controle definitivo — ver README §Mitigação).
 * É o controle compensatório de <i>boundary de aplicação</i> que a CISA recomenda para quem
 * ainda não corrigiu, complementando a flag de JVM {@code -XX:-UseBASE64Intrinsics} e as regras
 * de borda em {@code regras/}.
 *
 * <p><b>Escopo (seja honesto ao implantar):</b> cobre os sinks pré-auth documentados —
 * {@code Authorization} (Basic/Bearer), parâmetros de query e de corpo form (SAMLRequest/
 * SAMLResponse/RelayState) e cookies. NÃO inspeciona o corpo bruto de requisições JSON/XML
 * (para não consumir/quebrar o stream da app); para tokens Base64 dentro de um corpo JSON,
 * conte com a flag de JVM ou a regra de borda.
 *
 * <p><b>Namespace:</b> este arquivo usa {@code jakarta.servlet} (Tomcat 10+, Jetty 11+,
 * Spring Boot 3+). Para o legado {@code javax.servlet} (Tomcat 9-, Spring Boot 2.x), troque os
 * imports {@code jakarta.servlet.*} por {@code javax.servlet.*}; o resto do código é idêntico.
 *
 * <p><b>Modo:</b> por padrão BLOQUEIA (400). O init-param {@code mode=detectonly} apenas registra
 * em log e deixa passar — use por alguns dias para validar fluxos auth/SAML/JWT reais antes de negar.
 */
public final class Java4ShellFilter implements Filter {

    /**
     * Mesma FORMA canônica das regras do repo (regras/README.md): um run Base64 contíguo, nos dois
     * alfabetos ({@code +/} e url-safe {@code _-}), de {@code >=64} chars alinhado a quad, terminando
     * em UM {@code '='}. O {@code {16,}+} é possessivo = anti-ReDoS (sem backtracking O(N²) num valor
     * grande). {@code {16,}} casa 64 e 128 chars (os dois gatilhos documentados: JDK 21/25/27 e JDK 17).
     */
    private static final Pattern TRIGGER = Pattern.compile(
        "(?<![A-Za-z0-9+/_-])(?:[A-Za-z0-9+/_-]{4}){16,}+=(?![A-Za-z0-9+/_=-])");

    /** Comprimento mínimo do gatilho (64 corpo + 1 '='); pré-filtro barato antes do regex. */
    private static final int MIN_LEN = 65;

    private boolean blocking = true;

    @Override
    public void init(FilterConfig cfg) {
        String mode = cfg.getInitParameter("mode");
        if (mode != null && mode.equalsIgnoreCase("detectonly")) {
            blocking = false;
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
            throws IOException, ServletException {
        if (req instanceof HttpServletRequest) {
            String where = firstTrigger((HttpServletRequest) req);
            if (where != null) {
                req.getServletContext().log(
                    "[detect4shell] CVE-2026-114938 trigger-shape em " + where
                        + " de " + req.getRemoteAddr());
                if (blocking) {
                    HttpServletResponse http = (HttpServletResponse) resp;
                    http.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                    http.setContentType("text/plain; charset=utf-8");
                    http.getWriter().write("Bad Request\n");
                    return; // não chama a cadeia: a app nunca decodifica o gatilho
                }
            }
        }
        chain.doFilter(req, resp);
    }

    /** Retorna ONDE casou (header/param/cookie) ou {@code null}. Só inspeciona; não decodifica Base64. */
    private String firstTrigger(HttpServletRequest r) {
        Enumeration<String> names = r.getHeaderNames();
        if (names != null) {
            while (names.hasMoreElements()) {
                String h = names.nextElement();
                Enumeration<String> vals = r.getHeaders(h);
                while (vals != null && vals.hasMoreElements()) {
                    if (hit(vals.nextElement())) return "header:" + h;
                }
            }
        }
        // getParameterMap = query + corpo form (cobre SAMLRequest/SAMLResponse/RelayState).
        // Para content-type não-form (JSON/XML) o container não parseia params, então o stream
        // bruto NÃO é consumido aqui (não quebra @RequestBody etc.).
        for (Map.Entry<String, String[]> e : r.getParameterMap().entrySet()) {
            for (String v : e.getValue()) {
                if (hit(v)) return "param:" + e.getKey();
            }
        }
        Cookie[] cookies = r.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if (hit(c.getValue())) return "cookie:" + c.getName();
            }
        }
        return null;
    }

    private static boolean hit(String s) {
        return s != null && s.length() >= MIN_LEN && TRIGGER.matcher(s).find();
    }

    @Override
    public void destroy() { }
}
