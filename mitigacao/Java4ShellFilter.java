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
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Detect4Shell — Servlet Filter defensivo contra o Java4Shell (CVE-2026-114938).
 *
 * <p>Roda DENTRO da JVM, depois do TLS e do parser do container. Vê os parâmetros query/form
 * já URL-decodificados, então FECHA a evasão {@code %3D} que passa por regras de borda PRÉ-
 * normalização. ⚠️ NÃO decodifica entidades XML/SAML ({@code &#61;}) nem escapes JSON
 * ({@code \\u003d}) — esses só são resolvidos downstream (Jackson / parser XML), depois do filtro;
 * para eles use a flag de JVM ou o patch. Rejeita (HTTP 400) qualquer header, <b>segmento de PATH</b>,
 * parâmetro (query/form) ou cookie cujo valor casa a FORMA do gatilho Base64-malformado — ANTES de a
 * aplicação chamar {@code Base64.getDecoder().decode(...)}.
 *
 * <p><b>Não substitui atualizar o JDK</b> (o controle definitivo — ver README §Mitigação).
 * É o controle compensatório de <i>boundary de aplicação</i> que a CISA recomenda para quem
 * ainda não corrigiu, complementando a flag de JVM {@code -XX:-UseBASE64Intrinsics} e as regras
 * de borda em {@code regras/}.
 *
 * <p><b>Escopo (seja honesto ao implantar):</b> cobre os sinks pré-auth documentados —
 * {@code Authorization} (Basic/Bearer), parâmetros de query e de corpo form (SAMLRequest/
 * SAMLResponse/RelayState), cookies e <b>segmentos do PATH da URL</b> ({@code /download/<b64>}, ids REST
 * codificados — ver {@code pathTrigger}, inspecionado nos dois modos). NÃO lê o corpo bruto de requisições
 * JSON/XML: o container não parseia esses content-types em params, então o {@code getParameterMap()} abaixo
 * não toca o
 * stream deles — para um token Base64 dentro de um corpo JSON, conte com a flag de JVM ou a regra
 * de borda. ⚠️ MAS atenção: em POST {@code form-urlencoded}/multipart o {@code getParameterMap()}
 * <b>consome</b> o corpo, com dois efeitos de produção — ver o bloco "Dois footguns" abaixo.
 *
 * <p><b>Namespace:</b> este arquivo usa {@code jakarta.servlet} (Tomcat 10+, Jetty 11+,
 * Spring Boot 3+). Para o legado {@code javax.servlet} (Tomcat 9-, Spring Boot 2.x), troque os
 * imports {@code jakarta.servlet.*} por {@code javax.servlet.*}; o resto do código é idêntico.
 *
 * <p><b>⚠️ Dois footguns de produção (leia ANTES de pôr em {@code HIGHEST_PRECEDENCE}):</b> como o
 * filtro chama {@code getParameterMap()} cedo, em POST {@code application/x-www-form-urlencoded} (e
 * multipart) ele dispara o parse do corpo, e isso tem dois efeitos colaterais não óbvios:
 * <ol>
 * <li><b>Consome o input stream.</b> Parsear o form LÊ o corpo. Os params seguem disponíveis via
 *     {@code getParameter*} (o container os cacheia) — quem lê params do jeito normal NÃO quebra;
 *     mas quem lê o <i>corpo bruto</i> depois ({@code getInputStream()}/{@code getReader()}:
 *     verificação de HMAC sobre o corpo, algumas implementações de SAML POST-binding, parsers
 *     custom) encontra o stream VAZIO e quebra. Como SAML é alvo explícito deste filtro, valide o
 *     seu fluxo SAML POST antes de ligar o bloqueio.</li>
 * <li><b>Trava o charset.</b> Parsear params fixa o character-encoding da requisição. Se este filtro
 *     rodar ANTES do {@code CharacterEncodingFilter} da app, o encoding default é travado e um
 *     {@code setCharacterEncoding()} posterior não surte mais efeito → <i>mojibake</i> em valores de
 *     form não-ASCII.</li>
 * </ol>
 * Mitigação dos dois: ordene este filtro LOGO APÓS o {@code CharacterEncodingFilter} (ele só precisa
 * preceder o <i>sink</i> de Base64, não o setter de encoding) ou chame {@code setCharacterEncoding()}
 * você mesmo; e rode em {@code mode=detectonly} tempo suficiente para pegar regressões de
 * encoding/stream. Em último caso, o init-param {@code skipFormBody=true} evita ambos (não toca no
 * corpo: inspeciona só header/cookie/query-string/path) — ao custo de NÃO ver params de corpo (SAML
 * POST-binding), que nesse modo ficam a cargo da camada 1 (patch) / 2 (flag de JVM).
 *
 * <p><b>Init-params:</b> {@code mode=detectonly} só loga e deixa passar (use por alguns dias para
 * validar fluxos auth/SAML/JWT reais antes de negar); o padrão BLOQUEIA (400). {@code skipFormBody=true}
 * liga o modo stream-safe do footgun acima (não consome o corpo; perde a cobertura de params de corpo).
 */
public final class Java4ShellFilter implements Filter {

    /**
     * Mesma FORMA canônica das regras do repo (regras/README.md): um run Base64 contíguo de alfabeto
     * PURO (padrão {@code +/} OU url-safe {@code _-}, nunca misto — o intrínseco usa um só), de
     * {@code >=64} chars alinhado a quad, terminando em 1 OU 2 {@code '='} (lab: {@code A*64+"=="}
     * também dispara; aceitar só um '=' era bypassável). O {@code {16,}+} é possessivo = anti-ReDoS.
     * {@code {16,}} casa 64 e 128 chars (JDK 21/25/27 e JDK 17).
     */
    private static final Pattern TRIGGER = Pattern.compile(
        "(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}+|(?:[A-Za-z0-9_-]{4}){16,}+)={1,2}(?![A-Za-z0-9+/_=-])");

    /** Comprimento mínimo do gatilho (64 corpo + 1 '='); pré-filtro barato antes do regex. */
    private static final int MIN_LEN = 65;

    private boolean blocking = true;

    /**
     * Modo stream-safe (opt-in). Quando {@code true}, requisições POST form-urlencoded/multipart são
     * inspecionadas SÓ no header/cookie/query-string/path — o corpo NÃO é lido (não consome o stream, não
     * trava o charset). Default {@code false} = comportamento completo (inclui params de corpo). O
     * segmento de PATH é inspecionado nos DOIS modos (ver {@code pathTrigger}).
     */
    private boolean skipFormBody = false;

    @Override
    public void init(FilterConfig cfg) {
        String mode = cfg.getInitParameter("mode");
        if (mode != null && mode.equalsIgnoreCase("detectonly")) {
            blocking = false;
        }
        skipFormBody = "true".equalsIgnoreCase(cfg.getInitParameter("skipFormBody"));
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

    /** Retorna ONDE casou (header/path/param/cookie) ou {@code null}. Só inspeciona; não decodifica Base64. */
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
        // Segmento de PATH (finding #7): apps que Base64-decodam um segmento de caminho (/download/<b64>,
        // ids REST codificados) têm um pré-sink invisível a header/param/cookie. Roda nos DOIS modos — a
        // URI/pathInfo não é o corpo, então não consome o stream nem é afetada por skipFormBody. Ver
        // pathTrigger(): segmenta por '/' porque o '/' pertence ao alfabeto Base64 e quebra o lookbehind.
        String path = pathTrigger(r.getRequestURI(), r.getPathInfo());
        if (path != null) return path;
        // getParameterMap = query + (POST form) corpo; cobre SAMLRequest/SAMLResponse/RelayState.
        // Content-type não-form (JSON/XML): o container não parseia params → o corpo bruto NÃO é
        // tocado aqui (não quebra @RequestBody). ⚠️ MAS em POST form-urlencoded/multipart isso CONSOME
        // o input stream (ver Javadoc, footgun #1). skipFormBody=true pula o corpo nesses POSTs e
        // inspeciona só a query-string — LACUNA: params de corpo (SAML POST-binding) ficam de fora.
        if (skipFormBody && consumesBody(r)) {
            String q = queryStringTrigger(r.getQueryString());
            if (q != null) return q;
        } else {
            for (Map.Entry<String, String[]> e : r.getParameterMap().entrySet()) {
                for (String v : e.getValue()) {
                    if (hit(v)) return "param:" + e.getKey();
                }
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

    /**
     * Inspeciona o PATH da URL (finding #7) — fecha o pré-sink de apps que Base64-decodam um SEGMENTO de
     * caminho ({@code /download/<b64>}, ids REST codificados), que não aparece em header/param/cookie.
     * <p>O gatilho canônico tem lookbehind {@code (?<![A-Za-z0-9+/_-])} que EXCLUI {@code '/'} (o {@code '/'}
     * é do alfabeto padrão Base64), então um run colado no separador de path jamais casaria a URI inteira;
     * por isso quebramos o caminho em SEGMENTOS (split {@code '/'}) e rodamos a forma em cada um — no cru E
     * no URL-decodificado (fecha a evasão {@code %3D} num segmento de path). Usa {@code getRequestURI()}
     * (cru, cobre todo o caminho) e {@code getPathInfo()} (já decodificado pelo container). Retorna
     * {@code "path"} ou {@code null}.
     */
    private static String pathTrigger(String requestUri, String pathInfo) {
        if (segmentHit(requestUri)) return "path";
        // getPathInfo() já vem URL-decodificado pelo container; só re-checa se difere da URI crua.
        if (pathInfo != null && !pathInfo.equals(requestUri) && segmentHit(pathInfo)) return "path";
        return null;
    }

    /**
     * {@code true} se ALGUM segmento (split {@code '/'}) do caminho casa a forma do gatilho — no valor cru
     * OU no URL-decodificado (fecha {@code %3D}). Segmentar é o que habilita o match: isolado do {@code '/'},
     * o início do segmento satisfaz o lookbehind do gatilho. Só inspeciona; não decodifica Base64.
     */
    private static boolean segmentHit(String path) {
        if (path == null || path.isEmpty()) return false;
        for (String seg : path.split("/")) {
            if (seg.isEmpty()) continue;
            if (hit(seg)) return true;
            String dec = safeDecode(seg);
            if (!dec.equals(seg) && hit(dec)) return true;
        }
        return false;
    }

    /**
     * POST cujo corpo o container parsearia em params (form-urlencoded ou multipart) — nesses casos
     * {@code getParameterMap()} leria e CONSUMIRIA o corpo. Conservador: trata multipart como
     * consumidor mesmo quando (sem {@code @MultipartConfig}) o container não o parsearia — preferimos
     * nunca arriscar consumir o stream a arriscar quebrá-lo.
     */
    private static boolean consumesBody(HttpServletRequest r) {
        if (!"POST".equalsIgnoreCase(r.getMethod())) return false;
        String ct = r.getContentType();
        if (ct == null) return false;
        ct = ct.toLowerCase(Locale.ROOT);
        return ct.startsWith("application/x-www-form-urlencoded") || ct.startsWith("multipart/");
    }

    /**
     * Inspeciona APENAS a query-string crua (sem tocar o corpo). Para cada valor checa a forma no cru
     * E no URL-decodificado — o cru pega o '+'/'/' literais do alfabeto padrão e o decodificado fecha
     * a evasão {@code %3D}/{@code %2B}. Percent-encoding inválido cai para o cru (o regex ainda roda).
     * Retorna {@code "query:<chave>"} ou {@code null}.
     */
    private static String queryStringTrigger(String qs) {
        if (qs == null || qs.isEmpty()) return null;
        for (String pair : qs.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq >= 0 ? pair.substring(0, eq) : pair;
            String val = eq >= 0 ? pair.substring(eq + 1) : "";
            if (hit(val)) return "query:" + safeDecode(key);
            String dec = safeDecode(val);
            if (!dec.equals(val) && hit(dec)) return "query:" + safeDecode(key);
        }
        return null;
    }

    /**
     * URL-decode tolerante: em encoding malformado devolve a string crua (fail-open só naquele token).
     * Usa o overload {@code (String,String)} (Java 1.4+) p/ manter a portabilidade do filtro no legado
     * javax/Java 8 — o overload {@code (String,Charset)} só existe no Java 10+. "UTF-8" é sempre suportado,
     * então o {@code UnsupportedEncodingException} nunca dispara na prática (mas é checked, logo tratado).
     */
    private static String safeDecode(String s) {
        try {
            return URLDecoder.decode(s, "UTF-8");
        } catch (UnsupportedEncodingException | IllegalArgumentException ex) {
            return s;
        }
    }

    @Override
    public void destroy() { }
}
