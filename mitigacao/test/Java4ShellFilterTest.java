package detect4shell;

import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Harness funcional AUTO-CONTIDO do {@link Java4ShellFilter} — SEM Maven e SEM baixar a servlet-api.
 *
 * <p>Compila contra os STUBS inline de {@code jakarta.servlet} (ver {@code mitigacao/test/jakarta/}: só
 * a superfície que o filtro usa, com assinaturas idênticas a jakarta 6.0 / javax 4.0.1) e exercita o
 * filtro REAL com requisições fake, afirmando o comportamento em cada cenário. {@code System.exit(1)} em
 * qualquer falha, {@code 0} se todos passam — serve de gate de regressão (ver {@code mitigacao/test/run.sh}).
 *
 * <p>Cobre os modos default (bloqueia) × {@code skipFormBody} (stream-safe) × {@code detectonly}:
 * gatilho no corpo form, na query, em {@code Authorization}, em cookie e em SEGMENTO DE PATH (finding #7,
 * incl. a evasão {@code %3D}); e os NÃO-gatilhos esperados (GET benigno, corpo JSON não parseado, lacuna
 * de corpo no {@code skipFormBody}). O número de cenários abaixo = o número citado no README.
 */
public final class Java4ShellFilterTest {

    // ---- vetores Base64-malformados (texto benigno; nada é decodificado/executado) ----
    private static final String RUN64 = "A".repeat(64);     // run quad-alinhado de 64 chars (JDK 21/25/27)
    private static final String TRIG = RUN64 + "=";          // gatilho canônico (65 chars, 1 pad)
    private static final String TRIG2 = RUN64 + "==";        // variante 2 pads (também dispara)

    private static int ran = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {
        final Cfg def = new Cfg();                                   // default: bloqueia, inspeciona corpo
        final Cfg skip = new Cfg().set("skipFormBody", "true");      // stream-safe: não lê o corpo
        final Cfg detect = new Cfg().set("mode", "detectonly");      // só loga

        System.out.println("Detect4Shell - harness funcional do Java4ShellFilter (stubs jakarta.servlet inline)\n");

        System.out.println("Modo default (bloqueia 400):");
        // 1. SAMLResponse no CORPO form -> bloqueia (sink pre-auth Keycloak/PingFederate POST-binding)
        block("1  corpo form SAMLResponse", def, new Req().method("POST").uri("/saml/acs")
                .contentType("application/x-www-form-urlencoded").param("SAMLResponse", TRIG).param("RelayState", "/home"));
        // 2. SAMLRequest na QUERY -> bloqueia (redirect binding; container ja decodifica em params)
        block("2  query-param SAMLRequest", def, new Req().method("GET").uri("/saml")
                .query("SAMLRequest=" + TRIG + "&x=1").param("SAMLRequest", TRIG).param("x", "1"));
        // 3. Authorization: Basic ... -> bloqueia
        block("3  header Authorization", def, new Req().method("POST").uri("/login")
                .header("Authorization", "Basic " + TRIG));
        // 4. Cookie -> bloqueia
        block("4  cookie", def, new Req().method("GET").uri("/app").cookie("sess", TRIG));
        // 5. PATH: /download/<b64>= -> bloqueia (finding #7; segmento isolado do '/' casa o lookbehind)
        block("5  path /download/<b64>=", def, new Req().method("GET")
                .uri("/download/" + TRIG).pathInfo("/download/" + TRIG));
        // 6. PATH com evasao %3D: /download/<b64>%3D -> bloqueia via URL-decode do segmento (finding #7)
        block("6  path evasao %3D", def, new Req().method("GET")
                .uri("/download/" + RUN64 + "%3D").pathInfo("/download/" + RUN64 + "="));
        // 7. Dois pads '==' no Authorization -> bloqueia (guarda o fix do bypass "so um '='")
        block("7  Authorization dois-pads ==", def, new Req().method("POST").uri("/login")
                .header("Authorization", "Basic " + TRIG2));
        // 8. GET benigno (Basic auth valido curto, sem gatilho) -> PASSA
        pass("8  GET benigno", def, new Req().method("GET").uri("/health")
                .header("User-Agent", "curl/8.0").header("Authorization", "Basic dXNlcjpwYXNz"));
        // 9. Corpo JSON (container NAO parseia em params) -> PASSA intacto (lacuna honesta: use flag/borda)
        pass("9  corpo JSON nao inspecionado", def, new Req().method("POST").uri("/api/x")
                .contentType("application/json"));

        System.out.println("\nModo skipFormBody (stream-safe: nao le o corpo):");
        // 10. Gatilho SO no corpo form -> PASSA (lacuna ESPERADA: corpo nao e inspecionado neste modo)
        pass("10 corpo form NAO inspecionado (lacuna esperada)", skip, new Req().method("POST").uri("/saml/acs")
                .contentType("application/x-www-form-urlencoded").query("").param("SAMLResponse", TRIG));
        // 11. Evasao %3D na QUERY crua -> bloqueia (queryStringTrigger decodifica sem tocar o corpo)
        block("11 query %3D ainda pega", skip, new Req().method("POST").uri("/cb")
                .contentType("application/x-www-form-urlencoded").query("t=" + RUN64 + "%3D"));
        // 12. PATH ainda pega no skipFormBody (nao depende do corpo) -> bloqueia (finding #7)
        block("12 path ainda pega", skip, new Req().method("POST")
                .uri("/download/" + TRIG).contentType("application/x-www-form-urlencoded"));

        System.out.println("\nModo detectonly (so loga, nao bloqueia):");
        // 13. Gatilho presente mas apenas logado -> PASSA (cadeia chamada, sem 400)
        pass("13 detectonly so loga", detect, new Req().method("POST").uri("/login")
                .header("Authorization", "Basic " + TRIG));

        int ok = ran - failed;
        System.out.println("\nResultado: " + ok + "/" + ran + " cenarios OK (" + failed + " falha(s))");
        System.exit(failed == 0 ? 0 : 1);
    }

    // ---- asserts ----

    /** Espera BLOQUEIO: status 400 e cadeia NAO chamada (a app nunca ve o gatilho). */
    private static void block(String name, Cfg cfg, Req req) throws Exception {
        ran++;
        Java4ShellFilter f = new Java4ShellFilter();
        f.init(cfg);
        Resp resp = new Resp();
        Chain chain = new Chain();
        f.doFilter(req, resp, chain);
        boolean ok = resp.status == 400 && !chain.called;
        report(name, ok, "esperado BLOCK(400, sem cadeia); obtido status=" + resp.status + " chainCalled=" + chain.called);
    }

    /** Espera PASSAGEM: cadeia chamada e sem 400. */
    private static void pass(String name, Cfg cfg, Req req) throws Exception {
        ran++;
        Java4ShellFilter f = new Java4ShellFilter();
        f.init(cfg);
        Resp resp = new Resp();
        Chain chain = new Chain();
        f.doFilter(req, resp, chain);
        boolean ok = resp.status != 400 && chain.called;
        report(name, ok, "esperado PASS(cadeia, sem 400); obtido status=" + resp.status + " chainCalled=" + chain.called);
    }

    private static void report(String name, boolean ok, String detail) {
        if (ok) {
            System.out.println("  [OK]   " + name);
        } else {
            failed++;
            System.out.println("  [FAIL] " + name + " -- " + detail);
        }
    }

    // ---- fakes (implementam os stubs jakarta.servlet) ----

    /** Request fake, estilo builder. Implementa só a superfície que o filtro consulta. */
    private static final class Req implements HttpServletRequest {
        private String method = "GET";
        private String uri = "/";
        private String pathInfo = null;
        private String query = null;
        private String contentType = null;
        private final Map<String, List<String>> headers = new LinkedHashMap<>();
        private final Map<String, String[]> params = new LinkedHashMap<>();
        private Cookie[] cookies = null;
        private final ServletContext ctx = new Ctx();

        Req method(String m) { this.method = m; return this; }
        Req uri(String u) { this.uri = u; return this; }
        Req pathInfo(String p) { this.pathInfo = p; return this; }
        Req query(String q) { this.query = q; return this; }
        Req contentType(String c) { this.contentType = c; return this; }
        Req header(String n, String v) { headers.computeIfAbsent(n, k -> new ArrayList<>()).add(v); return this; }
        Req param(String n, String v) { params.put(n, new String[]{v}); return this; }
        Req cookie(String n, String v) { this.cookies = new Cookie[]{new Cookie(n, v)}; return this; }

        @Override public Map<String, String[]> getParameterMap() { return params; }
        @Override public String getContentType() { return contentType; }
        @Override public String getRemoteAddr() { return "203.0.113.7"; }
        @Override public ServletContext getServletContext() { return ctx; }
        @Override public Enumeration<String> getHeaderNames() { return Collections.enumeration(headers.keySet()); }
        @Override public Enumeration<String> getHeaders(String n) {
            return Collections.enumeration(headers.getOrDefault(n, Collections.emptyList()));
        }
        @Override public String getQueryString() { return query; }
        @Override public String getMethod() { return method; }
        @Override public String getRequestURI() { return uri; }
        @Override public String getPathInfo() { return pathInfo; }
        @Override public Cookie[] getCookies() { return cookies; }
    }

    private static final class Resp implements HttpServletResponse {
        int status = 200;
        String contentType = null;
        final StringWriter sw = new StringWriter();
        final PrintWriter pw = new PrintWriter(sw);
        @Override public void setStatus(int sc) { this.status = sc; }
        @Override public void setContentType(String t) { this.contentType = t; }
        @Override public PrintWriter getWriter() { return pw; }
    }

    private static final class Chain implements FilterChain {
        boolean called = false;
        @Override public void doFilter(ServletRequest req, ServletResponse resp) { this.called = true; }
    }

    private static final class Cfg implements FilterConfig {
        private final Map<String, String> p = new LinkedHashMap<>();
        Cfg set(String k, String v) { p.put(k, v); return this; }
        @Override public String getInitParameter(String n) { return p.get(n); }
    }

    private static final class Ctx implements ServletContext {
        final List<String> logs = new ArrayList<>();
        @Override public void log(String msg) { logs.add(msg); }
    }

    private Java4ShellFilterTest() { }
}
