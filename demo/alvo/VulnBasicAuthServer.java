/*
 * DEMO ALVO — servidor Java DELIBERADAMENTE vulneravel ao Java4Shell (CVE-2026-114938).
 * Sink pre-auth classico: decodifica o credential de `Authorization: Basic`.
 *
 * Por request, faz uma verificacao INSTRUMENTADA do primitivo de corrupcao: decodifica num
 * buffer-sentinela e conta quantos bytes foram escritos FORA do fim logico da saida. Isso MEDE,
 * por request, se a violacao de memoria (CVE-2026-114938) disparou para aquele request. ATENCAO: o
 * DISPARO em si e HEAP-DEPENDENTE (ver docs/ANALISE.md) e o crash/DoS e a escalacao PROBABILISTICA do
 * mesmo primitivo; este alvo usa o padrao do reprodutor, entao a medicao e estavel (sinal de lab, nao IoC).
 *
 * SO PARA LAB / LOCALHOST. Alvo de teste de defesa, nao exploit: o "payload" e a string Base64
 * malformada ja publica (A*64 + "="); toda consequencia fica dentro do processo. Nao exponha.
 *
 * Compilar:  javac VulnBasicAuthServer.java
 * Rodar:     java VulnBasicAuthServer [bind] [porta]      (default 127.0.0.1 18080)
 * Mitigar:   java -XX:-UseBASE64Intrinsics VulnBasicAuthServer   (desliga o intrinseco vulneravel)
 *
 * Bind: o default e LOOPBACK (127.0.0.1), nao alcancavel pela LAN -- o caminho que todo mundo roda.
 *       Qualquer bind != loopback (ex. 0.0.0.0) emite um AVISO no stderr: so em rede isolada, NUNCA
 *       na Internet. 0.0.0.0 so e preciso quando um container (edge nginx) precisa alcancar o alvo.
 */
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

public final class VulnBasicAuthServer {
    private static volatile long sink;
    private static final AtomicLong n = new AtomicLong();
    // Buffer-sentinela REUTILIZADO (mesmo padrao do reprodutor Base64Trigger): aquecido com 200k decodes
    // e reusado a cada request. E isso que torna a medicao do OOB DETERMINISTICA — array FRESCO por request
    // dispara ~0% (heap varia); o array reusado/aquecido dispara de forma estavel. Handlers rodam
    // sequencialmente (setExecutor(null)), entao o TARGET compartilhado nao sofre corrida.
    private static final byte[] TARGET = new byte[4096];

    public static void main(String[] args) throws Exception {
        String bind = args.length > 0 ? args[0] : "127.0.0.1";
        int port    = args.length > 1 ? Integer.parseInt(args[1]) : 18080;

        InetSocketAddress listen = new InetSocketAddress(bind, port);
        // Higiene de lab: o default e loopback (nao alcancavel pela LAN). Qualquer bind != loopback
        // (0.0.0.0, IP de LAN, ...) deixa este alvo DELIBERADAMENTE vulneravel exposto -> AVISO no stderr.
        // Emitido ANTES do warm-up e do s.start(), para que quem roda veja o alerta ANTES de o servidor
        // comecar a aceitar requests (antes era impresso DEPOIS de "ouvindo em", com o alvo ja servindo).
        InetAddress boundIp = listen.getAddress();
        if (boundIp == null || !boundIp.isLoopbackAddress()) {
            System.err.println("[alvo] AVISO: bind " + bind + " alcancavel na rede -- este alvo e"
                + " DELIBERADAMENTE vulneravel; use SO em rede isolada, NUNCA na Internet.");
        }
        warmJit();

        HttpServer s = HttpServer.create(listen, 0);
        s.createContext("/", ex -> {
            int status; String msg;
            String auth = ex.getRequestHeaders().getFirst("Authorization");
            if (auth == null || !auth.startsWith("Basic ")) {
                status = 200; msg = "OK user=anon (sem credencial)";
            } else {
                String cred = auth.substring(6).trim();
                int oob = oobWriteBytes(cred);                 // <<< primitivo instrumentado
                if (oob > 0) {
                    status = 500;
                    msg = "MEMORY-CORRUPTION cve-2026-114938 oob_write=" + oob + " bytes";
                    System.out.println("[alvo] #" + n.incrementAndGet()
                        + " !!! ESCRITA OOB DE " + oob + " BYTES (CVE-2026-114938 DISPAROU) cred.len=" + cred.length());
                } else {
                    try {
                        byte[] raw = Base64.getDecoder().decode(cred);  // credencial valida
                        String t = new String(raw, StandardCharsets.UTF_8);
                        status = 200; msg = "OK user=" + (t.contains(":") ? t.substring(0, t.indexOf(':')) : t);
                    } catch (IllegalArgumentException bad) {
                        status = 400; msg = "bad-base64 (malformado, mas SEM escrita OOB: patched/imune)";
                        System.out.println("[alvo] #" + n.incrementAndGet() + " base64 malformado SEM OOB (mitigado)");
                    }
                }
            }
            byte[] body = (msg + "\n").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, body.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(body); }
        });
        s.setExecutor(null); s.start();
        System.out.println("[alvo] vulneravel ouvindo em " + bind + ":" + port
            + "  (intrinseco Base64 AVX-512 aquecido)");
    }

    /** Mede os bytes escritos FORA do fim logico, num buffer-sentinela (logica do reprodutor
     *  confinado). >0  => a escrita OOB disparou; 0 => patched / CPU imune / entrada benigna. */
    private static int oobWriteBytes(String cred) {
        byte[] src = cred.getBytes(StandardCharsets.US_ASCII);
        int bodyLen = cred.endsWith("=") ? cred.length() - 1 : cred.length();
        if (bodyLen < 1) return 0;
        int outputEnd = bodyLen / 4 * 3 + 2;
        // Reusa o buffer-sentinela aquecido (padrao do reprodutor). O OOB dispara de forma estavel no
        // 1o decode malformado apos o warm-up; um malformado DEOPTIMIZA o metodo (excecao em codigo
        // compilado), entao disparos repetidos no MESMO processo param ate re-aquecer. Para o demo, o
        // alvo e (re)iniciado fresco antes do disparo -> o 1o request da rajada dispara o OOB (sinal de lab).
        Arrays.fill(TARGET, (byte) 0x5a);
        try { Base64.getDecoder().decode(src, TARGET); } catch (IllegalArgumentException ignored) {}
        int changed = 0;
        for (int i = outputEnd; i >= 0 && i < TARGET.length; i++) if (TARGET[i] != (byte) 0x5a) changed++;
        return changed;
    }

    /** Aquece o intrinseco vetorizado via a MESMA forma de dois args usada na verificacao. */
    private static void warmJit() {
        Base64.Decoder d = Base64.getDecoder();
        byte[] valid = "A".repeat(64).getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < 200_000; i++) sink += d.decode(valid, TARGET);   // aquece o intrinseco E prepara o TARGET reusado
        System.out.println("[alvo] JIT aquecido (intrinseco Base64 AVX-512 ativo)");
    }
}
