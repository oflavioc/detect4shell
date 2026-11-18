/*
 * Reprodutor local confinado do Java4Shell (CVE-2026-114938) — uso defensivo / verificação de patch.
 *
 * Derivado de poc/Base64Trigger.java do projeto ikow/java4shell-poc
 *   https://github.com/ikow/java4shell-poc
 * MIT License · Copyright (c) 2026 Qi Deng  (veja o arquivo NOTICE para o aviso completo).
 *
 * Toda escrita permanece dentro de um array de 4096 bytes do próprio programa. Sem rede,
 * sem weaponização. Rode apenas em um host que você possui, num processo isolado.
 */
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/** Bounded standalone trigger: every write stays inside a real 4096-byte array. */
public final class Base64Trigger {
    private static volatile int sink;

    public static void main(String[] args) {
        Base64.Decoder decoder = Base64.getDecoder();
        int length = Runtime.version().feature() == 17 ? 128 : 64;
        int outputEnd = length / 4 * 3 + 2;
        byte[] valid = "A".repeat(length).getBytes(StandardCharsets.US_ASCII);
        byte[] malformed = ("A".repeat(length) + "=").getBytes(StandardCharsets.US_ASCII);
        byte[] target = new byte[4096];

        // Warm up the JIT so C2 compiles the Base64 intrinsic (AVX-512 path)
        for (int i = 0; i < 200_000; i++) {
            sink += decoder.decode(valid, target);
        }

        // Fill target with sentinel value
        Arrays.fill(target, (byte) 0x5a);
        boolean rejected = false;
        try {
            decoder.decode(malformed, target);
        } catch (IllegalArgumentException expected) {
            rejected = true;
        }

        // Inspect beyond the expected output, inside the allocated destination.
        int changed = 0;
        int first = -1;
        int last = -1;
        for (int i = outputEnd; i < target.length; i++) {
            if (target[i] != (byte) 0x5a) {
                changed++;
                if (first < 0) first = i;
                last = i;
            }
        }

        System.out.println("runtime=" + System.getProperty("java.runtime.version"));
        System.out.println("vm=" + System.getProperty("java.vm.name"));
        System.out.printf("rejected=%s changed=%d first=%d last=%d%n",
            rejected, changed, first, last);

        if (!rejected || changed != 62 || first != outputEnd || last != outputEnd + 61) {
            System.err.println("NOT REPRODUCED");
            System.exit(1);
        }
        System.out.println("REPRODUCED");
    }
}
