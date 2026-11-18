/*
 * Detect4Shell — regras YARA para o Java4Shell (CVE-2026-114938). Uso defensivo.
 *
 * YARA é melhor para VARRER ARQUIVOS: dumps de crash da JVM (forense pós-exploração),
 * capturas de tráfego salvas (pcap/logs) e amostras. NOTA: o motor de regex do YARA NÃO
 * suporta lookbehind, então a forma do gatilho aqui é levemente mais ampla que a das
 * regras de rede (Suricata/ModSec) — correlacione com as strings de contexto para precisão.
 */

rule Java4Shell_JVM_Crash_Artifact
{
    meta:
        description = "Dump de crash da JVM (hs_err) com o frame do stub de Base64 — indício de corrupção de heap (CVE-2026-114938)"
        cve = "CVE-2026-114938"
        severity = "high"
        reference = "https://github.com/ikow/java4shell-poc"
    strings:
        $hs   = "hs_err_pid"
        $sig  = "SIGSEGV"
        $b64  = "_base64_decodeBlock"
        $stub = "StubRoutines"
        $g1   = "G1ParScanThreadState"
        $iae  = "java.util.Base64"
    condition:
        // um dump de crash que menciona o stub de Base64 ou a GC logo após um SIGSEGV
        ($hs or $sig) and ($b64 or ($stub and $iae) or $g1)
}

rule Java4Shell_Malformed_Base64_Payload
{
    meta:
        description = "Payload do gatilho Java4Shell (Base64 malformado longo terminando em '=') em contexto de auth/SAML (CVE-2026-114938)"
        cve = "CVE-2026-114938"
        severity = "medium"
    strings:
        // >=64 chars Base64 (ambos alfabetos) seguidos de 1 ou 2 '=' e uma fronteira não-Base64
        $shape = /([^A-Za-z0-9+\/_-]|^)(([A-Za-z0-9+\/]{4}){16,}|([A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+\/_=-]|\x0d|\x0a)/
        $ctx_basic  = "Authorization: Basic " nocase
        $ctx_bearer = "Authorization: Bearer " nocase
        $ctx_saml1  = "SAMLRequest=" nocase
        $ctx_saml2  = "SAMLResponse=" nocase
    condition:
        $shape and any of ($ctx_*)
}

rule Java4Shell_Exact_PoC_Trigger
{
    meta:
        description = "Gatilho canônico exato do PoC (64/128 x 'A' + '=') — amostra/known-PoC (CVE-2026-114938)"
        cve = "CVE-2026-114938"
        severity = "low"
    strings:
        $a64  = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        $a128 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    condition:
        any of them
}
