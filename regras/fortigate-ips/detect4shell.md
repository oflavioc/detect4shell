# Detect4Shell — FortiGate IPS (Java4Shell / CVE-2026-114938)

Custom IPS signature para **detectar e bloquear inline** o gatilho Base64-malformado em **qualquer**
HTTP que atravessa o FortiGate — não só o que está atrás de um WAF. Ideal para proteger apps Java
expostas no perímetro.

> ⚠️ **Antes:** cheque o **FortiGuard** — a Fortinet provavelmente publica uma assinatura IPS oficial
> para CVE-2026-114938; esta custom signature é **complemento/stopgap** e cobre vetores que assinaturas
> genéricas podem perder (SAML/JWT/cookie/url-safe).
> **HTTPS:** exige **SSL deep inspection** na policy, senão o IPS não vê o conteúdo.
> Sintaxe de `F-SBID` varia por versão do FortiOS — **teste em lab** antes de produção.

## Custom signatures (CLI)

```
config ips custom
    edit "Java4Shell.Base64.Auth"
        set signature "F-SBID( --name \"Java4Shell.Base64.Auth\"; --protocol tcp; --service HTTP; --flow from_client; --context header; --pattern \"Authorization|3a 20|\"; --no_case; --pcre \"/(?<![A-Za-z0-9+\\/_-])(?:[A-Za-z0-9+\\/_-]{4}){16,}=(?![A-Za-z0-9+\\/_=-])/\"; --severity high; )"
    next
    edit "Java4Shell.Base64.URI"
        set signature "F-SBID( --name \"Java4Shell.Base64.URI\"; --protocol tcp; --service HTTP; --flow from_client; --context uri; --pcre \"/(?<![A-Za-z0-9+\\/_-])(?:[A-Za-z0-9+\\/_-]{4}){16,}(?:=(?![A-Za-z0-9+\\/_=-])|%3[dD])/\"; --severity high; )"
    next
    edit "Java4Shell.Base64.Body"
        set signature "F-SBID( --name \"Java4Shell.Base64.Body\"; --protocol tcp; --service HTTP; --flow from_client; --context body; --pcre \"/(?<![A-Za-z0-9+\\/_-])(?:[A-Za-z0-9+\\/_-]{4}){16,}(?:=(?![A-Za-z0-9+\\/_=-])|%3[dD])/\"; --severity high; )"
    next
end
```

## Aplicar numa IPS sensor e na policy

```
config ips sensor
    edit "D4S-Java4Shell"
        config entries
            edit 1
                set rule 0
                set location header uri body
                # referencie as custom signatures; ação de bloqueio:
                set status enable
                set action block
            next
        end
        # adicione as custom signatures ao sensor (via GUI: IPS → Sensors → Add Signature → Custom)
    next
end
# depois: aplique a sensor "D4S-Java4Shell" na firewall policy que publica as apps Java,
# COM ssl-ssh-profile de deep-inspection para enxergar HTTPS.
```

## GUI (resumo)
1. **Security Profiles → Intrusion Prevention → (custom signatures)**: cole cada `F-SBID(...)`.
2. Crie/edite uma **IPS Sensor**, adicione as custom signatures, **Action = Block**, Severity = High.
3. Aplique a sensor na **Firewall Policy** das apps Java expostas, com **SSL deep inspection** ligado.
4. Comece com **Action = Monitor/Pass** por alguns dias; depois mude para **Block**.

## Notas
- Começa em **Monitor** (só loga) → valide falsos-positivos → vire **Block**.
- Os logs de IPS vão para **FortiAnalyzer/FortiSIEM** (veja `regras/siem/fortisiem-fortianalyzer.md`)
  para correlação com crash/host.
- Controle **compensatório** (o que a CISA recomenda) — **não substitui corrigir o JDK**.
