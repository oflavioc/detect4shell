# Java4Shell com o Fortinet Security Fabric

Se a sua organização usa Fortinet, várias soluções ajudam contra o Java4Shell (CVE-2026-114938),
cada uma numa função. Mapa honesto por **função de defesa** e **impacto real** — nada de "tudo resolve".
Os artefatos prontos deste repo estão marcados com 📦.

> O controle **definitivo** continua sendo **atualizar o JDK**. Tudo abaixo é **compensatório/complementar**
> (exatamente o que a CISA recomenda enquanto o patch não chega a todo lugar).

## 🔎 IDENTIFICAR — onde eu estou exposto / inventário de Java
| Solução | Como ajuda | Impacto |
|---|---|---|
| **FortiClient EMS** | Vulnerability scan dos endpoints gerenciados → lista **versões de JDK** afetadas (17.0.6+/21/25/27). Resolve o problema central "onde está o Java". | **Alto** |
| **FortiRecon** (EASM) | Descobre serviços **Java expostos na internet** (Jira/Confluence/Jenkins/Keycloak…) que você talvez nem saiba que existem. | **Médio-alto** |
| **FortiSIEM CMDB** | Marca hosts com OpenJDK afetado em CPU AVX-512 VBMI como maior risco (enriquece as regras). | Médio |

## 🛡️ PROTEGER / PREVENIR — barrar o gatilho na borda
| Solução | Como ajuda | Impacto | Artefato |
|---|---|---|---|
| **FortiGate IPS** | Bloqueio **inline no perímetro** da forma do gatilho em **qualquer** HTTP exposto (precisa SSL deep inspection). | **Alto** | 📦 `regras/fortigate-ips/` |
| **FortiWeb** (WAF) | Custom signature dedicada; cobre SAML/JWT/cookie/url-safe. | **Alto** | 📦 `regras/fortiweb/` |
| **FortiADC** | ADC/LB com WAF — mesma lógica de regra na frente das apps Java que ele balanceia. | Médio | (use a regex de `../regras/README.md`) |
| **FortiProxy** | Proxy reverso com inspeção IPS/WAF — aplica a mesma assinatura. | Médio | (idem) |
| **FortiDDoS** | A exploração precisa de uma **rajada** (o JIT compila o intrínseco após **~200k decodificações** — ver `ANALISE.md`; tipicamente dezenas/centenas de milhares de requisições) → detecta/mitiga como **flood** volumétrico/de aplicação; ataca o vetor de **DoS**. | Médio | — |

## 🚨 DETECTAR — ver tentativa e impacto
| Solução | Como ajuda | Impacto | Artefato |
|---|---|---|---|
| **FortiAnalyzer** | Event handlers + relatórios sobre os hits de FortiWeb/FortiGate. | **Alto** | 📦 `regras/siem/fortisiem-fortianalyzer.md` |
| **FortiSIEM** | Rules de correlação (forma na rede + rajada + crash no host). | **Alto** | 📦 (idem) |
| **FortiEDR** | No **host**: detecta a JVM crashando repetidamente / `hs_err_pid`, processos anômalos — o sinal que a **rede perde** (lembre: em JDK 21.0.13+G1 houve corrupção **sem** crash). Pode **isolar** o host. | **Médio-alto** | — |
| **FortiNDR** | Anomalia de rede (floods de Base64 incomuns) por ML — comportamental, não específico. | Marginal | — |

## 🔁 RESPONDER — automatizar a reação
| Solução | Como ajuda | Impacto |
|---|---|---|
| **FortiSOAR** | Playbook: num incidente do FortiSIEM/FortiAnalyzer → **bloquear o IP** no FortiGate, abrir ticket, **consultar o inventário** (FortiClient) por JDK afetado, notificar o dono do ativo. | Médio-alto |
| **FortiEDR** | Resposta no endpoint (isolar/encerrar processo) quando há crash/corrupção. | Médio |

## Fluxo recomendado (end-to-end num shop Fortinet)
1. **FortiRecon + FortiClient EMS** → inventariar Java exposto + versões vulneráveis.
2. **FortiGate IPS + FortiWeb** → bloquear a forma do gatilho na borda (comece em Monitor/Alert).
3. **FortiAnalyzer/FortiSIEM** → correlacionar rede (hit) + host (crash/exceções); **FortiEDR** pega o host.
4. **FortiSOAR** → resposta automática; **FortiDDoS** cobre a rajada.
5. Em paralelo e prioritário: **corrigir o JDK** para o build `.1`.

> Marginais para este caso específico: **FortiDAST** (testa suas apps, mas não enxerga bem o bug de
> intrínseco) e **FortiDeceptor** (decoy Java — nicho). Honestamente, o maior ganho vem de
> **inventário (FortiClient/FortiRecon) + bloqueio na borda (FortiGate IPS/FortiWeb) + correção do JDK**.
