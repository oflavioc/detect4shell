# On-the-wire — prova que as regras DISPARAM no tráfego real

Os tiers 1–5 provam que a **regex casa** (`validar.py`, `per-engine/`, `fp-replay/`) e que o **arquivo
carrega** no motor real (`per-engine/load_check.sh`). Falta um elo: a regra **dispara quando um pacote
de verdade atravessa o motor**? Este tier fecha esse elo, com dois motores reais em Docker.

## O que prova

| motor | como | gatilho | benigno |
|---|---|---|---|
| **Suricata** (8.x) | replay de PCAP (`-r`) com handshake TCP + HTTP reassemblado | `trigger.pcap` → **sid 2026114950** (http.header); `trigger_uri.pcap` → **sid 2026114951** (http.uri) | `benign.pcap` (base64 válido) → **0 alertas** |
| **ModSecurity v3** (nginx, sem CRS) | request HTTP **vivo** contra `regras/modsecurity/detect4shell.conf` | gatilho no header `Authorization` → **HTTP 403** (bloqueio) + `ruleId 2026114950` no audit | base64 válido → **HTTP 200** (sem FP) |

Além do bloqueio, o tier também prova o comportamento **ENVIADO de fábrica** (DETECTONLY): um gatilho num
argumento de query devolve **200** mas **registra** `ruleId 2026114952` no audit — detecta no fio sem
bloquear, que é o default do arquivo enviado.

## Resultado (2026-11-19, Docker 29.x — jasonish/suricata:8.0.8 + owasp/modsecurity:nginx-alpine)

```
suricata header trigger (sid 50)   | PASS | sid 2026114950 disparou no http.header
suricata uri trigger (sid 51)      | PASS | sid 2026114951 disparou no http.uri
suricata benign silencio           | PASS | 0 alertas detect4shell em trafego benigno
modsec stack readiness             | PASS | healthz 200
modsec header trigger -> 403       | PASS | BLOQUEOU (overlay deny na regra 2026114950)
modsec benign -> 200               | PASS | passou ao backend (sem FP)
modsec arg detect-only -> 200      | PASS | shipped pass,log: 200 e registra
modsec audit: header sid logado    | PASS | ruleId 2026114950 no audit JSON
modsec audit: arg sid logado       | PASS | ruleId 2026114952 no audit (detect-only)
ON-THE-WIRE: PASS
```

## Rodar

```bash
bash testes/on-the-wire/run.sh      # exige Docker; sai !=0 em qualquer falha
```

O `run.sh` orquestra tudo: gera os PCAPs (Python stdlib, num container — **sem scapy, sem pip**), roda os
replays no Suricata, sobe a stack ModSecurity (`modsecurity/docker-compose.yml`), dispara os `curl` e
derruba tudo no fim (trap). A saída efêmera vai pra `.work/` (gitignored).

## Estrutura

```
on-the-wire/
  run.sh                       orquestrador (gera pcaps, replay, sobe WAF, curl, teardown)
  suricata/gen_pcaps.py        gerador de PCAP sem dependências (handshake TCP + checksums corretos)
  modsecurity/
    docker-compose.yml         WAF (OWASP ModSecurity/nginx) -> backend inerte (nginx 200)
    Dockerfile.waf             imagem base + 1 script de entrypoint (não edita a imagem)
    95-detect4shell-rules.sh   dá Include nas regras ENVIADAS + no overlay, após o setup da imagem
    overlay.conf               flip opt-in pass->deny (status:403) só na regra do header, pro teste
    backend.conf               app fake: 200 em qualquer rota
```

## Por que o 403 usa um "overlay"

O arquivo **enviado** `regras/modsecurity/detect4shell.conf` opera em **DETECTONLY** (`pass,log`): ele
**registra** o match e devolve **200** — o próprio cabeçalho dele instrui a trocar `pass` → `deny`
(+ `status:403`) **depois de ajustar** ao seu tráfego. O `overlay.conf` faz exatamente essa troca
documentada, **de fora** (`SecRuleUpdateActionById`), **sem editar** o arquivo enviado — que segue sendo
testado como-está (o `ruleId` no audit prova que ELE disparou). Assim o tier prova as **duas** coisas: a
detecção do arquivo de fábrica **e** o caminho de bloqueio que o operador liga em produção.

## Limites honestos

- Isto prova **detecção/bloqueio no fio**, **não explorabilidade** do CVE-2026-114938 e **não** que um host
  esteja vulnerável. O disparo do oob-write é **heap-dependente / probabilístico** (ver `docs/ANALISE.md`);
  casar a FORMA do gatilho é um **sinal de detecção**, podendo ser um token malformado benigno raro —
  **banner ≠ regra ≠ bug**.
- `HTTP 500` / `oob_write=62` são **instrumentação de LAB** (`laboratorio/`), **não IoC** de campo. Aqui o
  "sucesso" é o motor **alertar/bloquear a requisição**, não um crash.
- Os PCAPs são **sintéticos** (handshake + request HTTP bem-formado com o gatilho no buffer certo), não uma
  captura de um ataque real. Exercitam os buffers de app-layer da regra (`http.header`, `http.uri`), que é
  o que precisa ser provado — mas não substituem um PCAP de produção amostrado de forma independente.
- O Suricata roda com `HOME_NET` padrão (cliente em `203.0.113.10` → servidor em `10.0.0.5`, i.e.
  EXTERNAL→HOME) e `-k none` (os checksums gerados já são válidos; `-k none` é cinto-e-suspensório).
- O benigno usa um base64 **válido terminado em `==`** (não só string curta): prova, no fio, que a exclusão
  de falso-positivo por **alinhamento de quad** funciona de verdade.
- Cobre os motores de **rede** (Suricata/IDS e ModSecurity/WAF). YARA e as regras SIEM/Sigma/cloud-WAF têm
  cobertura de **load**/match nos outros tiers; não há replay vivo pra elas aqui.
- Nada disto substitui **corrigir o JDK**. É defesa em profundidade na borda enquanto você aplica o patch.
