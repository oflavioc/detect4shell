# Honeypot Detect4Shell — SENSOR em modo-monitor (backend inerte)

```
internet/LAN --> [ sensor: nginx, só detecta ] --rede interna--> [ mock: nginx, "200 OK" fixo ]
```

## O que é (e o que NÃO é)

- É um **SENSOR**. Mede a **FORMA do gatilho** (token que parece Base64 com padding
  `=`/`==`, a forma canônica split do Detect4Shell) que chega até ele: interesse de
  scanners e comportamento de alerta.
- **NÃO é um alvo vulnerável** e **NÃO mede sucesso de exploração**. O backend (`mock`)
  é **inerte**: nginx puro devolvendo um `200 OK` fixo. Não é Java, nunca decodifica
  Base64, não faz parsing de nada. Nada aqui pode ser explorado.
- O alvo vulnerável `demo/alvo/VulnBasicAuthServer.java` **nunca** faz parte deste stack.
- **Modo-monitor**: num hit, o sensor registra uma linha JSON estruturada (qual campo
  casou: `authorization` / `args` / `cookie`) e **ainda assim encaminha** a requisição.
  Nunca devolve 403. Valores crus de header/arg **não** são logados (só os flags de match
  e um bucket de comprimento), então credenciais reais enviadas por scanners/clientes
  não são armazenadas.
- As regras são os `map`s de `regras/nginx/detect4shell.conf` (split canônico + `={1,2}`).
  `regras/` fica intocado; os `map`s são copiados para `sensor/nginx.conf`.
- A medição de falso-positivo já é feita offline em escala pelo `testes/fp-replay/`
  (replay em modo-monitor). Este honeypot é a **forma implantável** para observar scans reais.

## Isolamento (padrões)

- Só a porta do sensor é publicada, presa em `127.0.0.1:8097` → **sem exposição de
  entrada por padrão**. Atrás dele só existe o mock inerte.
- `mock` fica numa rede `internal: true`: sem egress, não publicada.
  `sensor` fica na `edge` (para a porta publicada) mais a `backend`.
- Limitado: sensor 64 MB / 0,25 CPU / 64 pids, mock 32 MB / 0,1 CPU / 32 pids;
  `client_max_body_size 8k`, buffers de header pequenos e timeouts curtos.
- Root FS `read_only` (tmpfs `/tmp`), `cap_drop: ALL` (+CHOWN/SETUID/SETGID, o mínimo
  que o nginx precisa), `no-new-privileges`, sem volumes de host exceto os configs
  read-only; o log é um volume nomeado.

## Rodar

```bash
cd honeypot
docker compose up -d
bash demo_hit.sh            # uma requisição benigna + uma com gatilho, e imprime o log de alerta
docker compose logs -f sensor        # os alertas também vão para o stdout
docker compose exec -T sensor cat //var/log/j4s/alerts.jsonl   # use /var/... fora do Git-Bash
docker compose down -v
```

Manual:

```bash
curl -i -u admin:secret http://127.0.0.1:8097/                              # 200, sem log
curl -i -H "Authorization: Basic $(printf 'A%.0s' $(seq 1 64))=" http://127.0.0.1:8097/  # 200 + LOGADO
```

Esperado: ambas devolvem `200` (modo-monitor), só a do gatilho aparece no log com
`"j4s_match":{"authorization":1,...}`. A porta é `127.0.0.1:8097`; edite o compose se estiver ocupada.

## Regras de exposição segura

1. Se um dia você expuser qualquer coisa, exponha **ESTE** (sensor inerte + mock),
   deliberadamente (troque o mapeamento de porta de `127.0.0.1:` para todas as interfaces)
   e atrás dos seus controles de borda normais. **NUNCA** exponha o `VulnBasicAuthServer`
   vulnerável.
2. Um backend genuinamente vulnerável **não** fica seguro só colocando o detector dele em
   modo-alerta; é por isso que o design é sensor → mock inerte.
3. Para testar execução vulnerável de verdade, use uma **VM descartável**: sem entrada,
   egress negado (incluindo DNS e metadata de nuvem), CPU/mem/corpo/tempo limitados com os
   limites impostos **fora da JVM** (um limite de heap da JVM não é fronteira de segurança
   contra corrupção de memória), snapshots e um kill switch.
