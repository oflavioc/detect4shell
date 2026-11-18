# Detect4Shell honeypot — monitor-mode SENSOR (inert backend)

```
internet/LAN --> [ sensor: nginx, detect-only ] --internal net--> [ mock: nginx, fixed "200 OK" ]
```

## What this is (and is not)

- It is a **SENSOR**. It measures the **trigger SHAPE** (Base64-looking token with
  `=`/`==` padding, the Detect4Shell canonical split form) arriving at it: scanner
  interest and alert behaviour.
- It is **NOT a vulnerable target** and **NOT a measure of exploit success**. The
  backend (`mock`) is **inert**: plain nginx returning a fixed `200 OK`. It is not
  Java, never decodes Base64, parses nothing. Nothing here can be exploited.
- The vulnerable `demo/alvo/VulnBasicAuthServer.java` is **never** part of this stack.
- **Monitor mode**: on a hit the sensor logs a structured JSON line (which field
  matched: `authorization` / `args` / `cookie`) and **still proxies** the request.
  It never returns 403. Raw header/arg values are not logged (only match flags and a
  length bucket), so real credentials sent by scanners/clients are not stored.
- Rules are the maps from `regras/nginx/detect4shell.conf` (canonical split + `={1,2}`).
  `regras/` is untouched; the maps are copied into `sensor/nginx.conf`.
- False-positive measurement is already done offline at scale by `testes/fp-replay/`
  (monitor-mode replay). This honeypot is the deployable form for observing real scans.

## Isolation (defaults)

- Only the sensor port is published, bound to `127.0.0.1:8097` -> **no inbound
  exposure by default**. Behind it is only the inert mock.
- `mock` is on an `internal: true` network: no egress, not published.
  `sensor` is on `edge` (for the published port) plus `backend`.
- Bounded: sensor 64 MB / 0.25 CPU / 64 pids, mock 32 MB / 0.1 CPU / 32 pids;
  `client_max_body_size 8k`, small header buffers and short timeouts.
- `read_only` root FS (tmpfs `/tmp`), `cap_drop: ALL` (+CHOWN/SETUID/SETGID, the minimum
  nginx needs), `no-new-privileges`, no host volumes except read-only configs; the log
  is a named volume.

## Run

```bash
cd honeypot
docker compose up -d
bash demo_hit.sh            # one benign + one trigger request, then prints the alert log
docker compose logs -f sensor        # alerts also go to stdout
docker compose exec -T sensor cat //var/log/j4s/alerts.jsonl   # use /var/... outside Git-Bash
docker compose down -v
```

Manual:

```bash
curl -i -u admin:secret http://127.0.0.1:8097/                              # 200, no log
curl -i -H "Authorization: Basic $(printf 'A%.0s' $(seq 1 64))=" http://127.0.0.1:8097/  # 200 + LOGGED
```

Expected: both return `200` (monitor mode), only the trigger appears in the log with
`"j4s_match":{"authorization":1,...}`. Port is `127.0.0.1:8097`; edit the compose file if busy.

## Safe-exposure rules

1. If you ever expose anything, expose **THIS** (inert sensor + mock), deliberately
   (change the port mapping from `127.0.0.1:` to all interfaces) and behind your normal
   edge controls. **NEVER** expose the vulnerable `VulnBasicAuthServer`.
2. A genuinely vulnerable backend cannot be made safe by putting its detector in
   alert-only mode; that is why the design is sensor -> inert mock.
3. For real vulnerable-execution testing use a **disposable VM**: no inbound, egress
   denied (including DNS and cloud metadata), bounded CPU/mem/body/time with limits
   enforced **outside the JVM** (a JVM heap limit is not a security boundary against
   memory corruption), snapshots, and a kill switch.
