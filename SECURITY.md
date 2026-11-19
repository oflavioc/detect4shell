# Política de segurança — Detect4Shell

O Detect4Shell é uma **ferramenta DEFENSIVA** (regras de detecção, mitigação na aplicação, lab confinado
e testes). **Não é um produto com superfície de ataque exposta** — então "segurança" aqui tem dois
sentidos, tratados separadamente.

## 1. A vulnerabilidade que o projeto DETECTA (Java4Shell / CVE-2026-114938)

É um bug no **OpenJDK**, não neste repositório. O controle definitivo é **atualizar o JDK** para os
builds `.1` (ver [README — Mitigação](README.md#mitigação-para-reportar-a-donos-de-ativos)). O CVE é
público e já corrigido no upstream; não há nada a "reportar" aqui sobre o CVE em si.

## 2. Problemas NO repositório (regras, scanner, filtro, lab)

Se você encontrar:

- um **falso-negativo** (um gatilho real que uma regra não pega) ou um **falso-positivo** (tráfego
  legítimo que uma regra marca);
- uma regra que **não carrega/compila** no engine;
- um problema de segurança na **tooling de demo/lab** (ex.: o alvo deliberadamente vulnerável alcançável
  além do esperado, ou a tooling de ataque disparando sem o opt-in esperado),

abra uma **issue** em <https://github.com/oflavioc/detect4shell/issues> com um PoC mínimo e reprodutível.
A forma do gatilho é **pública** (`A×64+"="`) — você **não** precisa de exploit para demonstrar. Para algo
que considere sensível, marque a issue como tal ou use o canal de contato do mantenedor antes de divulgar.

## Escopo e versão suportada

- Versão suportada: a **`main`** (release atual **`v1.0.0`**).
- ⚠️ **Lembrete de lab:** `demo/alvo/VulnBasicAuthServer.java` é **deliberadamente vulnerável** e o
  `laboratorio/` roda o gatilho confinado (dentro de um array do próprio programa, `--network none`).
  **Nunca** exponha esses alvos na Internet — use só em rede isolada. A tooling de ataque do repo é
  **loopback-gated** por padrão (alvo remoto exige opt-in explícito).

## O que este projeto NÃO faz

Não há exploit weaponizado, cadeia de RCE, nem writer/reader de heap — por design. O único material
"ofensivo" é a string Base64 já pública do PoC upstream creditado. Ver o **aviso de escopo** no
[README](README.md).
