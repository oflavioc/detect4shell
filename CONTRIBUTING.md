# Contribuindo com o Detect4Shell

Contribuições são bem-vindas — regras novas, cobertura de engine, vetores de teste, correções de doc.
Duas coisas guiam tudo aqui: **o gate de testes tem que ficar verde** e a **disciplina de honestidade**.

## Antes de abrir um PR

Rode o gate completo (requer Docker + python3 + JDK 21):

```bash
bash test.sh     # 7 tiers; para no primeiro que falhar
```

Ele precisa sair **`OVERALL: PASS`**. O CI roda o mesmo em todo push/PR e **bloqueia** em caso de falha.

## Adicionando ou mudando uma regra

- Parta da **forma canônica** ([`regras/README.md`](regras/README.md)). Adapte ao engine (lookbehind →
  classe-de-fronteira para RE2/YARA; possessivo `{16,}+` → simples `{16,}` para FortiOS/Splunk; ramo
  `%3D` para buffers brutos) e **justifique** a divergência na doc.
- A regex é **extraída automaticamente** para a matriz por engine e para o **drift-guard**
  ([`testes/canonical_sync.py`](testes/canonical_sync.py)): se você duplicar a forma canônica num local
  novo, ou ela fica **byte-idêntica** (e você a adiciona ao guard) ou o gate falha. A asserção de
  completude garante que **nenhuma** regra enviada fica sem teste.
- Mantenha coerentes os invariantes de contagem citados nos docs (ex.: "43 regexes / 11 engines"): se
  mudar, atualize os docs **no mesmo PR**.

## Adicionando um vetor de teste

Edite [`testes/per-engine/vectors.py`](testes/per-engine/vectors.py). ⚠️ O corpus é **compartilhado**
por todos os engines com um único `should_match` global — um vetor novo tem que valer para **todas** as
regras, não só uma.

## Disciplina de honestidade (inegociável)

A tese do projeto é **honestidade**. Nenhum texto deve:

- afirmar **RCE genérico** como realidade (é *alegado-não-reproduzido* publicamente);
- dizer que o OOB "atravessou o WAF" (um bloqueio prova a **forma** na borda, não explorabilidade);
- tratar `HTTP 500` / `oob_write=62` como IoC de produção (é instrumentação de **lab**);
- esquecer que **nada substitui corrigir o JDK**.

Afirme só o **demonstrado**, declare os limites, e lembre: **banner ≠ match de regra ≠ bug**.

## Escopo

Só **defensivo**: sem exploit weaponizado, sem cadeia de RCE, sem disparar o gatilho contra alvo remoto
sem opt-in explícito. O alvo de lab **nunca** na Internet.
