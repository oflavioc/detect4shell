# Per-engine regex harness

Runs the ACTUAL regex each rule file ships through the FAITHFUL engine type, against a vector corpus.

| kind | engine in container | notes |
|------|---------------------|-------|
| pcre | `pcre2` (libpcre2)  | lookbehind + possessive quantifiers supported |
| re2  | `google-re2`        | rejects lookbehind / possessive: a compile failure is a REAL rule bug, no fallback |
| yara | `yara-python`       | regex embedded literally in a throwaway rule |

- `vectors.py` - corpus (seeded from `../validar.py` VETORES). Append with `add(id, token, raw, should_match, note)`.
- `engines.py` - manifest. Regexes are READ from `regras/**` and unescaped only for the engine's own escaping.
- `run.py` - drift guard, compile, TP/TN per regex, exit 1 on any failure.
- Rules where the regex itself demands context (`SAML...=`, `Bearer x.`, `Authorization: Basic `) get that
  prefix added to the token; the YARA `$shape` gets a trailing CRLF (its required boundary byte).

Run (Git-Bash, Docker running): `bash testes/per-engine/run.sh` from `dist/detect4shell`.

The harness is read-only: a failing row is a finding about the rule, never fixed here.
