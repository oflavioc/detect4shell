#!/usr/bin/env python3
# Detect4Shell — drift-guard for the canonical trigger regex copies that live OUTSIDE regras/.
#
# The per-engine matrix (testes/per-engine/) extracts and tests the 43 regexes from the regras/ rule
# files. But the SAME canonical PCRE/RE2 form is hand-duplicated in FIVE places the matrix does NOT see
# (it scans only regras/) — the demo edge proxy, the Servlet Filter, the fp-replay harness, the honeypot
# sensor map, and the ENGINE_PCRE embedded in testes/validar.py — and nothing keeps them in sync. A
# future edit to the canonical pattern would silently diverge in exactly those copies. The validar.py
# copy is the most dangerous to let drift: it is the tier-1 pass/fail ORACLE, so a silent drift there
# would make tier 1 validate the shipped detector against the WRONG form (green on a lie).
# This guard asserts every copy is byte-identical to the regras/ reference. Pure text compare: no
# engine, no Docker, python3 only. Exit 1 on any drift (prints which copy diverged).
#
# NOT pinned here (documented asymmetry, not an oversight): the nginx `$args` maps (honeypot/sensor,
# demo/edge-nginx, regras/nginx) carry a `%3D` raw-buffer SUPERSET of the canonical PCRE — same core,
# tail swapped to `(?:={1,2}(?![A-Za-z0-9+/_=-])|%3[dD])`. Those files ARE pinned below, but against the
# plain CANON_PCRE (present byte-identical in their auth/cookie maps); the `%3D` tail has no constant
# here, matching how the two nginx entries already in CHECKS are treated. So the `%3D` core is NOT
# drift-guarded — track that gap separately if the `%3D` branch ever earns its own canonical constant.
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Single source of truth, mirrored from regras/README.md §"Padrões canônicos".
CANON_PCRE = r"(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}+|(?:[A-Za-z0-9_-]{4}){16,}+)={1,2}(?![A-Za-z0-9+/_=-])"
CANON_RE2 = r"(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)"

# (file, pattern, role). Self-anchoring: the constants above must appear in BOTH the regras/ reference
# AND every out-of-band copy, so editing the pattern in one place without the others fails here.
CHECKS = [
    ("regras/README.md",                CANON_PCRE, "reference: canonical doc (PCRE)"),
    ("regras/README.md",                CANON_RE2,  "reference: canonical doc (RE2)"),
    ("regras/nginx/detect4shell.conf",  CANON_PCRE, "reference engine: nginx (live-proven)"),
    ("regras/cloud-waf/cloudflare.md",  CANON_RE2,  "reference engine: Cloudflare (RE2)"),
    # --- the 5 out-of-band copies (NOT covered by testes/per-engine/, which scans only regras/) ---
    ("demo/edge-nginx/nginx.conf",      CANON_PCRE, "out-of-band: demo edge proxy"),
    ("mitigacao/Java4ShellFilter.java", CANON_PCRE, "out-of-band: Servlet Filter TRIGGER"),
    ("testes/fp-replay/fp_replay.py",   CANON_PCRE, "out-of-band: fp-replay CANON"),
    ("testes/fp-replay/fp_replay.py",   CANON_RE2,  "out-of-band: fp-replay RE2C"),
    # honeypot sensor: auth + cookie maps are byte-identical CANON_PCRE; its `$args` map is the `%3D`
    # superset variant (see header) — CANON_PCRE pins the two identical maps, not the `%3D` tail.
    ("honeypot/sensor/nginx.conf",      CANON_PCRE, "out-of-band: honeypot sensor map (auth/cookie)"),
    # validar.py ENGINE_PCRE = the tier-1 pass/fail ORACLE; drift here silently flips tier 1 green-on-wrong.
    ("testes/validar.py",               CANON_PCRE, "out-of-band: tier-1 ORACLE (validar.py ENGINE_PCRE)"),
]


def haystack(path: pathlib.Path) -> str:
    # Normalize markdown table pipe-escapes (`\|` -> `|`) so a doc table matches the bare-pipe form.
    return path.read_text(encoding="utf-8", errors="ignore").replace("\\|", "|")


def main() -> int:
    fails = []
    for rel, pat, role in CHECKS:
        p = ROOT / rel
        if not p.exists():
            fails.append((rel, role, "FILE NOT FOUND"))
        elif pat not in haystack(p):
            fails.append((rel, role, "canonical pattern NOT found (drifted?)"))

    if fails:
        print("DRIFT-GUARD FAIL — a canonical regex copy diverged from regras/README.md:")
        for rel, role, why in fails:
            print(f"  [{role}] {rel}: {why}")
        print("\nFix: make every copy byte-identical to the canonical form in regras/README.md,")
        print("or update CANON_PCRE/CANON_RE2 here AND regras/README.md together.")
        return 1

    print(f">>> drift-guard OK: canonical PCRE/RE2 in sync across {len(CHECKS)} locations "
          "(reference + 5 out-of-band copies).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
