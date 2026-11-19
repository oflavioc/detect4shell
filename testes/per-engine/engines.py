r"""Manifest: every detection regex each rule file ships, extracted LITERALLY by reading the file.

Nothing is hand-typed. Each entry: {engine, file, regex, kind, flags, escape, context}
  kind    : 'pcre' | 're2' | 'yara'
  escape  : how the regex is escaped inside its file (the drift guard re-applies it and re-finds the text)
  context : literal prefix the rule itself requires (derived from the regex text, see _ctx)
Only the engine's own escaping is undone (Suricata \/ -> /, FortiGate \\/ -> /, JSON string escapes).
"""
import glob
import json
import os
import re

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
RULES = os.path.join(ROOT, "regras")
_cache = {}


def read(rel):
    if rel not in _cache:
        with open(os.path.join(RULES, rel), encoding="utf-8", newline="") as f:
            _cache[rel] = f.read().replace("\r\n", "\n")
    return _cache[rel]


BS = "\\"
# name -> (escape: regex -> in-file text, unescape: in-file text -> regex)
ESC = {
    "none": (lambda s: s, lambda s: s),
    "slash": (lambda s: s.replace("/", BS + "/"), lambda s: s.replace(BS + "/", "/")),            # Suricata pcre:"/.../"
    "fgt": (lambda s: s.replace("/", BS * 2 + "/"), lambda s: s.replace(BS * 2 + "/", "/")),      # FortiGate F-SBID --pcre \"/.../\"
    "json": (lambda s: json.dumps(s)[1:-1], lambda s: json.loads('"' + s + '"')),
}

MANIFEST = []


def _add(engine, file, raw, kind, esc="none", flags="", full=False):
    # full=True: match with .fullmatch instead of substring .search (see the Elastic/Lucene entry below).
    regex = ESC[esc][1](raw)
    if not _is_b64_rule(regex):      # prose/example text, not a shipped detection regex
        return
    MANIFEST.append({"engine": engine, "file": file, "regex": regex, "kind": kind,
                     "flags": flags, "escape": esc, "context": _ctx(regex), "full": full})


def _ctx(rx):
    """Context the rule itself demands before the Base64 (subject = context + token)."""
    if rx.startswith("SAML"):
        return "SAMLResponse="
    if rx.startswith("Bearer"):
        return "Bearer x."
    if rx.startswith("Authorization: Basic "):
        return "Authorization: Basic "
    return ""


def _is_b64_rule(rx):
    # skips non-shape patterns (e.g. '^SAML(Request|Response)$', hs_err_pid crash indicator)
    return "{16,}" in rx or "{64,}" in rx


# ---------------- Suricata ----------------
f = "suricata/detect4shell.rules"
for line in read(f).splitlines():
    if not line.startswith("alert"):
        continue
    pm = re.search(r'pcre:"/(.*)/([a-zA-Z]*)";', line)
    sid = re.search(r"sid:(\d+)", line).group(1)
    if pm and _is_b64_rule(pm.group(1)):
        _add(f"suricata:{sid}", f, pm.group(1), "pcre", "slash", pm.group(2))

# ---------------- nginx ----------------
f = "nginx/detect4shell.conf"
for i, m in enumerate(re.finditer(r'^\s*"~(.+)"\s+1;', read(f), re.M), 1):
    _add(f"nginx:map{i}", f, m.group(1), "pcre")

# ---------------- ModSecurity ----------------
# NOTE: `i` advances for EVERY @rx match, but _is_b64_rule drops non-shape rules (e.g. the SAML
# ARGS_NAMES name-rule), so the shipped rx IDs are intentionally NON-CONTIGUOUS (rx4 is skipped).
# The ID is only a label — the 43-regex count and the drift guard are unaffected by the gaps.
f = "modsecurity/detect4shell.conf"
for i, m in enumerate(re.finditer(r'@rx (\S+)"', read(f)), 1):
    if _is_b64_rule(m.group(1)):
        _add(f"modsecurity:rx{i}", f, m.group(1), "pcre")

# ---------------- FortiWeb ----------------
f = "fortiweb/detect4shell.md"
txt = read(f)
n = 0
for m in re.finditer(r"^(\(\?<!\S+|\(\^\|\S+)$", txt, re.M):   # standalone code-block regex lines
    n += 1
    kind = "re2" if m.group(1).startswith("(^|") else "pcre"
    _add(f"fortiweb:{'fallback-re2' if kind == 're2' else 'block'}{n}", f, m.group(1), kind)
for i, m in enumerate(re.finditer(r'set expression "([^"]+)"', txt), 1):
    _add(f"fortiweb:cli{i}", f, m.group(1), "pcre")

# ---------------- FortiGate IPS ----------------
f = "fortigate-ips/detect4shell.md"
for i, m in enumerate(re.finditer(r'--pcre \\"/(.*?)/\\"', read(f)), 1):
    _add(f"fortigate-ips:sig{i}", f, m.group(1), "pcre", "fgt")

# ---------------- Splunk / Elastic ----------------
f = "siem/splunk-elastic.md"
txt = read(f)
for i, m in enumerate(re.finditer(r'\| rex field=_raw "(.+)"\s*$', txt, re.M), 1):
    _add(f"splunk:rex{i}", f, m.group(1), "pcre")
for i, m in enumerate(re.finditer(r'"http\.request\.headers\.authorization": "((?:[^"\\]|\\.)*)"', txt), 1):
    # Elasticsearch `regexp` runs on LUCENE, which is term-ANCHORED (implicit fullmatch), NOT substring
    # search. RE2 is the faithful lookaround-free proxy, but it MUST be driven with .fullmatch (full=True):
    # the correct Lucene form uses open `.*`-boundaries that, under .search, float into a sub-window ending
    # right before a '=' and FP on long valid base64. See regras/siem/splunk-elastic.md.
    _add(f"elastic:regexp{i}", f, m.group(1), "re2", "json", full=True)

# ---------------- Sigma ----------------
f = "sigma/detect4shell.yml"
txt = read(f)
for i, m in enumerate(re.finditer(r"\|re: '([^']+)'", txt), 1):
    _add(f"sigma:re{i}", f, m.group(1), "pcre")
for i, m in enumerate(re.finditer(r"variante de fronteira\s*#?\s*RE2: `([^`]+)`", txt), 1):
    _add(f"sigma:re2-variant{i}", f, m.group(1), "re2")

# ---------------- Cloud WAF ----------------
f = "cloud-waf/aws-waf.json"
for i, m in enumerate(re.finditer(r'"RegexString":\s*"((?:[^"\\]|\\.)*)"', read(f)), 1):
    _add(f"aws-waf:stmt{i}", f, m.group(1), "re2", "json")
f = "cloud-waf/cloudflare.md"
for i, m in enumerate(re.finditer(r'matches "([^"]+)"', read(f)), 1):
    _add(f"cloudflare:expr{i}", f, m.group(1), "re2")

# ---------------- FortiSIEM / FortiAnalyzer ----------------
f = "siem/fortisiem-fortianalyzer.md"
for i, m in enumerate(re.finditer(r'(?:=~|REGEXP) "([^"]+)"', read(f)), 1):
    _add(f"fortisiem-faz:rx{i}", f, m.group(1), "re2")

# ---------------- YARA ----------------
f = "yara/detect4shell.yar"
for i, m in enumerate(re.finditer(r"\$shape\s*=\s*/(.*)/\s*$", read(f), re.M), 1):
    _add(f"yara:shape{i}", f, m.group(1), "yara")


# ---------------- reverse coverage guard (manifest completeness) ----------------
# The per-file extractors above pull each shipped regex with a pattern + the {16,}/{64,} literal gate
# (_is_b64_rule). A rule added in a DIFFERENT shape -- a reformatted line, or a {20,}/{32,} quantifier
# variant -- would be dropped SILENTLY from the manifest and shipped with NO per-engine test, CI green.
# orphan_rules() is the independent safety net the per-file extraction lacks: it re-scans every file
# under regras/ for lines that carry the FULL canonical trigger form and asserts that a manifest regex
# is present on each such line. run.py turns a non-empty result into exit 1 (the "43 ... files" line
# only counted; it never ASSERTED completeness).
#
# The form signature is the shape itself, NOT the {16,}/{64,} literal, so a quantifier variant is still
# recognised as a rule: a left boundary on the Base64 alphabet (lookbehind or boundary class) + the
# dual-alphabet quad-run `(?:[A-Za-z0-9_-]{4}){N,}` + the `={1,2}` padding. Low false-alarm by design --
# a partial form quoted in prose/comments (no left boundary, or an ellipsis in place of the run) is NOT
# a shipped rule and is skipped; the README doc-table copies carry the full form and are matched to the
# manifest cross-file (so they pass, not flag). Coverage is byte-exact after undoing only the escaping
# that legitimately differs between a live rule and a quoted copy (see _coverage_norm).
_FORM_RUN = re.compile(r"\[A-Za-z0-9_-\]\{4\}\)\{\d+,\}")   # url-safe quad-run: (?:[A-Za-z0-9_-]{4}){N,}
_FORM_LB = ("(?<![A-Za-z0-9", "[^A-Za-z0-9")                # left boundary (lookbehind OR class) on the alphabet
_FORM_PAD = "={1,2}"                                        # the malformed-Base64 1-or-2 '=' tail


def _coverage_norm(s):
    # Undo ONLY the escaping that differs between a live rule and a quoted copy, so the substring compare
    # is faithful across engines: FortiGate \\/ , Suricata/YARA \/ , markdown-table \|  ->  / / | .
    return s.replace("\\\\/", "/").replace("\\/", "/").replace("\\|", "|")


def _is_trigger_form_line(line):
    # True when the line carries the complete canonical trigger shape (not a prose/comment fragment).
    return _FORM_PAD in line and _FORM_RUN.search(line) is not None and any(b in line for b in _FORM_LB)


def orphan_rules():
    """Return [(relpath, lineno, line)] for each shipped trigger-shape regex NOT covered by MANIFEST.

    Empty list == complete coverage. Independent of the per-file extractors and of _is_b64_rule, so it
    catches a rule that those would drop (reformatted line / {20,} quantifier variant). See the block
    comment above for the form signature and the low-false-alarm rationale."""
    cover = [_coverage_norm(e["regex"]) for e in MANIFEST]
    orphans = []
    for path in sorted(glob.glob(os.path.join(RULES, "**", "*"), recursive=True)):
        if not os.path.isfile(path):
            continue
        rel = os.path.relpath(path, RULES).replace(os.sep, "/")
        try:
            with open(path, encoding="utf-8", newline="") as fh:
                text = fh.read().replace("\r\n", "\n")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.split("\n"), 1):
            if not _is_trigger_form_line(line):
                continue
            if not any(c in _coverage_norm(line) for c in cover):
                orphans.append((rel, i, line.strip()))
    return orphans
