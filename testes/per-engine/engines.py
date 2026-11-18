r"""Manifest: every detection regex each rule file ships, extracted LITERALLY by reading the file.

Nothing is hand-typed. Each entry: {engine, file, regex, kind, flags, escape, context}
  kind    : 'pcre' | 're2' | 'yara'
  escape  : how the regex is escaped inside its file (the drift guard re-applies it and re-finds the text)
  context : literal prefix the rule itself requires (derived from the regex text, see _ctx)
Only the engine's own escaping is undone (Suricata \/ -> /, FortiGate \\/ -> /, JSON string escapes).
"""
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


def _add(engine, file, raw, kind, esc="none", flags=""):
    regex = ESC[esc][1](raw)
    if not _is_b64_rule(regex):      # prose/example text, not a shipped detection regex
        return
    MANIFEST.append({"engine": engine, "file": file, "regex": regex, "kind": kind,
                     "flags": flags, "escape": esc, "context": _ctx(regex)})


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
    _add(f"elastic:regexp{i}", f, m.group(1), "re2", "json")

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
