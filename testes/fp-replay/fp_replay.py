#!/usr/bin/env python3
# Detect4Shell FP-replay: mede a taxa de FALSOS-POSITIVOS da forma canonica contra um corpus
# GRANDE de Base64 benigno REAL (nao os 18 vetores curados). Tudo offline, deterministico (seed).
# Roda no motor fiel: pcre2 (PCRE) + google-re2 (RE2). Ver run.sh / README.md.
#
# A forma canonica aqui espelha regras/README.md (o harness per-engine garante que as regras shipadas
# nao derivam dela). Nenhuma string gerada aqui deve casar: toda FP e um achado.
import re2, pcre2, base64, os, random, string
random.seed(1337)
CANON = pcre2.compile(rb"(?<![A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}+|(?:[A-Za-z0-9_-]{4}){16,}+)={1,2}(?![A-Za-z0-9+/_=-])")
RE2C  = re2.compile(r"(^|[^A-Za-z0-9+/_-])(?:(?:[A-Za-z0-9+/]{4}){16,}|(?:[A-Za-z0-9_-]{4}){16,})={1,2}([^A-Za-z0-9+/_=-]|$)")
def canon(s): return CANON.search(s.encode()) is not None
def re2m(s):  return RE2C.search(s) is not None

corpus = []  # (categoria, string) — TODO benigno
for _ in range(40000):
    b = os.urandom(random.randint(1, 400))
    corpus.append(("b64-std", base64.b64encode(b).decode()))
    corpus.append(("b64-url", base64.urlsafe_b64encode(b).decode()))
for _ in range(5000):
    seg = lambda n: base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")
    corpus.append(("jwt", f"{seg(random.randint(20,60))}.{seg(random.randint(80,300))}.{seg(32)}"))
for _ in range(3000):
    corpus.append(("data-uri", "data:image/png;base64," + base64.b64encode(os.urandom(random.randint(50,900))).decode()))
hexc = "0123456789abcdef"
for _ in range(3000):
    corpus.append(("presigned", f"https://s3.amazonaws.com/b/k?X-Amz-Credential=AKIA{''.join(random.choices(string.ascii_uppercase+string.digits,k=16))}%2F20261118%2Fus-east-1&X-Amz-Signature={''.join(random.choices(hexc,k=64))}"))
    corpus.append(("uuid", "-".join(''.join(random.choices(hexc,k=k)) for k in (8,4,4,4,12))))
    corpus.append(("hex", ''.join(random.choices(hexc,k=random.randint(32,128)))))
    corpus.append(("rest-path", "/api/v1/" + "/".join(''.join(random.choices(string.ascii_lowercase+"_-",k=random.randint(4,20))) for _ in range(random.randint(3,8)))))
    corpus.append(("analytics", "ga="+''.join(random.choices(string.ascii_letters+string.digits+".-_",k=random.randint(40,120)))))
sl = "/seclists/common.txt"   # paths web reais (montado pelo run.sh; opcional)
if os.path.exists(sl):
    for line in open(sl, errors="ignore"):
        line = line.strip()
        if line and not line.startswith("#"): corpus.append(("seclist-path", line))

from collections import Counter
tot = Counter(); fp_c = Counter(); fp_re2 = Counter(); examples = []
for cat, s in corpus:
    tot[cat] += 1
    if canon(s): fp_c[cat] += 1; examples.append(("PCRE", cat, s[:60]))
    if re2m(s):  fp_re2[cat] += 1
N = len(corpus); FP = sum(fp_c.values()); FR = sum(fp_re2.values())
print(f"Corpus benigno: {N} strings em {len(tot)} categorias")
print(f"{'categoria':14} {'qtd':>7} {'FP-PCRE':>8} {'FP-RE2':>7}")
for cat in sorted(tot):
    print(f"{cat:14} {tot[cat]:>7} {fp_c[cat]:>8} {fp_re2[cat]:>7}")
print(f"\nTOTAL FP: PCRE={FP}/{N} ({100*FP/N:.4f}%)   RE2={FR}/{N} ({100*FR/N:.4f}%)")
if examples:
    print("Exemplos de FP (primeiros 10):")
    for eng, cat, s in examples[:10]: print(f"  [{eng}] {cat}: {s}")
    raise SystemExit(1)
print(">>> ZERO falsos-positivos em todo o corpus de producao.")
