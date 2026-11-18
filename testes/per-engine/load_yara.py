"""Assert the shipped YARA rule FILE compiles in real libyara. Run inside the container (cwd = testes/per-engine)."""
import sys

import yara

PATH = "/repo/regras/yara/detect4shell.yar"
try:
    rules = yara.compile(filepath=PATH)
except Exception as e:
    print(f"{type(e).__name__}: {e}")
    sys.exit(1)
n = sum(1 for _ in rules)
print(f"compiled OK ({n} rule(s), yara-python {yara.__version__ if hasattr(yara, '__version__') else '?'}, libyara {yara.YARA_VERSION})")
