#!/usr/bin/env python3
"""Per-engine harness: run each rule file's ACTUAL shipped regex through the FAITHFUL engine type.

  pcre -> pcre2 (libpcre2)      re2  -> google-re2 (rejects lookbehind / possessive)      yara -> yara-python

For each manifest entry: (a) drift guard, (b) compile in the faithful engine (NO fallback to another
engine), (c) match every vector, (d) print a row. Exit 1 on any compile failure, drift, or wrong TP/TN.
Read-only: never touches the rules. Run inside the Docker image (see run.sh).
"""
import sys

import engines
from vectors import VECTORS

import pcre2
import re2
import yara


def compile_entry(e):
    """Return a matcher(subject:str)->bool, or raise."""
    kind, rx = e["kind"], e["regex"]
    if kind == "re2":
        pat = re2.compile(rx)
        return lambda s: pat.search(s) is not None
    if kind == "pcre":
        pat = pcre2.compile(rx, flags=pcre2.I if "i" in e["flags"] else 0)
        return lambda s: pat.search(s) is not None
    if kind == "yara":
        src = "\n".join(["rule t {", " strings:", "  $s = /" + rx + "/", " condition:", "  $s", "}", ""])
        rules = yara.compile(source=src)
        return lambda s: bool(rules.match(data=s.encode()))
    raise ValueError(f"unknown kind {kind}")


def subject_for(e, v):
    # the rule's own required context + token; YARA's shape demands a trailing boundary byte (wire has CRLF)
    return e["context"] + v["token"] + ("\r\n" if e["kind"] == "yara" else "")


def main():
    rows, bad = [], 0
    tp_total = sum(1 for v in VECTORS if v["should_match"])
    tn_total = len(VECTORS) - tp_total
    for e in engines.MANIFEST:
        drift = engines.ESC[e["escape"]][0](e["regex"]) not in engines.read(e["file"])
        status, err, tp, tn, fails = "OK", "", 0, 0, []
        try:
            m = compile_entry(e)
        except Exception as ex:
            m, err = None, f"{type(ex).__name__}: {ex}"
        if m:
            for v in VECTORS:
                hit = m(subject_for(e, v))
                if hit == v["should_match"]:
                    tp += v["should_match"]
                    tn += (not v["should_match"])
                else:
                    fails.append(v["id"] + (":FN" if v["should_match"] else ":FP"))
        compiled = "yes" if m else "NO"
        if drift or not m or fails:
            status = "FAIL"
            bad += 1
        rows.append((e, compiled, tp, tn, fails, drift, err, status))

    w = max(len(r[0]["engine"]) for r in rows)
    print(f"{'engine':<{w}} | kind | compiled | {'TP':>5} | {'TN':>5} | drift | status | failing-vector-ids")
    print("-" * (w + 70))
    for e, compiled, tp, tn, fails, drift, err, status in rows:
        tpc = f"{tp}/{tp_total}" if compiled == "yes" else "-"
        tnc = f"{tn}/{tn_total}" if compiled == "yes" else "-"
        print(f"{e['engine']:<{w}} | {e['kind']:<4} | {compiled:<8} | {tpc:>5} | {tnc:>5} | "
              f"{'DRIFT' if drift else 'ok':<5} | {status:<6} | {', '.join(fails) if fails else (err or '-')}")
    print("-" * (w + 70))
    print(f"{len(rows)} regexes across {len({r[0]['file'] for r in rows})} files, {len(VECTORS)} vectors "
          f"({tp_total} should-match / {tn_total} should-not). FAILED engines: {bad}")
    if bad:
        print("\nFAILURE DETAIL (rule-level findings; harness never edits rules):")
        for e, compiled, tp, tn, fails, drift, err, status in rows:
            if status == "FAIL":
                print(f"- {e['engine']} [{e['file']}]\n    regex: {e['regex']}")
                if drift: print("    DRIFT: regex not found in file")
                if err: print(f"    compile error: {err}")
                if fails: print(f"    wrong verdicts: {', '.join(fails)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
