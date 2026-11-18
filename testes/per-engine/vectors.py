"""Vector corpus for the per-engine harness.

Seeded from the 16 labeled vectors in ../validar.py (VETORES). `token` is the Base64-ish string the
rules are meant to (not) match; `raw` is the full HTTP request kept for reference / future raw-level
tests. All benign text. APPEND adversarial vectors at the bottom of VECTORS (or via add()).
"""
B64_STD_64 = ("Zm9vYmFy" * 8)[:64]
B64_URLSAFE_64 = ("Zm9v-mF_" * 8)[:64]
assert len(B64_STD_64) == 64 and len(B64_URLSAFE_64) == 64

import base64

VECTORS = []


def add(id, token, raw, should_match, note=""):
    VECTORS.append({"id": id, "token": token, "raw": raw, "should_match": should_match, "note": note})


add("T1-basic-A", "A" * 64 + "=",
    f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*64}=\r\n\r\n", True,
    "canonical: Basic auth, 64*A + '='")
add("T2-basic-naoA", B64_STD_64 + "=",
    f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {B64_STD_64}=\r\n\r\n", True,
    "evasion: Basic auth, 64 non-'A' Base64 chars + '='")
add("T3-saml-corpo", B64_STD_64 + "=",
    f"POST /saml/acs HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nSAMLResponse={B64_STD_64}=&RelayState=/home", True,
    "SAMLResponse in POST body")
add("T4-saml-query", B64_STD_64 + "=",
    f"GET /saml?SAMLRequest={B64_STD_64}=&x=1 HTTP/1.1\r\nHost: x\r\n\r\n", True,
    "SAMLRequest in query (redirect binding)")
add("T5-urlsafe", B64_URLSAFE_64 + "=",
    f"GET /api?token={B64_URLSAFE_64}= HTTP/1.1\r\nHost: x\r\n\r\n", True,
    "url-safe alphabet (- _)")
add("T6-cookie", B64_STD_64 + "=",
    f"GET /app HTTP/1.1\r\nHost: x\r\nCookie: sess={B64_STD_64}=\r\n\r\n", True,
    "malformed Base64 in Cookie value")
add("T7-param", B64_STD_64 + "=",
    f"GET /r?data={B64_STD_64}=&next=/ HTTP/1.1\r\nHost: x\r\n\r\n", True,
    "malformed Base64 as query parameter")
add("T8-jdk17-128", "A" * 128 + "=",
    f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*128}=\r\n\r\n", True,
    "JDK17 trigger: 128*A + '=' (32 quads)")
add("N6-prepad65", B64_STD_64 + "Q=",
    f"GET /r?data={B64_STD_64}Q=&n=/ HTTP/1.1\r\nHost: x\r\n\r\n", False,
    "lab: non-quad-aligned (65 chars)+'=' does NOT trigger the overflow")
add("T9-dois-pads", "A" * 64 + "==",
    f"POST /login HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {'A'*64}==\r\n\r\n", True,
    "lab: 64*A + '==' triggers (same as '=')")
add("N8-data-uri", B64_STD_64 + "QQ==",
    f"POST /u HTTP/1.1\r\nHost: x\r\n\r\nimg=data:image/png;base64,{B64_STD_64}QQ==", False,
    "FP-control: valid data-URI base64 (len%4==0, '==')")
add("N1-basic-valido", "dXNlcjpwYXNzd29yZA==",
    "GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n\r\n", False,
    "valid short Basic auth")
add("N2-longo-valido", B64_STD_64 + "QQ==",
    f"POST /u HTTP/1.1\r\nHost: x\r\n\r\nblob={B64_STD_64}QQ==", False,
    "long valid Base64, correct padding (len%4==0)")
add("N3-malf-curto", "aGVsbG8=x",
    "GET /?t=aGVsbG8=x HTTP/1.1\r\nHost: x\r\n\r\n", False,
    "malformed but short (<64)")
add("N4-sem-pad", B64_STD_64 + "QQ",
    f"GET /?t={B64_STD_64}QQ HTTP/1.1\r\nHost: x\r\n\r\n", False,
    "long Base64, no trailing '='")
add("N5-nao-b64", "0123456789abcdef" * 5,
    "GET /?t=" + "0123456789abcdef" * 5 + " HTTP/1.1\r\nHost: x\r\n\r\n", False,
    "long non-Base64 (hex)")

# ---- append new adversarial vectors below: add(id, token, raw, should_match, note) ----


def _adv(id, token, should_match, note):
    add(id, token, f"GET /x?v={token} HTTP/1.1\r\nHost: x\r\n\r\n", should_match, note)


_S64 = ("Zm9vYmFy" * 8)[:64]
_adv("A1-std64-plus-slash", "ABCD" * 15 + "EF+/" + "=", True, "std64 +/")
_adv("A2-url64", "_-_-" * 16 + "=", True, "url64")
_adv("A3-jdk17-128", "A" * 128 + "=", True, "jdk17-128")
_adv("A4-doispads", "A" * 64 + "==", True, "doispads")
_adv("A5-std64-nonA", _S64 + "=", True, "std64-nonA")
_adv("A6-hex-edge", "0123456789abcdef" * 5 + "=", True, "hex-edge-malformed")
_adv("AN1-valid-b64-1eq", base64.b64encode(b"x" * 65).decode(), False, "valid-b64-1eq")
_adv("AN2-valid-url-b64", base64.urlsafe_b64encode(b"z" * 65).decode(), False, "valid-url-b64")
_adv("AN3-data-uri-png", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", False, "data-uri-png")
_adv("AN4-jwt-seg", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", False, "jwt-seg")
_adv("AN5-rest-path-mixed", "ab/c-d_e" * 10 + "=", False, "rest-path-mixed")
_adv("AN6-mixed-64-alphabet", ("A" * 30 + "+" + "_" + "A" * 32) + "=", False, "mixed-64-alphabet")
_adv("AN7-3-pads", "A" * 64 + "===", False, "3-pads")
_adv("AN8-15-quads", "A" * 60 + "=", False, "15-quads")
_adv("AN9-nonaligned-63", "A" * 63 + "=", False, "nonaligned-63")
_adv("AN10-valid-doublepad", _S64 + "QQ==", False, "valid-b64-doublepad")
_adv("AN11-prepad65", _S64 + "Q=", False, "prepad65-unaligned")

# reviewer-raised regression guards (valid encodings that must NOT alert)
_V = base64.b64encode(b"SAML-ASSERTION-xmlns-payload-" * 15).decode()
_adv("AN12-urlenc-valid-saml", _V.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D"), False,
     "url-encoded-valid-saml")
_adv("AN13-mime-wrapped-valid", "\r\n".join(_V[i:i + 76] for i in range(0, len(_V), 76)), False,
     "mime-linewrapped-valid")
_adv("AN14-base64url-valid", base64.urlsafe_b64encode(b"jwt-ish-token-data-" * 12).decode(), False,
     "base64url-valid")
