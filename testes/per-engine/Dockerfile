FROM python:3.12-slim
# Faithful engines: RE2 (google-re2), PCRE2 (libpcre2), YARA. Rules are mounted at runtime, never baked in.
# Versions are PINNED (==) so this blocking gate stays reproducible: an upstream engine release can change
# matching behavior, and an unpinned install would let the gate drift or flake with no rule edit at all.
# cp312 manylinux wheels exist for all three (python:3.12-slim = glibc >= 2.28). Bump deliberately, together.
RUN pip install --no-cache-dir google-re2==1.1.20251105 pcre2==0.7.1 yara-python==4.5.4
WORKDIR /repo
