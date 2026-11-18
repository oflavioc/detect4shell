FROM python:3.12-slim
# Faithful engines: RE2 (google-re2), PCRE2 (libpcre2), YARA. Rules are mounted at runtime, never baked in.
RUN pip install --no-cache-dir google-re2 pcre2 yara-python
WORKDIR /repo
