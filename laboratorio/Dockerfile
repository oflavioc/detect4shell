# Detect4Shell — laboratório confinado (CVE-2026-114938).
# Só reproduz em host x86-64 com AVX-512 VBMI. Em ARM64 (mesmo com --platform
# linux/amd64 via QEMU) NÃO dispara, pois o QEMU não emula AVX-512.
#
# Construir:  docker build -t detect4shell-lab .
# Rodar:      docker run --rm --network none detect4shell-lab
# Mitigação:  docker run --rm --network none detect4shell-lab -XX:-UseBASE64Intrinsics Base64Trigger
#   (ENTRYPOINT já é `java`; os args vão DEPOIS dele — não repita o `java`.)
#
# Observação: a imagem eclipse-temurin:21-jdk-noble estava, na divulgação, em 21.0.13
# (ainda vulnerável). Para testar o lado corrigido, troque por um build .1 (ex. Corretto
# 21.0.13.1.2) e confirme NAO_REPRODUZIDO.

FROM eclipse-temurin:21-jdk-noble
WORKDIR /lab
COPY Base64Trigger.java .
RUN javac Base64Trigger.java
ENTRYPOINT ["java"]
CMD ["Base64Trigger"]
