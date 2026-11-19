# Detect4Shell — laboratório confinado (CVE-2026-114938).
# Só reproduz em host x86-64 com AVX-512 VBMI. Em ARM64 (mesmo com --platform
# linux/amd64 via QEMU) NÃO dispara, pois o QEMU não emula AVX-512.
#
# Construir:  docker build -t detect4shell-lab .
# Rodar:      docker run --rm --network none detect4shell-lab
# Mitigação:  docker run --rm --network none detect4shell-lab -XX:-UseBASE64Intrinsics Base64Trigger
#   (ENTRYPOINT já é `java`; os args vão DEPOIS dele — não repita o `java`.)
#
# Observação: a base está FIXADA em eclipse-temurin:21.0.13_9-jdk-noble — exatamente o build
# 21.0.13+9-LTS que laboratorio/matrix/matrix.md registrou como REPRODUZIDO (ainda vulnerável).
# Antes a tag flutuante :21-jdk-noble rolava sozinha para a próxima point release e um dia o lab
# ia parar de reproduzir em silêncio. Para testar o lado CORRIGIDO, troque por um build .1 — a tag
# fixada eclipse-temurin:21.0.12.1_1-jdk-noble, ou Corretto 21.0.13.1.2 — e confirme NAO_REPRODUZIDO.
# (Lab confinado: um NAO_REPRODUZIDO não prova por si a segurança do serviço em produção — nada
# substitui corrigir o JDK.)

FROM eclipse-temurin:21.0.13_9-jdk-noble
WORKDIR /lab
COPY Base64Trigger.java .
RUN javac Base64Trigger.java
ENTRYPOINT ["java"]
CMD ["Base64Trigger"]
