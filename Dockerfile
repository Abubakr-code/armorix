# Armorix CLI for CI pipelines:
#   docker run --rm -v "$PWD:/src" ghcr.io/abubakr-code/armorix scan /src
FROM python:3.12-slim AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY armorix ./armorix
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
LABEL org.opencontainers.image.title="Armorix" \
      org.opencontainers.image.description="Offline AI code auditor — AST taint analysis, secrets, CVEs, CI/Docker checks" \
      org.opencontainers.image.source="https://github.com/Abubakr-code/armorix"
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 10001 armorix
COPY --from=build /install /usr/local
USER armorix
ENV ARMORIX_HOME=/home/armorix/.armorix
WORKDIR /src
ENTRYPOINT ["armorix"]
CMD ["scan", "/src"]
