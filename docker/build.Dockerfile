# Imagem de build: gcc + musl (Linux estático) e mingw-w64 (Windows estático).
# Nada disso é instalado na máquina; só existe dentro do container.
FROM alpine:3.22
RUN apk add --no-cache build-base mingw-w64-gcc
WORKDIR /src/core
