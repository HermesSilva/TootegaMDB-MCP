#!/usr/bin/env bash
# Gera os binários de distribuição, 100% estáticos, dentro de um container:
#   dist/linux-x64/tmdb        (musl)
#   dist/win32-x64/tmdb.exe    (mingw-w64; só DLLs do próprio Windows)
# Uso (WSL, na raiz do projeto):  bash scripts/build-dist.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Controle de build: cada build de distribuição soma um ao número em BUILD.
# O número entra no executável (tmdb version -> 1.0.0.N) e no nome do .vsix.
# Para gerar de novo sem somar:  KEEP_BUILD=1 bash scripts/build-dist.sh
build=$(cat BUILD 2>/dev/null || echo 0)
if [ -z "${KEEP_BUILD:-}" ]; then
  build=$((build + 1))
  echo "$build" > BUILD
fi
echo "== build $build"

IMAGE=tmdb-build
docker build -q -t "$IMAGE" -f docker/build.Dockerfile docker >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/src "$IMAGE" make linux windows

echo
echo "== verificação"
file dist/linux-x64/tmdb dist/win32-x64/tmdb.exe 2>/dev/null || ls -l dist/*/
echo "-- dependências dinâmicas do binário Linux (deve ser nenhuma):"
(ldd dist/linux-x64/tmdb 2>&1 || true) | sed 's/^/   /'
echo "-- DLLs importadas pelo binário Windows (devem ser só as do sistema):"
docker run --rm -v "$PWD":/src "$IMAGE" sh -c \
  "x86_64-w64-mingw32-objdump -p /src/dist/win32-x64/tmdb.exe | grep 'DLL Name' | sed 's/^/   /'"
echo "-- selftest do binário Linux estático:"
./dist/linux-x64/tmdb selftest | tail -1
echo "-- versão:"
./dist/linux-x64/tmdb version
