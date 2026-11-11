#!/usr/bin/env bash
# Sonda rápida: roda uma ferramenta com log detalhado.
# Uso:  bash tests/probe.sh FERRAMENTA 'JSON'      ex.: bash tests/probe.sh test_connection '{"connection":"ora"}'
cd "$(dirname "$0")/.."
./core/build/tmdb --lang en --verbose --config tests/connections.json call "$@" 2>&1 | tail -${LINES_MAX:-40}
