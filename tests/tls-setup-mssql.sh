#!/usr/bin/env bash
# Sobe um SQL Server 2022 com certificado próprio e TLS 1.3 habilitado, para testar
# o modo estrito (TDS 8.0). Requer os certificados de tests/tls-setup.sh.
# Uso (WSL, na raiz do projeto):  bash tests/tls-setup-mssql.sh
set -euo pipefail
D=/tmp/tmdb-tls
[ -f "$D/server.pem" ] || { echo "rode antes: bash tests/tls-setup.sh"; exit 1; }
mkdir -p "$D/mssql"
cp "$D/server.pem" "$D/mssql/server.pem"; cp "$D/server.key" "$D/mssql/server.key"
chmod 644 "$D/mssql/server.pem" "$D/mssql/server.key"
cat > "$D/mssql/mssql.conf" <<'EOF'
[network]
tlscert = /tls/server.pem
tlskey = /tls/server.key
tlsprotocols = 1.2,1.3
forceencryption = 0
EOF
docker rm -f tmdb-ms-tls >/dev/null 2>&1 || true
# O modo estrito exige que o certificado valha para o nome da própria máquina do servidor.
docker run -d --name tmdb-ms-tls --hostname sql.tmdb.test -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD=Tmdb_Test_123 -e MSSQL_PID=Developer \
  -p 127.0.0.1:51434:1433 -v "$D/mssql/mssql.conf:/var/opt/mssql/mssql.conf:ro" -v "$D/mssql:/tls:ro" \
  mcr.microsoft.com/mssql/server:2022-latest >/dev/null
echo "aguardando o SQL Server..."
for i in $(seq 1 40); do
  if docker logs tmdb-ms-tls 2>&1 | grep -q "SQL Server is now ready for client connections"; then break; fi
  sleep 2
done
docker logs tmdb-ms-tls 2>&1 | grep -i "Allowed TLS protocol\|TLS certificate\|strict" | cut -c1-160 | tail -4
